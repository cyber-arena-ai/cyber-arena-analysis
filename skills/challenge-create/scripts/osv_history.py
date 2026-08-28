"""Manifested advisory loading and Git-range parsing."""

from __future__ import annotations

import hashlib
import json
import re
import zipfile
from collections import defaultdict
from pathlib import Path

try:
    from ._lib import canonical_github_repo
except ImportError:  # direct execution
    from _lib import canonical_github_repo


class CorpusError(ValueError):
    pass


HEX40 = re.compile(r"[0-9a-f]{40}")
SOURCE_ROLES = {"base", "fast_lane", "enrichment"}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def manifest_archives(raw_dir: Path, manifest_path: Path) -> tuple[dict, list[dict]]:
    """Validate and resolve the exact advisory archives listed by a manifest."""
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    archives = []
    for source in manifest.get("sources", []):
        role = str(source.get("role") or "base")
        if role not in SOURCE_ROLES:
            raise CorpusError(f"invalid advisory source role: {role!r}")
        if role == "fast_lane":
            lane = source.get("lane")
            priority = source.get("priority")
            if not isinstance(lane, str) or not lane.strip():
                raise CorpusError("fast-lane advisory source requires lane")
            if not isinstance(priority, int) or isinstance(priority, bool) or priority < 1:
                raise CorpusError("fast-lane advisory source requires positive priority")
        name = str(source.get("path", ""))
        if not name or Path(name).name != name:
            raise CorpusError(f"invalid manifest archive path: {name!r}")
        path = raw_dir / name
        if not path.is_file():
            raise CorpusError(f"missing archive: {path}")
        if source.get("bytes") != path.stat().st_size:
            raise CorpusError(f"archive size mismatch: {path}")
        if source.get("sha256") != _sha256(path):
            raise CorpusError(f"archive hash mismatch: {path}")
        try:
            with zipfile.ZipFile(path) as archive:
                bad_member = archive.testzip()
        except zipfile.BadZipFile as error:
            raise CorpusError(f"invalid ZIP archive: {path}") from error
        if bad_member:
            raise CorpusError(f"corrupt ZIP member {bad_member!r} in {path}")
        archives.append({"path": path, "source": {**source, "role": role}})
    if not archives:
        raise CorpusError("manifest contains no archives")
    return manifest, archives


def _github_path_parts(url: str | None) -> list[str]:
    if not url:
        return []
    from urllib.parse import urlparse

    parsed = urlparse(url.strip())
    if parsed.hostname not in {"github.com", "www.github.com"}:
        return []
    return [part for part in parsed.path.strip("/").split("/") if part]


def candidate_repository_roles(record: dict) -> dict[str, set[str]]:
    """Extract application-repository evidence without promoting repair locations."""
    roles: dict[str, set[str]] = defaultdict(set)
    for affected in record.get("affected", []):
        for affected_range in affected.get("ranges", []):
            if affected_range.get("type") != "GIT":
                continue
            if repository := canonical_github_repo(affected_range.get("repo")):
                roles["affected_git_range"].add(repository)
    for reference in record.get("references", []):
        url = str(reference.get("url", ""))
        repository = canonical_github_repo(url)
        parts = _github_path_parts(url)
        if not repository:
            continue
        if reference.get("type") == "PACKAGE":
            roles["package_reference"].add(repository)
        elif (
            reference.get("type") == "ADVISORY"
            and len(parts) >= 5
            and parts[2:4] == ["security", "advisories"]
        ):
            roles["upstream_security_advisory"].add(repository)
    return roles


def parse_git_phases(events: list[dict]) -> tuple[list[dict], list[str]]:
    """Parse OSV Git events using the structural rules required by Stage 2."""
    phases = []
    blockers = []
    current = {"introduced": [], "fixed": [], "last_affected": []}
    seen_terminal = False
    for event in events:
        if not isinstance(event, dict) or len(event) != 1:
            blockers.append("invalid_event_shape")
            continue
        kind, raw_value = next(iter(event.items()))
        value = str(raw_value).lower()
        if kind not in {"introduced", "fixed", "last_affected"}:
            blockers.append(f"unsupported_event:{kind}")
            continue
        if kind == "introduced" and value != "0" and not HEX40.fullmatch(value):
            blockers.append("invalid_introduced_commit")
            continue
        if kind != "introduced" and not HEX40.fullmatch(value):
            blockers.append(f"invalid_{kind}_commit")
            continue
        if kind == "introduced":
            if seen_terminal:
                phases.append(current)
                current = {"introduced": [], "fixed": [], "last_affected": []}
                seen_terminal = False
            current["introduced"].append(value)
        else:
            if not current["introduced"]:
                blockers.append(f"{kind}_without_introduction")
            current[kind].append(value)
            seen_terminal = True
    if any(current.values()):
        phases.append(current)
    if not phases:
        blockers.append("empty_git_range")
    return phases, sorted(set(blockers))


def iter_archive_records(archives: list[dict]):
    for item in archives:
        archive_path = item["path"]
        source = item["source"]
        with zipfile.ZipFile(archive_path) as archive:
            for member in archive.infolist():
                if member.is_dir() or not member.filename.endswith(".json"):
                    continue
                with archive.open(member) as stream:
                    yield {
                        "source_archive": archive_path.name,
                        "source_member": member.filename,
                        "source_database": str(
                            source.get("source")
                            or source.get("ecosystem")
                            or archive_path.stem
                        ),
                        "source_role": source.get("role", "base"),
                        "source_lane": source.get("lane"),
                        "source_priority": source.get("priority"),
                        "record": json.load(stream),
                    }
