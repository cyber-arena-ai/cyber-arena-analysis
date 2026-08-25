"""Lossless project-level OSV history extraction and overlap analysis."""

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
        archives.append({"path": path, "source": source})
    if not archives:
        raise CorpusError("manifest contains no archives")
    return manifest, archives


def package_key(package: dict) -> str | None:
    ecosystem = package.get("ecosystem")
    name = package.get("name")
    return f"{ecosystem}:{name}" if ecosystem and name else None


def record_ids(record: dict) -> set[str]:
    return {
        str(value)
        for value in [record.get("id"), *record.get("aliases", [])]
        if value
    }


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


def candidate_repositories(record: dict) -> set[str]:
    return {
        repository
        for repositories in candidate_repository_roles(record).values()
        for repository in repositories
    }


def affected_keys(affected: dict) -> tuple[set[str], bool]:
    """Return package/Git units and whether Git version attribution is ambiguous."""
    key = package_key(affected.get("package", {}))
    if key:
        return {key}, False
    repositories = {
        repository
        for item in affected.get("ranges", [])
        if item.get("type") == "GIT"
        if (repository := canonical_github_repo(item.get("repo")))
    }
    return {f"GIT:{repository}" for repository in repositories}, len(repositories) > 1


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


def record_packages(record: dict) -> set[str]:
    return {
        key
        for affected in record.get("affected", [])
        for key in affected_keys(affected)[0]
    }


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
                        "record": json.load(stream),
                    }


def iter_raw_records(raw_dir: Path, manifest_path: Path | None = None):
    if manifest_path is None:
        archives = [
            {"path": path, "source": {"path": path.name}}
            for path in sorted(raw_dir.glob("*.zip"))
        ]
    else:
        _, archives = manifest_archives(raw_dir, manifest_path)
    yield from iter_archive_records(archives)


class _Aliases:
    def __init__(self, size: int):
        self.parent = list(range(size))

    def find(self, item: int) -> int:
        while self.parent[item] != item:
            self.parent[item] = self.parent[self.parent[item]]
            item = self.parent[item]
        return item

    def union(self, left: int, right: int) -> None:
        left, right = self.find(left), self.find(right)
        if left != right:
            self.parent[right] = left


def _component_id(ids: set[str]) -> str:
    for prefix in ("CVE-", "GHSA-"):
        matches = sorted(value for value in ids if value.startswith(prefix))
        if matches:
            return matches[0]
    return sorted(ids)[0]


def build_components(records: list[dict]) -> list[dict]:
    aliases = _Aliases(len(records))
    owner: dict[str, int] = {}
    for index, wrapped in enumerate(records):
        for identifier in record_ids(wrapped["record"]):
            if identifier in owner:
                aliases.union(index, owner[identifier])
            else:
                owner[identifier] = index

    grouped: dict[int, list[dict]] = defaultdict(list)
    for index, wrapped in enumerate(records):
        grouped[aliases.find(index)].append(wrapped)

    components = []
    for members in grouped.values():
        ids = {
            identifier
            for wrapped in members
            for identifier in record_ids(wrapped["record"])
        }
        summaries = sorted(
            {
                wrapped["record"].get("summary", "")
                for wrapped in members
                if wrapped["record"].get("summary")
            }
        )
        components.append(
            {
                "component_id": _component_id(ids),
                "ids": sorted(ids),
                "summary": summaries[0] if summaries else "",
                "records": members,
            }
        )
    return sorted(components, key=lambda item: item["component_id"])


def _component_state(component: dict, packages: set[str], version: str) -> str:
    matched_unit = False
    requires_range_evaluation = False
    ambiguous_match = False
    for wrapped in component["records"]:
        for affected in wrapped["record"].get("affected", []):
            keys, ambiguous = affected_keys(affected)
            if not packages & keys:
                continue
            matched_unit = True
            if version in {str(value) for value in affected.get("versions", [])}:
                if ambiguous:
                    ambiguous_match = True
                else:
                    return "reported_present"
            if affected.get("ranges"):
                requires_range_evaluation = True
    if ambiguous_match:
        return "ambiguous_git_version_attribution"
    if requires_range_evaluation:
        return "range_evaluation_required"
    return "not_reported" if matched_unit else "different_package"


def explicit_versions(components: list[dict], packages: set[str]) -> list[str]:
    return sorted(
        {
            str(version)
            for component in components
            for wrapped in component["records"]
            for affected in wrapped["record"].get("affected", [])
            if packages & affected_keys(affected)[0]
            for version in affected.get("versions", [])
        }
    )


def analyze_overlap(
    components: list[dict],
    packages: set[str],
    checkpoints: list[tuple[str, str]] | None = None,
) -> dict:
    if checkpoints is None:
        checkpoints = [(version, version) for version in explicit_versions(components, packages)]
        order_source = "unordered union of explicit affected versions"
    else:
        order_source = "caller-provided checkpoint order"

    rows = []
    for label, version in checkpoints:
        states = {
            component["component_id"]: _component_state(component, packages, version)
            for component in components
        }
        present = [
            component_id
            for component_id, state in states.items()
            if state == "reported_present"
        ]
        range_evaluation_required = [
            component_id
            for component_id, state in states.items()
            if state == "range_evaluation_required"
        ]
        ambiguous_git_version_attribution = [
            component_id
            for component_id, state in states.items()
            if state == "ambiguous_git_version_attribution"
        ]
        rows.append(
            {
                "label": label,
                "version": version,
                "reported_present_count": len(present),
                "reported_present": present,
                "range_evaluation_required_count": len(range_evaluation_required),
                "range_evaluation_required": range_evaluation_required,
                "ambiguous_git_version_attribution_count": len(
                    ambiguous_git_version_attribution
                ),
                "ambiguous_git_version_attribution": (
                    ambiguous_git_version_attribution
                ),
            }
        )

    maximum = max((row["reported_present_count"] for row in rows), default=0)
    maxima = [row["label"] for row in rows if row["reported_present_count"] == maximum]
    return {
        "evidence_semantics": (
            "reported_present is an exact positive match in OSV affected.versions; "
            "absence is not inferred when a native ecosystem or Git range remains unevaluated"
        ),
        "checkpoint_order": order_source,
        "checkpoints": rows,
        "selection": {
            "metric": "maximum reported_present advisory-component count",
            "maximum_count": maximum,
            "maximal_checkpoints": maxima,
            "earliest_maximal_checkpoint": (
                maxima[0] if maxima and order_source.startswith("caller-provided") else None
            ),
        },
    }
