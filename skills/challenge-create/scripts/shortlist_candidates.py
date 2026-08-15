#!/usr/bin/env python3
"""Build a compact OSS challenge-candidate shortlist from retained sources."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import zipfile
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from _lib import (
    canonical_github_repo,
    popularity_score,
)


HEX40 = re.compile(r"[0-9a-fA-F]{40}")
URL_DATE = re.compile(
    r"/(20\d{2})/(0?[1-9]|1[0-2])/(0?[1-9]|[12]\d|3[01])(?:/|$)"
)
AVAILABILITY_ONLY = re.compile(
    r"\b(?:denial[- ]of[- ]service|dos\b|crash(?:es)?\b|panic\b|"
    r"resource exhaustion|resource consumption|memory exhaustion|"
    r"stack overflow|infinite (?:loop|recursion)|deadlock|hang\b)\b",
    re.IGNORECASE,
)
SECURITY_OUTCOME = re.compile(
    r"\b(?:authorization|authentication|access control|privilege|"
    r"cross[- ](?:tenant|user|project|account|boundary)|account takeover|"
    r"remote code execution|rce\b|command injection|code injection|"
    r"sandbox escape|arbitrary file (?:read|write)|path traversal|"
    r"sql injection|ssrf\b|credential|secret|token|identity spoof|"
    r"information disclosure|data disclosure|data leak|master key|"
    r"cache key collision|file overwrite|protected|permission)\b",
    re.IGNORECASE,
)
NON_RUNTIME = re.compile(
    r"\b(?:github actions?|ci workflow|release workflow|build workflow)\b",
    re.IGNORECASE,
)

BEHAVIOR_REFERENCE_TYPES = {"EVIDENCE"}

BASE_POPULARITY_SCORE = 75
PRIORITY_POPULARITY_SCORE = 85
PRIORITY_MIN_COMPONENTS = 2
MAX_INACTIVITY_DAYS = 730
NON_LICENSES = {None, "", "NOASSERTION", "OTHER"}
SERVICE_CATEGORIES = {
    "ai-platform",
    "ci-cd",
    "cms-publishing",
    "collaboration",
    "data-analytics",
    "data-service",
    "developer-platform",
    "infrastructure",
    "network-service",
    "observability",
    "security-identity",
    "self-hosted",
    "storage-files",
    "workflow-automation",
}
SERVICE_TOPICS = {
    "api-gateway",
    "authentication",
    "authorization",
    "ci-cd",
    "cloud-storage",
    "cms",
    "collaboration",
    "content-management-system",
    "database",
    "file-sharing",
    "git-server",
    "iam",
    "identity-management",
    "message-queue",
    "monitoring",
    "observability",
    "orchestration",
    "project-management",
    "reverse-proxy",
    "self-hosted",
    "sso",
    "web-server",
    "workflow",
    "workflow-automation",
}


class InputError(ValueError):
    pass


class Aliases:
    def __init__(self) -> None:
        self.parent: dict[str, str] = {}

    def find(self, item: str) -> str:
        self.parent.setdefault(item, item)
        while self.parent[item] != item:
            self.parent[item] = self.parent[self.parent[item]]
            item = self.parent[item]
        return item

    def union_all(self, items: set[str]) -> None:
        if not items:
            return
        root = self.find(min(items))
        for item in items:
            other = self.find(item)
            if root != other:
                self.parent[other] = root


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise InputError(f"invalid timestamp {value!r}") from error
    if parsed.tzinfo is None:
        raise InputError(f"timestamp lacks timezone: {value!r}")
    return parsed.astimezone(timezone.utc)


def _record_ids(record: dict) -> set[str]:
    return {
        str(value)
        for value in [record.get("id"), *record.get("aliases", [])]
        if value
    }


def _manifest_archives(raw_dir: Path, manifest_path: Path) -> tuple[list[Path], dict]:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    archives = []
    for source in manifest.get("sources", []):
        name = str(source.get("path", ""))
        if not name or Path(name).name != name:
            raise InputError(f"invalid manifest archive path: {name!r}")
        path = raw_dir / name
        if not path.is_file():
            raise InputError(f"missing archive: {path}")
        if source.get("bytes") != path.stat().st_size:
            raise InputError(f"archive size mismatch: {path}")
        if source.get("sha256") != _sha256(path):
            raise InputError(f"archive hash mismatch: {path}")
        with zipfile.ZipFile(path) as archive:
            bad_member = archive.testzip()
        if bad_member:
            raise InputError(f"corrupt ZIP member {bad_member!r} in {path}")
        archives.append(path)
    if not archives:
        raise InputError("manifest contains no archives")
    return archives, manifest


def _records(archives: list[Path]):
    for archive_path in sorted(archives):
        with zipfile.ZipFile(archive_path) as archive:
            for member in archive.infolist():
                if member.is_dir() or not member.filename.endswith(".json"):
                    continue
                with archive.open(member) as stream:
                    yield archive_path.name, member.filename, json.load(stream)


def _commit_from_url(url: str | None) -> str | None:
    if not url:
        return None
    parsed = urlparse(url)
    if parsed.hostname not in {"github.com", "www.github.com"}:
        return None
    parts = [part for part in parsed.path.strip("/").split("/") if part]
    if len(parts) >= 4 and parts[2] == "commit" and HEX40.fullmatch(parts[3]):
        return parts[3].lower()
    return None


def _fix_boundaries(record: dict) -> set[tuple[str, str, str, str]]:
    fixes = set()
    for affected in record.get("affected", []):
        for affected_range in affected.get("ranges", []):
            if affected_range.get("type") != "GIT":
                continue
            repository = canonical_github_repo(affected_range.get("repo"))
            if not repository:
                continue
            for event in affected_range.get("events", []):
                commit = str(event.get("fixed", "")).lower()
                if HEX40.fullmatch(commit):
                    fixes.add(
                        (
                            repository,
                            commit,
                            "osv_git_fixed",
                            f"https://github.com/{repository}/commit/{commit}",
                        )
                    )
    for reference in record.get("references", []):
        if reference.get("type") != "FIX":
            continue
        url = str(reference.get("url", ""))
        repository = canonical_github_repo(url)
        commit = _commit_from_url(url)
        if repository and commit:
            fixes.add((repository, commit, "reference_fix", url))
    return fixes


def _package_keys(record: dict) -> set[str]:
    return {
        f"{package['ecosystem']}:{package['name']}"
        for affected in record.get("affected", [])
        if (package := affected.get("package"))
        and package.get("ecosystem")
        and package.get("name")
    }


def _cwes(record: dict) -> set[str]:
    values = []
    containers = [record.get("database_specific", {})]
    for affected in record.get("affected", []):
        containers.extend(
            [
                affected.get("database_specific", {}),
                affected.get("ecosystem_specific", {}),
            ]
        )
    for container in containers:
        if not isinstance(container, dict):
            continue
        for key in ("cwe", "cwes", "cwe_id", "cwe_ids"):
            raw = container.get(key, [])
            values.extend([raw] if isinstance(raw, str) else raw or [])
    return {
        f"CWE-{match.group(1)}"
        for value in values
        if (match := re.search(r"CWE[- ]?(\d+)", str(value), re.IGNORECASE))
    }


def _behavioral_evidence(component: dict) -> list[dict]:
    evidence = []
    if component["summaries"]:
        evidence.append({"type": "osv_summary", "count": len(component["summaries"])})
    if component["details"]:
        evidence.append({"type": "osv_details", "count": len(component["details"])})
    evidence_urls = sorted(
        url
        for reference_type, url in component["references"]
        if reference_type in BEHAVIOR_REFERENCE_TYPES
    )
    if evidence_urls:
        evidence.append(
            {"type": "public_evidence_reference", "urls": evidence_urls}
        )
    return evidence


def _component_id(ids: set[str]) -> str:
    for prefix in ("CVE-", "GHSA-"):
        matches = sorted(identifier for identifier in ids if identifier.startswith(prefix))
        if matches:
            return matches[0]
    return sorted(ids)[0]


def _priority_reason(component: dict, cutoff: datetime | None) -> str | None:
    summary = " | ".join(component["summaries"])
    outcome = bool(SECURITY_OUTCOME.search(summary))
    if cutoff:
        for reference in component["references"]:
            match = URL_DATE.search(reference["url"])
            if not match:
                continue
            published = datetime(
                *(int(part) for part in match.groups()), tzinfo=timezone.utc
            )
            if published <= cutoff:
                return "explicit_pre_cutoff_reference"
    if AVAILABILITY_ONLY.search(summary) and not outcome:
        return "availability_only"
    if NON_RUNTIME.search(summary) and not outcome:
        return "non_runtime_only"
    if not outcome:
        return "no_clear_security_outcome_in_summary"
    if not any(fix["source"] == "reference_fix" for fix in component["fixes"]):
        return "no_direct_fix_reference"
    return None


def _actively_maintained(project: dict, as_of: datetime) -> bool:
    pushed_at = _timestamp(project.get("pushed_at"))
    return pushed_at is not None and 0 <= (as_of - pushed_at).days <= MAX_INACTIVITY_DAYS


def generate(
    *,
    projects_path: Path,
    raw_dir: Path,
    manifest_path: Path,
    cutoff_value: str | None,
) -> dict:
    cutoff = _timestamp(cutoff_value)
    archives, manifest = _manifest_archives(raw_dir, manifest_path)
    project_payload = json.loads(projects_path.read_text(encoding="utf-8"))
    ranking_as_of_value = str(
        project_payload.get("generated_at") or manifest.get("generated_at") or ""
    )
    ranking_as_of = _timestamp(ranking_as_of_value)
    if ranking_as_of is None:
        raise InputError("project catalog and OSV manifest lack a generated_at timestamp")
    projects = {
        project["repository"].lower(): project
        for project in project_payload.get("projects", [])
        if project.get("repository")
    }

    aliases = Aliases()
    metadata = []
    scanned = withdrawn = 0
    for _, _, record in _records(archives):
        scanned += 1
        ids = _record_ids(record)
        if ids:
            aliases.union_all(ids)
        if record.get("withdrawn"):
            withdrawn += 1
            continue
        if not ids:
            continue
        metadata.append(
            {
                "identifier": min(ids),
                "published": _timestamp(record.get("published")),
                "fixes": _fix_boundaries(record),
            }
        )

    dates: dict[str, list[datetime]] = defaultdict(list)
    fixes: dict[str, set[tuple[str, str, str, str]]] = defaultdict(set)
    for item in metadata:
        root = aliases.find(item["identifier"])
        if item["published"]:
            dates[root].append(item["published"])
        fixes[root].update(item["fixes"])
    candidate_roots = {
        root
        for root, root_fixes in fixes.items()
        if root_fixes
        and (
            cutoff is None
            or (dates[root] and min(dates[root]) > cutoff)
        )
    }

    components: dict[str, dict] = {}
    for archive_name, member_name, record in _records(archives):
        if record.get("withdrawn") or not (ids := _record_ids(record)):
            continue
        root = aliases.find(min(ids))
        if root not in candidate_roots:
            continue
        component = components.setdefault(
            root,
            {
                "ids": set(),
                "summaries": set(),
                "details": set(),
                "packages": set(),
                "references": set(),
                "severities": set(),
                "sources": set(),
                "source_databases": set(),
                "cwes": set(),
            },
        )
        component["ids"].update(ids)
        if record.get("summary"):
            component["summaries"].add(str(record["summary"]).strip())
        if record.get("details"):
            component["details"].add(str(record["details"]).strip())
        component["packages"].update(_package_keys(record))
        component["cwes"].update(_cwes(record))
        component["references"].update(
            (str(reference.get("type", "UNKNOWN")), str(reference["url"]))
            for reference in record.get("references", [])
            if reference.get("url")
        )
        component["severities"].update(
            str(severity["score"])
            for severity in record.get("severity", [])
            if severity.get("score")
        )
        component["sources"].add(f"{archive_name}:{member_name}")
        component["source_databases"].add(Path(archive_name).stem)

    rows_by_repository: dict[str, list[dict]] = defaultdict(list)
    priority_exclusions = Counter()
    hard_gate_exclusions = Counter()
    for root, component in components.items():
        ids = component["ids"]
        component_id = _component_id(ids)
        summaries = sorted(component["summaries"])
        if component_id.startswith(("MAL-", "OSV-")) or any(
            "malicious code in " in summary.lower() for summary in summaries
        ):
            hard_gate_exclusions["malicious_package_record"] += 1
            continue
        behavioral_evidence = _behavioral_evidence(component)
        if not behavioral_evidence:
            hard_gate_exclusions["no_behavioral_evidence"] += 1
            continue
        for repository in sorted({fix[0] for fix in fixes[root]}):
            project = projects.get(repository)
            if not project or project.get("archived"):
                continue
            if not _actively_maintained(project, ranking_as_of):
                hard_gate_exclusions["inactive_project"] += 1
                continue
            if project.get("license") in NON_LICENSES:
                continue
            signals = (
                set(project.get("discovery_categories", [])) & SERVICE_CATEGORIES
            ) | (set(project.get("topics", [])) & SERVICE_TOPICS)
            if not signals:
                continue
            repository_fixes = [
                {"sha": sha, "source": source, "url": url}
                for fix_repository, sha, source, url in sorted(fixes[root])
                if fix_repository == repository
            ]
            row = {
                "component_id": component_id,
                "ids": sorted(ids),
                "earliest_osv_publication": min(dates[root]).isoformat(),
                "summaries": summaries,
                "details": sorted(component["details"]),
                "packages": sorted(component["packages"]),
                "fixes": repository_fixes,
                "references": [
                    {"type": reference_type, "url": url}
                    for reference_type, url in sorted(component["references"])
                ],
                "severities": sorted(component["severities"]),
                "sources": sorted(component["sources"]),
                "source_databases": sorted(component["source_databases"]),
                "cwes": sorted(
                    component["cwes"],
                    key=lambda item: int(item.split("-", 1)[1]),
                ),
                "behavioral_evidence": behavioral_evidence,
                "repair_evidence": repository_fixes,
            }
            reason = _priority_reason(row, cutoff)
            row["priority"] = reason is None
            row["priority_exclusion_reason"] = reason
            if reason:
                priority_exclusions[reason] += 1
            rows_by_repository[repository].append(row)

    output_projects = []
    priority_projects = []
    for repository, component_rows in rows_by_repository.items():
        project = projects[repository]
        score, score_components = popularity_score(project, as_of=ranking_as_of_value)
        if score < BASE_POPULARITY_SCORE:
            continue
        component_rows.sort(
            key=lambda item: (item["earliest_osv_publication"], item["component_id"])
        )
        priority_components = [item for item in component_rows if item["priority"]]
        row = {
            "repository": repository,
            "project": {
                key: project.get(key)
                for key in (
                    "url",
                    "description",
                    "stars",
                    "forks",
                    "license",
                    "pushed_at",
                    "topics",
                )
            },
            "popularity_score": score,
            "popularity_score_components": score_components,
            "application_review_required": True,
            "license_review_required": True,
            "components": component_rows,
        }
        output_projects.append(row)
        if (
            score >= PRIORITY_POPULARITY_SCORE
            and len(priority_components) >= PRIORITY_MIN_COMPONENTS
        ):
            priority_projects.append(
                {
                    "repository": repository,
                    "popularity_score": score,
                    "component_ids": [
                        item["component_id"] for item in priority_components
                    ],
                    "candidate_fix_commits": sorted(
                        {
                            fix["sha"]
                            for item in priority_components
                            for fix in item["fixes"]
                        }
                    ),
                }
            )

    output_projects.sort(key=lambda item: (-item["popularity_score"], item["repository"]))
    priority_projects.sort(
        key=lambda item: (-len(item["component_ids"]), -item["popularity_score"], item["repository"])
    )
    return {
        "schema_version": 1,
        "method": "compact_candidate_shortlist",
        "date_cutoff": {
            "enabled": cutoff is not None,
            "published_after": cutoff.isoformat() if cutoff else None,
            "comparison": "earliest active OSV publication is strictly later",
        },
        "thresholds": {
            "base_popularity_score": BASE_POPULARITY_SCORE,
            "priority_popularity_score": PRIORITY_POPULARITY_SCORE,
            "priority_min_components": PRIORITY_MIN_COMPONENTS,
            "maximum_inactivity_days": MAX_INACTIVITY_DAYS,
        },
        "sources": {
            "projects": {"path": str(projects_path), "sha256": _sha256(projects_path)},
            "osv_manifest": {
                "path": str(manifest_path),
                "sha256": _sha256(manifest_path),
            },
        },
        "summary": {
            "scanned_osv_records": scanned,
            "withdrawn_osv_records": withdrawn,
            "hard_gate_projects": len(output_projects),
            "hard_gate_components": sum(len(item["components"]) for item in output_projects),
            "priority_projects": len(priority_projects),
            "hard_gate_exclusions": dict(sorted(hard_gate_exclusions.items())),
            "priority_exclusions": dict(sorted(priority_exclusions.items())),
        },
        "priority_projects": priority_projects,
        "projects": output_projects,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--projects", type=Path, required=True)
    parser.add_argument("--raw-dir", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument(
        "--published-after",
        help="enable the optional cutoff with a timezone-qualified ISO-8601 timestamp",
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        payload = generate(
            projects_path=args.projects,
            raw_dir=args.raw_dir,
            manifest_path=args.manifest,
            cutoff_value=args.published_after,
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    except (InputError, OSError, KeyError, json.JSONDecodeError, zipfile.BadZipFile) as error:
        parser.error(str(error))
    print(
        f"wrote {payload['summary']['hard_gate_projects']} hard-gate projects and "
        f"{payload['summary']['priority_projects']} priority projects to {args.output}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
