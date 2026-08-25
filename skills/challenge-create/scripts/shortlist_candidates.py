#!/usr/bin/env python3
"""Build an advisory-first OSS challenge-candidate shortlist."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from _lib import canonical_github_repo, prototype_exclusion_reason
from osv_history import (
    CorpusError,
    candidate_repository_roles,
    iter_archive_records,
    manifest_archives,
    parse_git_phases,
)


HEX40 = re.compile(r"[0-9a-fA-F]{40}")
MAX_INACTIVITY_DAYS = 730
NON_LICENSES = {None, "", "NOASSERTION", "OTHER"}
BEHAVIOR_REFERENCE_TYPES = {"EVIDENCE"}
PROJECT_METADATA_FIELDS = (
    "url",
    "name",
    "description",
    "stars",
    "forks",
    "license",
    "archived",
    "pushed_at",
    "topics",
    "default_branch",
    "observed_at",
)


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


def _canonical_repository(value: str | None) -> str | None:
    return canonical_github_repo(value) or canonical_github_repo(
        f"https://github.com/{value}" if value else None
    )


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


def _release_boundaries(record: dict) -> set[tuple[str, str, str]]:
    boundaries = set()
    for affected in record.get("affected", []):
        package = affected.get("package", {})
        ecosystem = str(package.get("ecosystem", ""))
        name = str(package.get("name", ""))
        package_key = f"{ecosystem}:{name}" if ecosystem and name else ""
        for affected_range in affected.get("ranges", []):
            range_type = str(affected_range.get("type", "UNKNOWN"))
            if range_type == "GIT":
                continue
            for event in affected_range.get("events", []):
                fixed = str(event.get("fixed", ""))
                if fixed:
                    boundaries.add((range_type, package_key, fixed))
    return boundaries


def _git_range_evidence(record: dict) -> set[str]:
    evidence = set()
    for affected in record.get("affected", []):
        for affected_range in affected.get("ranges", []):
            if affected_range.get("type") != "GIT":
                continue
            repository = canonical_github_repo(affected_range.get("repo"))
            if not repository:
                continue
            events = affected_range.get("events", [])
            phases, blockers = parse_git_phases(events)
            if any(not phase["fixed"] for phase in phases):
                blockers = sorted({*blockers, "phase_without_fix_boundary"})
            evidence.add(
                json.dumps(
                    {
                        "repository": repository,
                        "events": events,
                        "blockers": blockers,
                    },
                    sort_keys=True,
                )
            )
    return evidence


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
            [affected.get("database_specific", {}), affected.get("ecosystem_specific", {})]
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
        evidence.append({"type": "advisory_summary", "count": len(component["summaries"])})
    if component["details"]:
        evidence.append({"type": "advisory_details", "count": len(component["details"])})
    urls = sorted(
        url
        for reference_type, url in component["references"]
        if reference_type in BEHAVIOR_REFERENCE_TYPES
    )
    if urls:
        evidence.append({"type": "public_evidence_reference", "urls": urls})
    return evidence


def _component_id(ids: set[str]) -> str:
    for prefix in ("CVE-", "GHSA-"):
        matches = sorted(identifier for identifier in ids if identifier.startswith(prefix))
        if matches:
            return matches[0]
    return sorted(ids)[0]


def _application_mapping(component: dict) -> tuple[str | None, dict]:
    roles = component["repository_roles"]
    for role in (
        "affected_git_range",
        "package_reference",
        "upstream_security_advisory",
    ):
        repositories = sorted(roles.get(role, set()))
        if len(repositories) == 1:
            return repositories[0], {
                "basis": role,
                "evidence": {
                    key: sorted(value) for key, value in sorted(roles.items()) if value
                },
            }
        if len(repositories) > 1:
            return None, {
                "reason": "ambiguous_application_repository",
                "basis": role,
                "candidate_repositories": repositories,
                "evidence": {
                    key: sorted(value) for key, value in sorted(roles.items()) if value
                },
            }
    return None, {
        "reason": "application_repository_not_established",
        "candidate_repositories": sorted(roles.get("fix_repository", set())),
        "evidence": {
            key: sorted(value) for key, value in sorted(roles.items()) if value
        },
    }


def _load_duplicate_inventory(path: Path | None) -> tuple[set[str], set[str]]:
    if path is None:
        return set(), set()
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("schema_version") != 1:
        raise InputError("duplicate inventory must use schema_version 1")
    repositories = set()
    for value in payload.get("repositories", []):
        repository = _canonical_repository(str(value))
        if not repository:
            raise InputError(f"invalid duplicate-inventory repository: {value!r}")
        repositories.add(repository)
    advisory_ids = {str(value) for value in payload.get("advisory_ids", []) if value}
    return repositories, advisory_ids


def _github_repository(repository: str) -> dict | None:
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "cyber-arena-stage1",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = Request(f"https://api.github.com/repos/{repository}", headers=headers)
    try:
        with urlopen(request, timeout=30) as response:
            payload = json.load(response)
    except HTTPError as error:
        if error.code == 404:
            return None
        raise InputError(
            f"GitHub metadata request failed for {repository}: HTTP {error.code}"
        ) from error
    except URLError as error:
        raise InputError(
            f"GitHub metadata request failed for {repository}: {error.reason}"
        ) from error
    canonical = canonical_github_repo(payload.get("html_url") or payload.get("full_name"))
    if not canonical:
        raise InputError(f"GitHub returned an invalid repository identity for {repository}")
    return {
        "repository": canonical,
        "url": payload.get("html_url"),
        "name": payload.get("name"),
        "description": payload.get("description"),
        "stars": payload.get("stargazers_count", 0),
        "forks": payload.get("forks_count", 0),
        "license": (payload.get("license") or {}).get("spdx_id"),
        "archived": bool(payload.get("archived")),
        "pushed_at": payload.get("pushed_at"),
        "topics": payload.get("topics", []),
        "default_branch": payload.get("default_branch"),
        "observed_at": datetime.now(timezone.utc).isoformat(),
    }


def _project_disposition(project: dict) -> tuple[str, str | None]:
    if project.get("archived"):
        return "excluded", "archived_project"
    observed_at = _timestamp(project.get("observed_at"))
    pushed_at = _timestamp(project.get("pushed_at"))
    if observed_at is None or pushed_at is None:
        return "unresolved", "missing_activity_timestamp"
    age = (observed_at - pushed_at).days
    if age < 0:
        return "unresolved", "future_activity_timestamp"
    if age > MAX_INACTIVITY_DAYS:
        return "excluded", "inactive_project"
    if project.get("license") in NON_LICENSES:
        return "unresolved", "acceptable_oss_license_not_established"
    service_reason = prototype_exclusion_reason(project)
    if service_reason == "no clear deployable network-service signal in repository metadata":
        return "unresolved", "deployable_service_not_established"
    if service_reason:
        return "excluded", service_reason
    return "accepted", None


def _project_metadata(project: dict, canonical: str) -> dict:
    return {
        **{key: project.get(key) for key in PROJECT_METADATA_FIELDS},
        "canonical_repository": canonical,
    }


def _component_row(root: str, component: dict, dates: dict, fixes: dict, releases: dict) -> dict:
    component["repository_roles"]["fix_repository"].update(
        fix_repository for fix_repository, _, _, _ in fixes[root]
    )
    repository, mapping = _application_mapping(component)
    commit_repairs = [
        {"repository": fix_repository, "sha": sha, "source": source, "url": url}
        for fix_repository, sha, source, url in sorted(fixes[root])
    ]
    release_repairs = [
        {"range_type": range_type, "package": package, "fixed": fixed}
        for range_type, package, fixed in sorted(releases[root])
    ]
    application_git_ranges = [
        item
        for value in sorted(component["git_ranges"])
        if (item := json.loads(value))["repository"] == repository
    ]
    return {
        "component_id": _component_id(component["ids"]),
        "ids": sorted(component["ids"]),
        "earliest_osv_publication": min(dates[root]).isoformat() if dates[root] else None,
        "summaries": sorted(component["summaries"]),
        "details": sorted(component["details"]),
        "packages": sorted(component["packages"]),
        "fixes": [
            {key: value for key, value in repair.items() if key != "repository"}
            for repair in commit_repairs
            if repair["repository"] == repository
        ],
        "fix_repositories": sorted({repair["repository"] for repair in commit_repairs}),
        "references": [
            {"type": reference_type, "url": url}
            for reference_type, url in sorted(component["references"])
        ],
        "severities": sorted(component["severities"]),
        "sources": sorted(component["sources"]),
        "source_databases": sorted(component["source_databases"]),
        "cwes": sorted(component["cwes"]),
        "behavioral_evidence": _behavioral_evidence(component),
        "repair_evidence": [*commit_repairs, *release_repairs],
        "application_repository": repository,
        "application_mapping": mapping,
        "application_git_ranges": application_git_ranges,
    }


def generate(
    *,
    raw_dir: Path,
    manifest_path: Path,
    cutoff_value: str | None,
    duplicate_inventory_path: Path | None = None,
    fetch_repository=None,
) -> dict:
    cutoff = _timestamp(cutoff_value)
    manifest, archives = manifest_archives(raw_dir, manifest_path)
    duplicate_repositories, duplicate_ids = _load_duplicate_inventory(
        duplicate_inventory_path
    )
    fetch_repository = fetch_repository or _github_repository

    aliases = Aliases()
    metadata = []
    scanned = withdrawn = 0
    for wrapped in iter_archive_records(archives):
        record = wrapped["record"]
        scanned += 1
        ids = _record_ids(record)
        if ids:
            aliases.union_all(ids)
        if record.get("withdrawn"):
            withdrawn += 1
            continue
        if ids:
            metadata.append(
                {
                    "identifier": min(ids),
                    "published": _timestamp(record.get("published")),
                    "fixes": _fix_boundaries(record),
                    "releases": _release_boundaries(record),
                }
            )

    dates: dict[str, list[datetime]] = defaultdict(list)
    fixes: dict[str, set[tuple[str, str, str, str]]] = defaultdict(set)
    releases: dict[str, set[tuple[str, str, str]]] = defaultdict(set)
    for item in metadata:
        root = aliases.find(item["identifier"])
        if item["published"]:
            dates[root].append(item["published"])
        fixes[root].update(item["fixes"])
        releases[root].update(item["releases"])

    repair_roots = {
        root for root in set(fixes) | set(releases) if fixes[root] or releases[root]
    }
    date_exclusions = Counter()
    active_roots = {aliases.find(item["identifier"]) for item in metadata}
    if missing_repairs := len(active_roots - repair_roots):
        date_exclusions["no_repair_evidence"] = missing_repairs
    candidate_roots = set()
    for root in repair_roots:
        if cutoff is not None and not dates[root]:
            date_exclusions["missing_publication_date"] += 1
        elif cutoff is not None and min(dates[root]) <= cutoff:
            date_exclusions["pre_cutoff_publication"] += 1
        else:
            candidate_roots.add(root)

    components: dict[str, dict] = {}
    for wrapped in iter_archive_records(archives):
        record = wrapped["record"]
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
                "repository_roles": defaultdict(set),
                "git_ranges": set(),
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
        component["sources"].add(
            f"{wrapped['source_archive']}:{wrapped['source_member']}"
        )
        component["source_databases"].add(wrapped["source_database"])
        for role, repositories in candidate_repository_roles(record).items():
            component["repository_roles"][role].update(repositories)
        component["git_ranges"].update(_git_range_evidence(record))

    exclusions = Counter(date_exclusions)
    unresolved = []
    rows_by_repository: dict[str, list[dict]] = defaultdict(list)
    for root, component in components.items():
        row = _component_row(root, component, dates, fixes, releases)
        summaries = row["summaries"]
        if row["component_id"].startswith(("MAL-", "OSV-")) or any(
            "malicious code in " in summary.lower() for summary in summaries
        ):
            exclusions["malicious_package_record"] += 1
            continue
        if not row["behavioral_evidence"]:
            exclusions["no_behavioral_evidence"] += 1
            continue
        row["duplicate_matches"] = sorted(duplicate_ids & set(row["ids"]))
        if not fixes[root]:
            unresolved.append(
                {
                    "component_id": row["component_id"],
                    "ids": row["ids"],
                    "reason": "exact_git_repair_not_established",
                    "repair_evidence": row["repair_evidence"],
                    "application_repository": row["application_repository"],
                    "application_mapping": row["application_mapping"],
                }
            )
            continue
        repository = row["application_repository"]
        if not repository:
            unresolved.append(
                {
                    "component_id": row["component_id"],
                    "ids": row["ids"],
                    **row["application_mapping"],
                }
            )
            continue
        if not row["application_git_ranges"] or any(
            item["blockers"] for item in row["application_git_ranges"]
        ):
            unresolved.append(
                {
                    "component_id": row["component_id"],
                    "ids": row["ids"],
                    "reason": "usable_application_git_range_not_established",
                    "application_repository": repository,
                    "application_mapping": row["application_mapping"],
                    "application_git_ranges": row["application_git_ranges"],
                    "repair_evidence": row["repair_evidence"],
                }
            )
            continue
        rows_by_repository[repository].append(row)

    fetched = 0
    accepted_rows: dict[str, dict] = {}
    for requested_repository, component_rows in sorted(rows_by_repository.items()):
        project = fetch_repository(requested_repository)
        fetched += 1
        if project is None:
            unresolved.append(
                {
                    "repository": requested_repository,
                    "component_ids": sorted(row["component_id"] for row in component_rows),
                    "reason": "repository_metadata_not_found",
                }
            )
            continue
        canonical = _canonical_repository(project.get("repository"))
        if not canonical:
            raise InputError(f"invalid fetched repository identity for {requested_repository}")
        disposition, reason = _project_disposition(project)
        if disposition != "accepted":
            item = {
                "repository": canonical,
                "requested_repository": requested_repository,
                "component_ids": sorted(row["component_id"] for row in component_rows),
                "reason": reason,
                "project": _project_metadata(project, canonical),
            }
            if disposition == "unresolved":
                unresolved.append(item)
            else:
                exclusions[reason] += len(component_rows)
            continue
        result = accepted_rows.setdefault(
            canonical,
            {
                "repository": canonical,
                "repository_aliases": [],
                "project": _project_metadata(project, canonical),
                "duplicate_matches": sorted(
                    {requested_repository, canonical} & duplicate_repositories
                ),
                "components": [],
            },
        )
        if requested_repository not in result["repository_aliases"]:
            result["repository_aliases"].append(requested_repository)
        result["duplicate_matches"] = sorted(
            set(result["duplicate_matches"])
            | ({requested_repository, canonical} & duplicate_repositories)
        )
        result["components"].extend(component_rows)

    output_projects = list(accepted_rows.values())
    for project in output_projects:
        project["repository_aliases"] = sorted(
            set(project["repository_aliases"]) | {project["repository"]}
        )
        project["components"].sort(
            key=lambda item: (
                item["earliest_osv_publication"] or "",
                item["component_id"],
            )
        )
    output_projects.sort(
        key=lambda item: (
            -len({db for row in item["components"] for db in row["source_databases"]}),
            -int(item["project"].get("stars") or 0),
            -int(item["project"].get("forks") or 0),
            item["repository"],
        )
    )

    sources = {
        "advisory_manifest": {
            "path": str(manifest_path),
            "sha256": _sha256(manifest_path),
            "source_count": len(manifest.get("sources", [])),
        }
    }
    if duplicate_inventory_path:
        sources["duplicate_inventory"] = {
            "path": str(duplicate_inventory_path),
            "sha256": _sha256(duplicate_inventory_path),
        }
    return {
        "schema_version": 2,
        "method": "advisory_first_candidate_shortlist",
        "date_cutoff": {
            "enabled": cutoff is not None,
            "published_after": cutoff.isoformat() if cutoff else None,
            "comparison": "earliest active advisory publication is strictly later",
        },
        "project_gates": {
            "maximum_inactivity_days": MAX_INACTIVITY_DAYS,
            "acceptable_oss_license_required": True,
            "deployable_service_signal_required": True,
        },
        "ordering": [
            "advisory source diversity",
            "stars (tie-breaker only)",
            "forks (tie-breaker only)",
            "repository",
        ],
        "sources": sources,
        "summary": {
            "scanned_advisory_records": scanned,
            "withdrawn_advisory_records": withdrawn,
            "github_repositories_fetched": fetched,
            "candidate_projects": len(output_projects),
            "candidate_components": sum(len(item["components"]) for item in output_projects),
            "unresolved_candidates": len(unresolved),
            "exclusions": dict(sorted(exclusions.items())),
        },
        "unresolved_candidates": sorted(
            unresolved,
            key=lambda item: (
                item.get("repository", ""),
                item.get("component_id", ""),
                item.get("reason", ""),
            ),
        ),
        "projects": output_projects,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw-dir", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--duplicate-inventory", type=Path)
    parser.add_argument(
        "--published-after",
        help="enable the optional cutoff with a timezone-qualified ISO-8601 timestamp",
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        payload = generate(
            raw_dir=args.raw_dir,
            manifest_path=args.manifest,
            cutoff_value=args.published_after,
            duplicate_inventory_path=args.duplicate_inventory,
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    except (InputError, CorpusError, OSError, KeyError, json.JSONDecodeError) as error:
        parser.error(str(error))
    print(
        f"wrote {payload['summary']['candidate_projects']} candidate projects and "
        f"{payload['summary']['unresolved_candidates']} unresolved candidates to {args.output}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
