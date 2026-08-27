#!/usr/bin/env python3
"""Build an advisory-first OSS challenge-candidate shortlist."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import time
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
EVIDENCE_ASSET_FIELDS = (
    "advisory_text",
    "exploit_evidence",
    "cwe",
    "affected_package",
    "exact_git_repair",
    "fixed_release",
    "application_repository",
    "usable_application_git_range",
    "repository_metadata",
)
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
METADATA_CACHE_SCHEMA_VERSION = 1
MAX_RATE_LIMIT_WAIT_SECONDS = 60
SERVICE_GATE_REASONS = {
    "conflicting_service_metadata",
    "deployable_service_not_established",
    "non_service_shape_indicated",
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


def _load_stage1_5_evidence(path: Path | None) -> dict[str, dict]:
    if path is None:
        return {}
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("schema_version") != 1:
        raise InputError("Stage 1.5 evidence must use schema_version 1")
    resolutions = {}
    for item in payload.get("resolutions", []):
        if not isinstance(item, dict):
            raise InputError("invalid Stage 1.5 resolution")
        component_id = str(item.get("component_id", ""))
        repository = _canonical_repository(item.get("repository"))
        service_url = str(item.get("service_evidence", ""))
        parsed = urlparse(service_url)
        parts = [part for part in parsed.path.strip("/").split("/") if part]
        if (
            not component_id
            or component_id in resolutions
            or repository != item.get("repository")
            or canonical_github_repo(service_url) != repository
            or len(parts) < 5
            or parts[2] != "blob"
            or not HEX40.fullmatch(parts[3])
        ):
            raise InputError(f"invalid Stage 1.5 resolution: {component_id!r}")

        resolution = {
            "component_id": component_id,
            "repository": repository,
            "service_evidence": service_url,
        }
        if repair := item.get("repair"):
            commits = repair.get("commits", [])
            events = repair.get("events", [])
            phases, blockers = parse_git_phases(events)
            normalized = []
            for commit in commits:
                sha = str(commit.get("sha", "")).lower()
                parent = str(commit.get("affected_parent", "")).lower()
                url = str(commit.get("url", ""))
                if (
                    not HEX40.fullmatch(sha)
                    or not HEX40.fullmatch(parent)
                    or canonical_github_repo(url) != repository
                    or _commit_from_url(url) != sha
                ):
                    raise InputError(f"invalid Stage 1.5 repair: {component_id}")
                normalized.append({"sha": sha, "affected_parent": parent, "url": url})
            fixed = {value for phase in phases for value in phase["fixed"]}
            if (
                not normalized
                or blockers
                or any(not phase["fixed"] for phase in phases)
                or fixed != {commit["sha"] for commit in normalized}
            ):
                raise InputError(f"invalid Stage 1.5 repair range: {component_id}")
            resolution["repair"] = {
                "commits": sorted(normalized, key=lambda value: value["sha"]),
                "events": events,
            }
        resolutions[component_id] = resolution
    return resolutions


def _rate_limit_delay(error: HTTPError) -> float | None:
    if error.code not in {403, 429}:
        return None
    headers = error.headers or {}
    retry_after = headers.get("Retry-After")
    if retry_after is not None:
        try:
            return max(0.0, float(retry_after))
        except ValueError:
            return None
    reset = headers.get("X-RateLimit-Reset")
    if reset is not None:
        try:
            return max(0.0, float(reset) - time.time())
        except ValueError:
            return None
    return None


def _github_repository(repository: str) -> dict | None:
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "cyber-arena-stage1",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = Request(f"https://api.github.com/repos/{repository}", headers=headers)
    for attempt in range(2):
        try:
            with urlopen(request, timeout=30) as response:
                payload = json.load(response)
            break
        except HTTPError as error:
            if error.code == 404:
                return None
            delay = _rate_limit_delay(error)
            if attempt == 0 and delay is not None and delay <= MAX_RATE_LIMIT_WAIT_SECONDS:
                time.sleep(delay)
                continue
            detail = ""
            if delay is not None:
                detail = f"; retry after approximately {int(delay)} seconds"
            raise InputError(
                f"GitHub metadata request failed for {repository}: "
                f"HTTP {error.code}{detail}"
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
    if service_reason:
        return "unresolved", service_reason
    return "accepted", None


def _load_metadata_cache(path: Path | None) -> dict[str, dict | None]:
    if path is None or not path.exists():
        return {}
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("schema_version") != METADATA_CACHE_SCHEMA_VERSION:
        raise InputError("GitHub metadata cache must use schema_version 1")
    repositories = payload.get("repositories")
    if not isinstance(repositories, dict):
        raise InputError("GitHub metadata cache repositories must be an object")
    for repository, project in repositories.items():
        if _canonical_repository(repository) != repository:
            raise InputError(f"invalid GitHub metadata cache key: {repository!r}")
        if project is not None and not isinstance(project, dict):
            raise InputError(
                f"invalid GitHub metadata cache entry for {repository!r}"
            )
    return repositories


def _write_metadata_cache(path: Path, repositories: dict[str, dict | None]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(
        json.dumps(
            {
                "schema_version": METADATA_CACHE_SCHEMA_VERSION,
                "repositories": repositories,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def _project_metadata(project: dict, canonical: str) -> dict:
    return {
        **{key: project.get(key) for key in PROJECT_METADATA_FIELDS},
        "canonical_repository": canonical,
    }


def _component_row(
    root: str,
    component: dict,
    dates: dict,
    fixes: dict,
    releases: dict,
    fast_lane_memberships: dict,
) -> dict:
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
    row = {
        "component_id": _component_id(component["ids"]),
        "ids": sorted(component["ids"]),
        "earliest_manifested_publication": (
            min(dates[root]).isoformat() if dates[root] else None
        ),
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
        "fast_lane_memberships": [
            {"priority": priority, "lane": lane, "source": source}
            for priority, lane, source in sorted(fast_lane_memberships[root])
        ],
    }
    if resolution := component.get("stage1_5_resolution"):
        row["stage1_5_resolution"] = resolution
    return row


def _fast_lane_fields(row: dict) -> dict:
    return {"fast_lane_memberships": row["fast_lane_memberships"]}


def _evidence_matrix_row(
    row: dict,
    *,
    disposition: str,
    reason: str | None,
    repository_metadata: bool,
    repository: str | None = None,
) -> dict:
    assets = {
        "advisory_text": bool(row["summaries"] or row["details"]),
        "exploit_evidence": any(
            reference["type"] in BEHAVIOR_REFERENCE_TYPES
            for reference in row["references"]
        ),
        "cwe": bool(row["cwes"]),
        "affected_package": bool(row["packages"]),
        "exact_git_repair": any(
            repair.get("sha") for repair in row["repair_evidence"]
        ),
        "fixed_release": any(
            repair.get("fixed") for repair in row["repair_evidence"]
        ),
        "application_repository": bool(row["application_repository"]),
        "usable_application_git_range": bool(row["application_git_ranges"])
        and not any(item["blockers"] for item in row["application_git_ranges"]),
        "repository_metadata": repository_metadata,
    }
    return {
        "component_id": row["component_id"],
        "disposition": disposition,
        "reason": reason,
        "repository": repository or row["application_repository"],
        "earliest_manifested_publication": row[
            "earliest_manifested_publication"
        ],
        "assets": assets,
    }


def _component_duplicate_matches(row: dict, duplicate_repositories: set[str]) -> list[str]:
    repositories = set(row["application_mapping"].get("candidate_repositories", []))
    if row["application_repository"]:
        repositories.add(row["application_repository"])
    return sorted(set(row["duplicate_matches"]) | (repositories & duplicate_repositories))


def _combined_fast_lane_memberships(rows: list[dict]) -> list[dict]:
    return [
        {"priority": priority, "lane": lane, "source": source}
        for priority, lane, source in sorted(
            {
                (
                    membership["priority"],
                    membership["lane"],
                    membership["source"],
                )
                for row in rows
                for membership in row["fast_lane_memberships"]
            }
        )
    ]


def _component_publications(rows: list[dict]) -> list[dict]:
    return [
        {
            "component_id": row["component_id"],
            "earliest_manifested_publication": row[
                "earliest_manifested_publication"
            ],
        }
        for row in sorted(rows, key=lambda item: item["component_id"])
    ]


def generate(
    *,
    raw_dir: Path,
    manifest_path: Path,
    duplicate_inventory_path: Path | None = None,
    metadata_cache_path: Path | None = None,
    stage1_5_evidence_path: Path | None = None,
    fetch_repository=None,
) -> dict:
    manifest, archives = manifest_archives(raw_dir, manifest_path)
    duplicate_repositories, duplicate_ids = _load_duplicate_inventory(
        duplicate_inventory_path
    )
    resolutions = _load_stage1_5_evidence(stage1_5_evidence_path)
    fetch_repository = fetch_repository or _github_repository
    metadata_cache = _load_metadata_cache(metadata_cache_path)

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
                    "fast_lane_membership": (
                        (
                            wrapped["source_priority"],
                            wrapped["source_lane"],
                            wrapped["source_database"],
                        )
                        if wrapped["source_role"] == "fast_lane"
                        else None
                    ),
                }
            )

    dates: dict[str, list[datetime]] = defaultdict(list)
    fixes: dict[str, set[tuple[str, str, str, str]]] = defaultdict(set)
    releases: dict[str, set[tuple[str, str, str]]] = defaultdict(set)
    fast_lane_memberships: dict[str, set[tuple[int, str, str]]] = defaultdict(set)
    for item in metadata:
        root = aliases.find(item["identifier"])
        if item["published"]:
            dates[root].append(item["published"])
        fixes[root].update(item["fixes"])
        releases[root].update(item["releases"])
        if item["fast_lane_membership"]:
            fast_lane_memberships[root].add(item["fast_lane_membership"])

    resolutions_by_root = {}
    for component_id, resolution in resolutions.items():
        if component_id not in aliases.parent:
            raise InputError(f"Stage 1.5 component is absent from the corpus: {component_id}")
        root = aliases.find(component_id)
        if root in resolutions_by_root:
            raise InputError(f"multiple Stage 1.5 resolutions target {component_id}")
        resolutions_by_root[root] = resolution
        if repair := resolution.get("repair"):
            repository = resolution["repository"]
            fixes[root] = {
                item for item in fixes[root] if item[0] != repository
            } | {
                (repository, commit["sha"], "stage1_5_direct_repair", commit["url"])
                for commit in repair["commits"]
            }

    repair_roots = {
        root for root in set(fixes) | set(releases) if fixes[root] or releases[root]
    }
    exclusions = Counter()
    active_roots = {aliases.find(item["identifier"]) for item in metadata}
    active_lanes = sorted(
        {
            (
                int(item["source"]["priority"]),
                str(item["source"]["lane"]),
                str(
                    item["source"].get("source")
                    or item["source"].get("ecosystem")
                    or item["path"].stem
                ),
            )
            for item in archives
            if item["source"]["role"] == "fast_lane"
        }
    )
    fast_lane_mode = bool(active_lanes)
    selected_roots = (
        set(fast_lane_memberships) if fast_lane_mode else set(repair_roots)
    )
    if not fast_lane_mode and (missing_repairs := len(active_roots - repair_roots)):
        exclusions["no_repair_evidence"] = missing_repairs
    candidate_roots = selected_roots

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

    for root, resolution in resolutions_by_root.items():
        component = components.get(root)
        if component is None:
            raise InputError(
                "Stage 1.5 correction does not target a selected component: "
                f"{_component_id({root})}"
            )
        repository, _ = _application_mapping(component)
        if repository != resolution["repository"]:
            raise InputError(
                "Stage 1.5 correction repository does not match application mapping: "
                f"{_component_id(component['ids'])}"
            )
        if repair := resolution.get("repair"):
            component["git_ranges"] = {
                value
                for value in component["git_ranges"]
                if json.loads(value)["repository"] != repository
            }
            component["git_ranges"].add(
                json.dumps(
                    {
                        "repository": repository,
                        "events": repair["events"],
                        "blockers": [],
                    },
                    sort_keys=True,
                )
            )
        component["stage1_5_resolution"] = resolution

    evidence_matrix_rows = {}
    unresolved = []
    rows_by_repository: dict[str, list[dict]] = defaultdict(list)
    for root, component in components.items():
        row = _component_row(
            root, component, dates, fixes, releases, fast_lane_memberships
        )
        summaries = row["summaries"]
        if row["component_id"].startswith(("MAL-", "OSV-")) or any(
            "malicious code in " in summary.lower() for summary in summaries
        ):
            evidence_matrix_rows[row["component_id"]] = _evidence_matrix_row(
                row,
                disposition="rejected",
                reason="malicious_package_record",
                repository_metadata=False,
            )
            exclusions["malicious_package_record"] += 1
            continue
        if not row["behavioral_evidence"]:
            evidence_matrix_rows[row["component_id"]] = _evidence_matrix_row(
                row,
                disposition="rejected",
                reason="no_behavioral_evidence",
                repository_metadata=False,
            )
            exclusions["no_behavioral_evidence"] += 1
            continue
        row["duplicate_matches"] = sorted(duplicate_ids & set(row["ids"]))
        if not fixes[root]:
            evidence_matrix_rows[row["component_id"]] = _evidence_matrix_row(
                row,
                disposition="unresolved",
                reason="exact_git_repair_not_established",
                repository_metadata=False,
            )
            unresolved.append(
                {
                    "component_id": row["component_id"],
                    "ids": row["ids"],
                    "reason": "exact_git_repair_not_established",
                    "repair_evidence": row["repair_evidence"],
                    "earliest_manifested_publication": row[
                        "earliest_manifested_publication"
                    ],
                    "application_repository": row["application_repository"],
                    "application_mapping": row["application_mapping"],
                    "duplicate_matches": _component_duplicate_matches(
                        row, duplicate_repositories
                    ),
                    **_fast_lane_fields(row),
                }
            )
            continue
        repository = row["application_repository"]
        if not repository:
            reason = row["application_mapping"]["reason"]
            evidence_matrix_rows[row["component_id"]] = _evidence_matrix_row(
                row,
                disposition="unresolved",
                reason=reason,
                repository_metadata=False,
            )
            unresolved.append(
                {
                    "component_id": row["component_id"],
                    "ids": row["ids"],
                    "earliest_manifested_publication": row[
                        "earliest_manifested_publication"
                    ],
                    "duplicate_matches": _component_duplicate_matches(
                        row, duplicate_repositories
                    ),
                    **row["application_mapping"],
                    **_fast_lane_fields(row),
                }
            )
            continue
        if not row["application_git_ranges"] or any(
            item["blockers"] for item in row["application_git_ranges"]
        ):
            evidence_matrix_rows[row["component_id"]] = _evidence_matrix_row(
                row,
                disposition="unresolved",
                reason="usable_application_git_range_not_established",
                repository_metadata=False,
            )
            unresolved.append(
                {
                    "component_id": row["component_id"],
                    "ids": row["ids"],
                    "reason": "usable_application_git_range_not_established",
                    "application_repository": repository,
                    "application_mapping": row["application_mapping"],
                    "application_git_ranges": row["application_git_ranges"],
                    "repair_evidence": row["repair_evidence"],
                    "earliest_manifested_publication": row[
                        "earliest_manifested_publication"
                    ],
                    "duplicate_matches": _component_duplicate_matches(
                        row, duplicate_repositories
                    ),
                    **_fast_lane_fields(row),
                }
            )
            continue
        rows_by_repository[repository].append(row)

    fetched = 0
    accepted_rows: dict[str, dict] = {}
    for requested_repository, component_rows in sorted(rows_by_repository.items()):
        if requested_repository in metadata_cache:
            project = metadata_cache[requested_repository]
        else:
            project = fetch_repository(requested_repository)
            fetched += 1
            metadata_cache[requested_repository] = project
            if metadata_cache_path is not None:
                _write_metadata_cache(metadata_cache_path, metadata_cache)
        if project is None:
            for row in component_rows:
                evidence_matrix_rows[row["component_id"]] = _evidence_matrix_row(
                    row,
                    disposition="unresolved",
                    reason="repository_metadata_not_found",
                    repository_metadata=False,
                )
            unresolved.append(
                {
                    "repository": requested_repository,
                    "component_ids": sorted(row["component_id"] for row in component_rows),
                    "reason": "repository_metadata_not_found",
                    "fast_lane_memberships": _combined_fast_lane_memberships(
                        component_rows
                    ),
                    "component_publications": _component_publications(
                        component_rows
                    ),
                    "duplicate_matches": sorted(
                        {requested_repository} & duplicate_repositories
                    ),
                }
            )
            continue
        canonical = _canonical_repository(project.get("repository"))
        if not canonical:
            raise InputError(f"invalid fetched repository identity for {requested_repository}")
        disposition, reason = _project_disposition(project)
        admitted = component_rows if disposition == "accepted" else []
        blocked = [] if disposition == "accepted" else component_rows
        scoped = [row for row in component_rows if row.get("stage1_5_resolution")]
        if disposition == "unresolved" and reason in SERVICE_GATE_REASONS and scoped:
            admitted = scoped
            blocked = [row for row in component_rows if row not in scoped]

        if blocked:
            for row in blocked:
                evidence_matrix_rows[row["component_id"]] = _evidence_matrix_row(
                    row,
                    disposition=(
                        "unresolved" if disposition == "unresolved" else "rejected"
                    ),
                    reason=reason,
                    repository_metadata=True,
                    repository=canonical,
                )
            item = {
                "repository": canonical,
                "requested_repository": requested_repository,
                "component_ids": sorted(row["component_id"] for row in blocked),
                "reason": reason,
                "project": _project_metadata(project, canonical),
                "fast_lane_memberships": _combined_fast_lane_memberships(
                    blocked
                ),
                "component_publications": _component_publications(blocked),
                "duplicate_matches": sorted(
                    {requested_repository, canonical} & duplicate_repositories
                ),
            }
            if disposition == "unresolved":
                unresolved.append(item)
            else:
                exclusions[reason] += len(blocked)

        if not admitted:
            continue
        for row in admitted:
            evidence_matrix_rows[row["component_id"]] = _evidence_matrix_row(
                row,
                disposition="resolved",
                reason=None,
                repository_metadata=True,
                repository=canonical,
            )
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
        result["components"].extend(admitted)

    if metadata_cache_path is not None and not metadata_cache_path.exists():
        _write_metadata_cache(metadata_cache_path, metadata_cache)

    output_projects = list(accepted_rows.values())
    for project in output_projects:
        project["repository_aliases"] = sorted(
            set(project["repository_aliases"]) | {project["repository"]}
        )
        project["components"].sort(
            key=lambda item: (
                item["earliest_manifested_publication"] or "",
                item["component_id"],
            )
        )
        project["fast_lane_memberships"] = _combined_fast_lane_memberships(
            project["components"]
        )
    output_projects.sort(
        key=lambda item: (
            min(
                (
                    membership["priority"]
                    for membership in item["fast_lane_memberships"]
                ),
                default=10**9,
            ),
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
    if metadata_cache_path:
        sources["github_metadata_cache"] = {
            "path": str(metadata_cache_path),
            "sha256": _sha256(metadata_cache_path),
        }
    if stage1_5_evidence_path:
        sources["stage1_5_evidence"] = {
            "path": str(stage1_5_evidence_path),
            "sha256": _sha256(stage1_5_evidence_path),
        }
    ordering = [
        "advisory source diversity",
        "stars (tie-breaker only)",
        "forks (tie-breaker only)",
        "repository",
    ]
    if fast_lane_mode:
        ordering.insert(0, "fast-lane priority")
    disposition_counts = Counter(
        row["disposition"] for row in evidence_matrix_rows.values()
    )
    return {
        "schema_version": 4,
        "method": "advisory_first_candidate_shortlist",
        "project_gates": {
            "maximum_inactivity_days": MAX_INACTIVITY_DAYS,
            "acceptable_oss_license_required": True,
            "deployable_service_signal_required": True,
        },
        "ordering": ordering,
        "selection": {
            "mode": "fast_lane" if fast_lane_mode else "full_corpus",
            "active_lanes": [
                {"priority": priority, "lane": lane, "source": source}
                for priority, lane, source in active_lanes
            ],
            "seeded_components": len(fast_lane_memberships),
            "coverage_components": len(active_roots - set(fast_lane_memberships)),
            "selected_components": len(candidate_roots),
        },
        "sources": sources,
        "summary": {
            "scanned_advisory_records": scanned,
            "withdrawn_advisory_records": withdrawn,
            "github_repositories_fetched": fetched,
            "candidate_projects": len(output_projects),
            "candidate_components": sum(len(item["components"]) for item in output_projects),
            "unresolved_candidates": len(unresolved),
            "review_entries": len(output_projects) + len(unresolved),
            "component_dispositions": {
                disposition: disposition_counts[disposition]
                for disposition in ("resolved", "unresolved", "rejected")
            },
            "exclusions": dict(sorted(exclusions.items())),
        },
        "evidence_matrix": {
            "asset_fields": list(EVIDENCE_ASSET_FIELDS),
            "asset_semantics": (
                "true means the asset is present in the manifested Stage 1 "
                "evidence; false does not prove it is absent upstream"
            ),
            "rows": [
                evidence_matrix_rows[component_id]
                for component_id in sorted(evidence_matrix_rows)
            ],
        },
        "unresolved_candidates": sorted(
            unresolved,
            key=lambda item: (
                min(
                    (
                        membership["priority"]
                        for membership in item.get("fast_lane_memberships", [])
                    ),
                    default=10**9,
                ),
                item.get("repository") or item.get("application_repository") or "",
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
        "--metadata-cache",
        type=Path,
        help=(
            "checkpoint completed GitHub lookups; defaults to "
            "<output-dir>/sources/github_repository_metadata.json"
        ),
    )
    parser.add_argument(
        "--stage1-5-evidence",
        type=Path,
        help="validated project facts and direct-repair corrections from Stage 1.5",
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    metadata_cache = args.metadata_cache or (
        args.output.parent / "sources" / "github_repository_metadata.json"
    )
    try:
        payload = generate(
            raw_dir=args.raw_dir,
            manifest_path=args.manifest,
            duplicate_inventory_path=args.duplicate_inventory,
            metadata_cache_path=metadata_cache,
            stage1_5_evidence_path=args.stage1_5_evidence,
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
