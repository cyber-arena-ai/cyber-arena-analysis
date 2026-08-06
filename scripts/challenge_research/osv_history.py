"""Lossless project-level OSV history extraction and overlap analysis."""

from __future__ import annotations

import json
import zipfile
from collections import defaultdict
from pathlib import Path

try:
    from ._lib import canonical_github_repo, strong_reference_repository
except ImportError:  # direct execution
    from _lib import canonical_github_repo, strong_reference_repository


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


def record_packages(record: dict) -> set[str]:
    return {
        key
        for affected in record.get("affected", [])
        for key in affected_keys(affected)[0]
    }


def record_repositories(record: dict) -> set[str]:
    repositories = {
        repository
        for affected in record.get("affected", [])
        for item in affected.get("ranges", [])
        if item.get("type") == "GIT"
        if (repository := canonical_github_repo(item.get("repo")))
    }
    for reference in record.get("references", []):
        repository = strong_reference_repository(reference)
        if repository:
            repositories.add(repository)
    return repositories


def iter_raw_records(raw_dir: Path):
    for archive_path in sorted(raw_dir.glob("*.zip")):
        with zipfile.ZipFile(archive_path) as archive:
            for member in archive.infolist():
                if member.is_dir() or not member.filename.endswith(".json"):
                    continue
                with archive.open(member) as stream:
                    yield {
                        "source_archive": archive_path.name,
                        "source_member": member.filename,
                        "record": json.load(stream),
                    }


def select_project_records(
    raw_dir: Path,
    repository: str,
    requested_packages: set[str] | None = None,
) -> tuple[list[dict], set[str], dict]:
    """Select repository records, then recover package-only aliases in a second pass."""
    repository = repository.lower()
    requested_packages = set(requested_packages or ())
    selected: dict[tuple[str, str], dict] = {}
    inferred_packages: set[str] = set()
    scanned = 0

    for wrapped in iter_raw_records(raw_dir):
        scanned += 1
        record = wrapped["record"]
        if record.get("withdrawn"):
            continue
        packages = record_packages(record)
        repository_match = repository in record_repositories(record)
        package_match = bool(requested_packages & packages)
        if repository_match or package_match:
            key = (wrapped["source_archive"], wrapped["source_member"])
            selected[key] = wrapped
        if repository_match:
            inferred_packages.update(packages)

    packages = requested_packages or inferred_packages
    if not requested_packages and packages:
        for wrapped in iter_raw_records(raw_dir):
            record = wrapped["record"]
            if record.get("withdrawn") or not packages & record_packages(record):
                continue
            key = (wrapped["source_archive"], wrapped["source_member"])
            selected[key] = wrapped

    return (
        sorted(
            selected.values(),
            key=lambda item: (
                item["record"].get("id", ""),
                item["source_archive"],
                item["source_member"],
            ),
        ),
        packages,
        {
            "scanned_record_count": scanned,
            "selected_record_count": len(selected),
            "selection_lanes": [
                "affected Git range or strong repository reference",
                "exact affected package identity",
            ],
        },
    )


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
