#!/usr/bin/env python3
"""Resolve OSV Git ranges into immutable pre-semantic overlap checkpoints."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from osv_history import parse_git_phases


HEX40 = re.compile(r"[0-9a-f]{40}")
UNSTABLE_TAG = re.compile(
    r"(?:^|[-_.])(?:alpha|beta|canary|dev|nightly|pre|preview|rc|snapshot)(?:[-_.\d]|$)",
    re.IGNORECASE,
)


class ResolutionError(ValueError):
    pass


def _report_name(repository: str) -> str:
    return "__".join(
        re.sub(r"[^A-Z0-9]+", "_", part.upper()).strip("_")
        for part in repository.split("/")
    )


def _git(repository: Path, *arguments: str, check: bool = True) -> subprocess.CompletedProcess:
    environment = {**os.environ, "GIT_NO_LAZY_FETCH": "1"}
    result = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        capture_output=True,
        text=True,
        env=environment,
        check=False,
    )
    if check and result.returncode:
        detail = result.stderr.strip() or result.stdout.strip()
        raise ResolutionError(f"git {' '.join(arguments)} failed: {detail}")
    return result


def clone_if_missing(repository: str, cache_dir: Path) -> tuple[Path, bool]:
    path = cache_dir / f"{repository.replace('/', '__')}.git"
    if path.exists():
        if _git(path, "rev-parse", "--is-bare-repository").stdout.strip() != "true":
            raise ResolutionError(f"not a bare Git repository: {path}")
        return path, False
    cache_dir.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(
        [
            "git",
            "clone",
            "--bare",
            "--filter=tree:0",
            f"https://github.com/{repository}.git",
            str(path),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode:
        raise ResolutionError(
            f"git clone failed for {repository}: {result.stderr.strip()}"
        )
    return path, True


def refresh_repository(repository_path: Path) -> str:
    result = subprocess.run(
        [
            "git",
            "-C",
            str(repository_path),
            "fetch",
            "--prune",
            "--filter=tree:0",
            "origin",
            "+HEAD:refs/cyber-arena/upstream-head",
            "+refs/heads/*:refs/heads/*",
            "+refs/tags/*:refs/tags/*",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode:
        raise ResolutionError(
            f"git fetch failed for {repository_path}: {result.stderr.strip()}"
        )
    return "refs/cyber-arena/upstream-head"


def fetch_missing_boundaries(project: dict, repository_path: Path) -> list[str]:
    failures = []
    commits = {
        str(value).lower()
        for component in project["components"]
        for affected_range in component.get("project_git_ranges", [])
        for event in affected_range.get("events", [])
        for value in event.values()
        if str(value) != "0" and HEX40.fullmatch(str(value).lower())
    }
    for commit in sorted(commits):
        if _has_commit(repository_path, commit):
            continue
        result = subprocess.run(
            [
                "git",
                "-C",
                str(repository_path),
                "fetch",
                "--filter=tree:0",
                "origin",
                commit,
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode or not _has_commit(repository_path, commit):
            failures.append(commit)
    return failures


def _has_commit(repository: Path, commit: str) -> bool:
    result = _git(repository, "cat-file", "-t", commit, check=False)
    return result.returncode == 0 and result.stdout.strip() == "commit"


def _is_ancestor(repository: Path, ancestor: str, descendant: str) -> bool:
    result = _git(
        repository,
        "merge-base",
        "--is-ancestor",
        ancestor,
        descendant,
        check=False,
    )
    if result.returncode not in {0, 1}:
        raise ResolutionError(result.stderr.strip() or "git ancestry check failed")
    return result.returncode == 0


def _commit_info(repository: Path, commit: str) -> dict:
    payload = _git(repository, "cat-file", "-p", commit).stdout
    parents = []
    committed_at = None
    for line in payload.splitlines():
        if not line:
            break
        if line.startswith("parent "):
            parents.append(line.split()[1])
        if line.startswith("committer "):
            match = re.search(r" (\d+) [+-]\d{4}$", line)
            if match:
                committed_at = datetime.fromtimestamp(
                    int(match.group(1)), tz=timezone.utc
                ).isoformat()
    return {"commit": commit, "parents": parents, "committed_at": committed_at}


def _range_affected(phases: list[dict], checkpoint: str, is_ancestor) -> bool:
    for phase in phases:
        introduced = any(
            value == "0" or is_ancestor(value, checkpoint)
            for value in phase["introduced"]
        )
        if not introduced:
            continue
        if any(is_ancestor(value, checkpoint) for value in phase["fixed"]):
            continue
        if phase["last_affected"] and not any(
            is_ancestor(checkpoint, value) for value in phase["last_affected"]
        ):
            continue
        return True
    return False


def _ancestry_extreme(commits: list[str], is_ancestor, *, earliest: bool) -> str | None:
    for candidate in commits:
        if all(
            is_ancestor(candidate, other)
            if earliest
            else is_ancestor(other, candidate)
            for other in commits
        ):
            return candidate
    return None


def _stable_tags_at(repository: Path, commit: str) -> list[str]:
    tags = _git(repository, "tag", "--points-at", commit).stdout.splitlines()
    return sorted(
        tag.strip()
        for tag in tags
        if tag.strip()
        and any(character.isdigit() for character in tag)
        and not UNSTABLE_TAG.search(tag)
    )


def _partition_lineages(checkpoints: list[dict], is_ancestor) -> list[list[dict]]:
    """Partition equal-state checkpoints into deterministic ancestry chains."""
    chains: list[list[dict]] = []
    for checkpoint in sorted(
        checkpoints, key=lambda item: (item["committed_at"] or "", item["commit"])
    ):
        for chain in chains:
            if all(
                is_ancestor(checkpoint["commit"], other["commit"])
                or is_ancestor(other["commit"], checkpoint["commit"])
                for other in chain
            ):
                chain.append(checkpoint)
                break
        else:
            chains.append([checkpoint])
    return chains


def _representative(checkpoints: list[dict]) -> dict:
    return max(
        checkpoints,
        key=lambda item: (
            bool(item["stable_release_tags"]),
            item["on_head_lineage"],
            item["committed_at"] or "",
            item["commit"],
        ),
    )


def _component_has_behavioral_evidence(component: dict) -> bool:
    return bool(
        component.get("behavioral_evidence")
        or component.get("summaries")
        or component.get("details")
        or any(
            reference.get("type") == "EVIDENCE"
            for reference in component.get("references", [])
        )
    )


def _window_inventory(checkpoints: list[dict], components: list[dict], is_ancestor) -> list[dict]:
    component_index = {item["component_id"]: item for item in components}
    grouped: dict[tuple[str, ...], list[dict]] = defaultdict(list)
    for checkpoint in checkpoints:
        if checkpoint["reported_affected"]:
            grouped[tuple(checkpoint["reported_affected"])].append(checkpoint)

    windows = []
    for component_ids, same_state in sorted(grouped.items()):
        for chain in _partition_lineages(same_state, is_ancestor):
            representative = _representative(chain)
            selected_components = [component_index[value] for value in component_ids]
            affected_units = sorted(
                {
                    unit
                    for component in selected_components
                    for unit in component.get("affected_units", [])
                }
            )
            cwes = sorted(
                {
                    cwe
                    for component in selected_components
                    for cwe in component.get("cwes", [])
                }
            )
            fix_boundaries = sorted(
                {
                    boundary
                    for component in selected_components
                    for boundary in component.get("verified_fix_boundaries", [])
                }
            )
            evidence_complete = sum(
                _component_has_behavioral_evidence(component)
                and bool(component.get("verified_fix_boundaries"))
                for component in selected_components
            )
            windows.append(
                {
                    "component_ids": list(component_ids),
                    "checkpoints": chain,
                    "representative_checkpoint": representative["commit"],
                    "earliest_by_ancestry": _ancestry_extreme(
                        [item["commit"] for item in chain], is_ancestor, earliest=True
                    ),
                    "newest_by_ancestry": _ancestry_extreme(
                        [item["commit"] for item in chain], is_ancestor, earliest=False
                    ),
                    "signals": {
                        "reported_overlap_count": len(component_ids),
                        "evidence_complete_component_count": evidence_complete,
                        "affected_unit_count": len(affected_units),
                        "fix_boundary_count": len(fix_boundaries),
                        "vulnerability_class_count": len(cwes),
                        "introduced_from_origin_component_count": sum(
                            bool(component.get("introduced_from_origin"))
                            for component in selected_components
                        ),
                        "stable_release_checkpoint": bool(
                            representative["stable_release_tags"]
                        ),
                        "on_head_lineage": representative["on_head_lineage"],
                        "committed_at": representative["committed_at"],
                    },
                    "affected_units": affected_units,
                    "cwes": cwes,
                    "fix_boundaries": fix_boundaries,
                    "ready_for_semantic_review": evidence_complete == len(component_ids),
                }
            )

    windows.sort(
        key=lambda item: (
            item["signals"]["committed_at"] or "",
            item["representative_checkpoint"],
        )
    )
    for index, window in enumerate(windows, start=1):
        window["inventory_id"] = f"H{index}"
    return windows


def _select_windows(windows: list[dict], limit: int = 5) -> list[dict]:
    available = [item for item in windows if item["ready_for_semantic_review"]]
    selected = []
    while available and len(selected) < limit:
        if not selected:
            chosen = max(
                available,
                key=lambda item: (
                    item["signals"]["reported_overlap_count"],
                    item["signals"]["evidence_complete_component_count"],
                    item["signals"]["stable_release_checkpoint"],
                    item["signals"]["on_head_lineage"],
                    item["signals"]["committed_at"] or "",
                    item["representative_checkpoint"],
                ),
            )
            reason = "widest_reported_overlap"
            distance = None
        else:
            selected_sets = [set(item["component_ids"]) for item in selected]

            def priority(item: dict) -> tuple:
                current = set(item["component_ids"])
                distance = min(len(current.symmetric_difference(other)) for other in selected_sets)
                new_components = len(current - set().union(*selected_sets))
                signals = item["signals"]
                return (
                    signals["reported_overlap_count"] >= 2,
                    new_components,
                    distance,
                    signals["reported_overlap_count"],
                    signals["stable_release_checkpoint"],
                    signals["on_head_lineage"],
                    signals["committed_at"] or "",
                    item["representative_checkpoint"],
                )

            chosen = max(available, key=priority)
            chosen_set = set(chosen["component_ids"])
            distance = min(
                len(chosen_set.symmetric_difference(set(item["component_ids"])))
                for item in selected
            )
            reason = "marginal_component_set_diversity"
        available.remove(chosen)
        selected.append(
            {
                **chosen,
                "window_id": f"W{len(selected) + 1}",
                "selection_reason": reason,
                "marginal_component_distance": distance,
            }
        )
    return selected


def resolve_project(
    project: dict,
    repository_path: Path,
    *,
    head_ref: str = "HEAD",
    head_source: str = "repository_head",
) -> dict:
    head = _git(repository_path, "rev-parse", head_ref).stdout.strip()
    commit_cache: dict[str, dict] = {}
    ancestry_cache: dict[tuple[str, str], bool] = {}
    verified_boundary_index: dict[str, dict] = {}

    def commit_info(commit: str) -> dict:
        if commit not in commit_cache:
            commit_cache[commit] = _commit_info(repository_path, commit)
        return commit_cache[commit]

    def is_ancestor(ancestor: str, descendant: str) -> bool:
        key = (ancestor, descendant)
        if key not in ancestry_cache:
            ancestry_cache[key] = _is_ancestor(
                repository_path, ancestor, descendant
            )
        return ancestry_cache[key]

    resolved_components = []
    excluded_components = []
    checkpoint_sources: dict[str, list[dict]] = defaultdict(list)
    for component in project["components"]:
        range_reasons = []
        parsed_ranges = []
        component_sources: dict[str, list[dict]] = defaultdict(list)
        fixed_boundaries = set()
        for affected_range in component.get("project_git_ranges", []):
            phases, range_blockers = parse_git_phases(affected_range.get("events", []))
            range_reasons.extend(range_blockers)
            for phase in phases:
                if not phase["fixed"]:
                    range_reasons.append("phase_without_fix_boundary")
                for introduced in phase["introduced"]:
                    if introduced == "0":
                        continue
                    if not _has_commit(repository_path, introduced):
                        range_reasons.append(f"missing_commit:{introduced}")
                for fixed in phase["fixed"]:
                    fixed_boundaries.add(fixed)
                    if not _has_commit(repository_path, fixed):
                        range_reasons.append(f"missing_commit:{fixed}")
                        continue
                    parents = commit_info(fixed)["parents"]
                    if not parents:
                        range_reasons.append(f"fixed_commit_without_parent:{fixed}")
                    else:
                        verified_boundary_index[fixed] = commit_info(fixed)
                    for index, parent in enumerate(parents):
                        component_sources[parent].append(
                            {
                                "type": "pre_fixed",
                                "component_id": component["component_id"],
                                "fixed": fixed,
                                "parent_index": index,
                            }
                        )
                for last_affected in phase["last_affected"]:
                    if not _has_commit(repository_path, last_affected):
                        range_reasons.append(f"missing_commit:{last_affected}")
                introduced_commits = [
                    value
                    for value in phase["introduced"]
                    if value != "0" and _has_commit(repository_path, value)
                ]
                fixed_commits = [
                    value
                    for value in phase["fixed"]
                    if _has_commit(repository_path, value)
                ]
                if introduced_commits and fixed_commits and not all(
                    any(is_ancestor(introduced, fixed) for fixed in fixed_commits)
                    for introduced in introduced_commits
                ):
                    range_reasons.append("introduction_not_ancestor_of_fix")
            parsed_ranges.append({**affected_range, "phases": phases})
        if not parsed_ranges:
            range_reasons.append("no_project_git_range")

        if range_reasons:
            status = "rejected"
            reason = "unresolved_project_git_range"
        elif not fixed_boundaries:
            status = "rejected"
            reason = "no_project_git_fix_boundary"
        else:
            status = "accepted"
            reason = None

        enriched = {
            **component,
            "parsed_git_ranges": parsed_ranges,
            "verified_fix_boundaries": sorted(fixed_boundaries),
            "programmatic_status": status,
            "programmatic_reason": reason,
            "programmatic_details": sorted(set(range_reasons)),
            "introduced_from_origin": any(
                "0" in phase["introduced"]
                for item in parsed_ranges
                for phase in item["phases"]
            ),
        }
        if status == "accepted":
            resolved_components.append(enriched)
            for commit, sources in component_sources.items():
                checkpoint_sources[commit].extend(sources)
        else:
            excluded_components.append(enriched)

    checkpoints = []
    for commit, sources in checkpoint_sources.items():
        if not _has_commit(repository_path, commit):
            continue
        affected = []
        for component in resolved_components:
            if any(
                _range_affected(item["phases"], commit, is_ancestor)
                for item in component["parsed_git_ranges"]
            ):
                affected.append(component["component_id"])
        info = commit_info(commit)
        checkpoints.append(
            {
                **info,
                "on_head_lineage": is_ancestor(commit, head),
                "stable_release_tags": _stable_tags_at(repository_path, commit),
                "sources": sorted(sources, key=lambda item: json.dumps(item, sort_keys=True)),
                "reported_affected": sorted(affected),
                "reported_affected_count": len(affected),
            }
        )
    checkpoints.sort(key=lambda item: (item["committed_at"] or "", item["commit"]))

    head_affected = sorted(
        component["component_id"]
        for component in resolved_components
        if any(
            _range_affected(item["phases"], head, is_ancestor)
            for item in component["parsed_git_ranges"]
        )
    )
    head_reference = {
        **commit_info(head),
        "source": head_source,
        "known_applicable_component_ids": head_affected,
        "snapshot_limited_no_known_applicable_issue": not head_affected,
    }

    window_inventory = _window_inventory(checkpoints, resolved_components, is_ancestor)
    candidate_windows = _select_windows(window_inventory)

    maximum = max((item["reported_affected_count"] for item in checkpoints), default=0)

    origin_component_count = sum(
        item["introduced_from_origin"] for item in resolved_components
    )
    return {
        "schema_version": 3,
        "repository": project["repository"],
        "repository_aliases": project.get(
            "repository_aliases", [project["repository"]]
        ),
        "method": "osv_git_event_ancestry",
        "project": project.get("project", {}),
        "duplicate_matches": project.get("duplicate_matches", []),
        "source_provenance": project.get("source_provenance", {}),
        "head_commit": head,
        "head_reference": head_reference,
        "input_component_count": len(project["components"]),
        "component_count": len(resolved_components),
        "rejected_component_count": sum(
            item["programmatic_status"] == "rejected"
            for item in excluded_components
        ),
        "introduced_from_origin_component_count": origin_component_count,
        "candidate_checkpoint_count": len(checkpoints),
        "window_inventory_count": len(window_inventory),
        "candidate_window_count": len(candidate_windows),
        "maximum_reported_overlap": maximum,
        "window_selection_method": {
            "name": "widest_then_greedy_marginal_component_diversity",
            "limit": 5,
            "authoritative_score": False,
        },
        "candidate_windows": candidate_windows,
        "window_inventory": window_inventory,
        "checkpoints": checkpoints,
        "components": resolved_components,
        "excluded_components": excluded_components,
        "fix_boundaries": [
            verified_boundary_index[key] for key in sorted(verified_boundary_index)
        ],
    }


def _short(values: list[str], limit: int = 6) -> str:
    if not values:
        return "—"
    suffix = f" (+{len(values) - limit})" if len(values) > limit else ""
    return ", ".join(f"`{value}`" for value in values[:limit]) + suffix


def _packet_window(window: dict) -> dict:
    checkpoint = next(
        item
        for item in window["checkpoints"]
        if item["commit"] == window["representative_checkpoint"]
    )
    return {
        key: window[key]
        for key in (
            "window_id",
            "inventory_id",
            "component_ids",
            "representative_checkpoint",
            "signals",
            "affected_units",
            "cwes",
            "fix_boundaries",
            "selection_reason",
            "marginal_component_distance",
            "ready_for_semantic_review",
        )
    } | {
        "checkpoint_evidence": {
            key: checkpoint[key]
            for key in (
                "commit",
                "committed_at",
                "on_head_lineage",
                "stable_release_tags",
                "sources",
            )
        }
    }


def _packet_component(component: dict) -> dict:
    detail_excerpts = []
    for detail in component.get("details", [])[:3]:
        text = str(detail)
        detail_excerpts.append(
            {
                "text": text[:4000],
                "truncated": len(text) > 4000,
                "original_characters": len(text),
            }
        )
    fields = (
        "component_id",
        "ids",
        "earliest_manifested_publication",
        "summaries",
        "packages",
        "references",
        "severities",
        "source_databases",
        "cwes",
        "fixes",
        "behavioral_evidence",
        "repair_evidence",
        "application_repository",
        "application_mapping",
        "application_git_ranges",
        "duplicate_matches",
        "affected_units",
        "project_git_ranges",
        "verified_fix_boundaries",
        "introduced_from_origin",
    )
    return {key: component.get(key) for key in fields} | {
        "detail_excerpts": detail_excerpts,
        "full_evidence_sources": component.get("sources", []),
    }


def _markdown(result: dict) -> str:
    lines = [
        f"# {result['repository']} commit-resolved candidate windows",
        "",
        "> Maintainer-only pre-semantic report. States are OSV claims evaluated on the upstream Git graph, not reproduced vulnerabilities.",
        "",
        f"- Input components: {result['input_component_count']}",
        f"- Accepted components: {result['component_count']}",
        f"- Rejected components: {result['rejected_component_count']}",
        f"- Components whose OSV range begins at repository origin: {result['introduced_from_origin_component_count']}",
        f"- Fix-boundary checkpoints evaluated: {result['candidate_checkpoint_count']}",
        f"- Distinct historical windows: {result['window_inventory_count']}",
        f"- Windows retained for semantic review: {result['candidate_window_count']}",
        f"- Maximum reported overlap: {result['maximum_reported_overlap']}",
        f"- Upstream HEAD observed: `{result['head_commit']}`",
        f"- HEAD has no known applicable retained component: `{str(result['head_reference']['snapshot_limited_no_known_applicable_issue']).lower()}`",
        "",
        "## Candidate windows",
        "",
        "| Window | Checkpoint | Reported advisories | Stable tag | Selection reason |",
        "| --- | --- | ---: | --- | --- |",
    ]
    for window in result["candidate_windows"]:
        checkpoint = next(
            item
            for item in window["checkpoints"]
            if item["commit"] == window["representative_checkpoint"]
        )
        lines.append(
            f"| {window['window_id']} | `{window['representative_checkpoint']}` | "
            f"{len(window['component_ids'])} | {_short(checkpoint['stable_release_tags'])} | "
            f"`{window['selection_reason']}` |"
        )
        lines.append("")
        lines.append(
            f"{window['window_id']} reported advisories: {_short(window['component_ids'], 20)}"
        )

    lines.extend(["", "## Historical window chronology", ""])
    for window in result["window_inventory"]:
        lines.append(
            f"- {window['inventory_id']}: `{window['representative_checkpoint']}` "
            f"({window['signals']['committed_at'] or 'unknown time'}), "
            f"{window['signals']['reported_overlap_count']} reported advisories."
        )
    if not result["window_inventory"]:
        lines.append("- None.")

    lines.extend(["", "## Programmatic exclusions", ""])
    if result["excluded_components"]:
        lines.extend(
            f"- `{item['component_id']}` — `{item['programmatic_status']}`: "
            f"`{item['programmatic_reason']}`."
            for item in result["excluded_components"]
        )
    else:
        lines.append("- None.")
    lines.extend(
        [
            "",
            "## Stop boundary",
            "",
            "These windows are ready for budgeted semantic review only. No application-fit, reachability, scope, PoC, build, exploit, attack-depth, or defense-depth judgment has been performed.",
            "",
        ]
    )
    return "\n".join(lines)


def write_outputs(results: list[dict], output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    packet_dir = output_dir / "semantic_packets"
    packet_dir.mkdir(exist_ok=True)
    rows = []
    for result in results:
        name = _report_name(result["repository"])
        result_path = output_dir / f"{name}.json"
        result_path.write_text(
            json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        (output_dir / f"{name}.md").write_text(_markdown(result), encoding="utf-8")
        selected_component_ids = {
            component_id
            for window in result["candidate_windows"]
            for component_id in window["component_ids"]
        }
        packet = {
            "schema_version": 2,
            "repository": result["repository"],
            "repository_aliases": result["repository_aliases"],
            "project": result["project"],
            "duplicate_matches": result["duplicate_matches"],
            "source_provenance": result["source_provenance"],
            "source_result": {
                "path": result_path.name,
                "sha256": hashlib.sha256(result_path.read_bytes()).hexdigest(),
            },
            "source_method": result["method"],
            "head_reference": result["head_reference"],
            "semantic_review_performed": False,
            "ready_for_semantic_review": bool(result["candidate_windows"]),
            "window_selection_method": result["window_selection_method"],
            "candidate_windows": [
                _packet_window(window) for window in result["candidate_windows"]
            ],
            "components": [
                _packet_component(component)
                for component in result["components"]
                if component["component_id"] in selected_component_ids
            ],
            "programmatic_exclusions": result["excluded_components"],
            "claim_boundary": (
                "Reported affected ranges and immutable fix-boundary checkpoints only; "
                "application fit, feature reachability, candidate scopes, and exploitability "
                "remain semantic or dynamic checks."
            ),
        }
        (packet_dir / f"{name}.json").write_text(
            json.dumps(packet, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        rows.append(
            f"| [{result['repository']}]({name}.md) | {result['input_component_count']} | "
            f"{result['component_count']} | {result['rejected_component_count']} | "
            f"{result['introduced_from_origin_component_count']} | {result['maximum_reported_overlap']} | "
            f"{result['window_inventory_count']} | {result['candidate_window_count']} | "
            f"{str(result['head_reference']['snapshot_limited_no_known_applicable_issue']).lower()} |"
        )
    index = [
        "# Commit-resolved pre-semantic overlap index",
        "",
        "> OSV Git ranges evaluated against immutable upstream commits. No semantic filtering has run.",
        "",
        "| Project | Input | Accepted | Rejected | Origin-introduced | Maximum | Historical windows | Semantic-ready windows | HEAD clean in corpus |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |",
        *rows,
        "",
    ]
    (output_dir / "INDEX.md").write_text("\n".join(index), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--overlap-dir", type=Path, required=True)
    parser.add_argument("--repo-cache", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument(
        "--offline-cache",
        action="store_true",
        help="use cached refs without refreshing; HEAD freshness will be unverified",
    )
    args = parser.parse_args()
    try:
        projects = [
            json.loads(path.read_text(encoding="utf-8"))
            for path in sorted(args.overlap_dir.glob("*.json"))
        ]
        results = []
        for project in projects:
            print(f"resolving {project['repository']}", flush=True)
            repository_path, created = clone_if_missing(
                project["repository"], args.repo_cache
            )
            if args.offline_cache:
                head_ref = "HEAD"
                head_source = "cached_repository_head_unverified"
            elif created:
                head_ref = "HEAD"
                head_source = "fresh_clone_default_branch"
            else:
                head_ref = refresh_repository(repository_path)
                head_source = "refreshed_upstream_default_branch"
            failed_fetches = fetch_missing_boundaries(project, repository_path)
            if failed_fetches:
                print(
                    f"  unavailable boundary commits: {', '.join(failed_fetches)}",
                    flush=True,
                )
            results.append(
                resolve_project(
                    project,
                    repository_path,
                    head_ref=head_ref,
                    head_source=head_source,
                )
            )
        write_outputs(results, args.output_dir)
    except (OSError, ResolutionError, KeyError, json.JSONDecodeError) as error:
        parser.error(str(error))
    print(f"wrote commit-resolved windows for {len(results)} projects")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
