#!/usr/bin/env python3
"""Resolve independent repair-parent candidates for semantic review."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from osv_history import parse_git_phases


HEX40 = re.compile(r"[0-9a-f]{40}")


class ResolutionError(ValueError):
    pass


def _report_name(repository: str) -> str:
    return "__".join(
        re.sub(r"[^A-Z0-9]+", "_", part.upper()).strip("_")
        for part in repository.split("/")
    )


def _git(repository: Path, *arguments: str, check: bool = True) -> subprocess.CompletedProcess:
    result = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        capture_output=True,
        text=True,
        env={**os.environ, "GIT_NO_LAZY_FETCH": "1"},
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


def refresh_repository(repository_path: Path) -> None:
    result = subprocess.run(
        [
            "git",
            "-C",
            str(repository_path),
            "fetch",
            "--prune",
            "--filter=tree:0",
            "origin",
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


def _has_commit(repository: Path, commit: str) -> bool:
    result = _git(repository, "cat-file", "-t", commit, check=False)
    return result.returncode == 0 and result.stdout.strip() == "commit"


def fetch_missing_boundaries(project: dict, repository_path: Path) -> list[str]:
    commits = {
        str(claim.get("sha", "")).lower()
        for component in project["components"]
        for claim in component.get("repair_claims", [])
        if HEX40.fullmatch(str(claim.get("sha", "")).lower())
    }
    commits.update(
        str(value).lower()
        for component in project["components"]
        for claim in component.get("range_claims", [])
        for event in claim.get("events", [])
        for value in event.values()
        if str(value) != "0" and HEX40.fullmatch(str(value).lower())
    )
    failures = []
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


def _commit_info(repository: Path, commit: str) -> dict:
    payload = _git(repository, "cat-file", "-p", commit).stdout
    parents = []
    committed_at = None
    for line in payload.splitlines():
        if not line:
            break
        if line.startswith("parent "):
            parents.append(line.split()[1])
        elif line.startswith("committer "):
            match = re.search(r" (\d+) [+-]\d{4}$", line)
            if match:
                committed_at = datetime.fromtimestamp(
                    int(match.group(1)), tz=timezone.utc
                ).isoformat()
    return {"commit": commit, "parents": parents, "committed_at": committed_at}


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


def _source_key(claim: dict) -> tuple[str, str]:
    provenance = claim.get("provenance", {})
    return str(provenance.get("archive", "")), str(provenance.get("member", ""))


def _fixed_boundaries(claim: dict) -> set[str]:
    return {
        str(event["fixed"]).lower()
        for event in claim.get("events", [])
        if "fixed" in event
    }


def _validate_range_claim(claim: dict, repository: Path) -> tuple[dict, list[str]]:
    phases, blockers = parse_git_phases(claim.get("events", []))
    reasons = list(claim.get("blockers", [])) + blockers
    for phase in phases:
        if not phase["fixed"]:
            reasons.append("phase_without_fix_boundary")
        introduced = [value for value in phase["introduced"] if value != "0"]
        boundaries = [*introduced, *phase["fixed"], *phase["last_affected"]]
        for commit in boundaries:
            if not _has_commit(repository, commit):
                reasons.append(f"missing_commit:{commit}")
        present_introduced = [
            value for value in introduced if _has_commit(repository, value)
        ]
        present_fixed = [
            value for value in phase["fixed"] if _has_commit(repository, value)
        ]
        if present_introduced and present_fixed:
            every_introduction_reaches_a_fix = all(
                any(_is_ancestor(repository, start, fixed) for fixed in present_fixed)
                for start in present_introduced
            )
            every_fix_follows_an_introduction = all(
                any(
                    _is_ancestor(repository, start, fixed)
                    for start in present_introduced
                )
                for fixed in present_fixed
            )
            if not (
                every_introduction_reaches_a_fix
                and every_fix_follows_an_introduction
            ):
                reasons.append("introduction_not_ancestor_of_fix")
    return {**claim, "phases": phases}, sorted(set(reasons))


def _component_candidates(component: dict, repository: Path) -> tuple[dict, list[dict]]:
    valid_ranges = []
    invalid_ranges = []
    for claim in component.get("range_claims", []):
        parsed, reasons = _validate_range_claim(claim, repository)
        if reasons:
            invalid_ranges.append({**parsed, "programmatic_details": reasons})
        else:
            valid_ranges.append(parsed)

    expected_parents = {
        item["sha"]: item["affected_parent"]
        for item in component.get("stage1_5_resolution", {})
        .get("repair", {})
        .get("commits", [])
    }
    repairs_by_commit: dict[str, list[dict]] = {}
    invalid_repairs = []
    for claim in component.get("repair_claims", []):
        commit = str(claim.get("sha", "")).lower()
        reasons = []
        if not HEX40.fullmatch(commit) or not _has_commit(repository, commit):
            reasons.append(f"missing_commit:{commit}")
        else:
            info = _commit_info(repository, commit)
            if len(info["parents"]) != 1:
                reasons.append(f"repair_requires_single_parent:{commit}")
            expected = expected_parents.get(commit)
            if len(info["parents"]) == 1 and expected is not None and info[
                "parents"
            ] != [expected]:
                reasons.append(f"affected_parent_mismatch:{commit}")
        if reasons:
            invalid_repairs.append({**claim, "programmatic_details": reasons})
        else:
            repairs_by_commit.setdefault(commit, []).append(claim)

    candidates = []
    for commit, repair_claims in sorted(repairs_by_commit.items()):
        repair_sources = {_source_key(item) for item in repair_claims}
        same_source = {
            claim["claim_id"]
            for claim in valid_ranges
            if _source_key(claim) in repair_sources
        }
        same_boundary = {
            claim["claim_id"]
            for claim in valid_ranges
            if commit in _fixed_boundaries(claim)
        }
        fallback_ids = sorted(same_source | same_boundary)
        if not fallback_ids:
            fallback_ids = sorted(claim["claim_id"] for claim in valid_ranges)
        info = _commit_info(repository, commit)
        candidates.append(
            {
                "candidate_id": f"{component['component_id']}@{commit}",
                "component_id": component["component_id"],
                "repair_commit": commit,
                "primary_commit": info["parents"][0],
                "repair_committed_at": info["committed_at"],
                "repair_claim_ids": sorted(
                    claim["claim_id"] for claim in repair_claims
                ),
                "repair_claim_sources": sorted(
                    {claim["source"] for claim in repair_claims}
                ),
                "fallback_range_claim_ids": fallback_ids,
                "ready_for_semantic_review": bool(fallback_ids),
            }
        )

    enriched = {
        **component,
        "repair_claims": sorted(
            (
                claim
                for claims in repairs_by_commit.values()
                for claim in claims
            ),
            key=lambda item: item["claim_id"],
        ),
        "range_claims": valid_ranges,
        "invalid_range_claims": invalid_ranges,
        "invalid_repair_claims": invalid_repairs,
        "revision_candidates": candidates,
    }
    return enriched, candidates


def resolve_project(project: dict, repository_path: Path) -> dict:
    components = []
    excluded = []
    candidates = []
    for component in project["components"]:
        enriched, component_candidates = _component_candidates(
            component, repository_path
        )
        ready = [item for item in component_candidates if item["ready_for_semantic_review"]]
        if ready:
            components.append(enriched)
            candidates.extend(ready)
        else:
            reason = (
                "no_valid_affected_range_claim"
                if not enriched["range_claims"]
                else "no_single_parent_repair_candidate"
            )
            excluded.append({**enriched, "programmatic_reason": reason})

    source_priority = {
        "stage1_5_direct_repair": 0,
        "reference_fix": 1,
        "osv_git_fixed": 2,
    }
    candidates.sort(
        key=lambda item: (
            min(
                source_priority.get(source, 3)
                for source in item["repair_claim_sources"]
            ),
            item["repair_committed_at"] or "",
            item["component_id"],
            item["repair_commit"],
        )
    )
    return {
        "schema_version": 1,
        "repository": project["repository"],
        "repository_aliases": project.get(
            "repository_aliases", [project["repository"]]
        ),
        "method": "independent_repair_parent_candidates",
        "project": project.get("project", {}),
        "duplicate_matches": project.get("duplicate_matches", []),
        "source_provenance": project.get("source_provenance", {}),
        "input_component_count": len(project["components"]),
        "component_count": len(components),
        "excluded_component_count": len(excluded),
        "revision_candidate_count": len(candidates),
        "revision_candidates": candidates,
        "components": components,
        "excluded_components": excluded,
    }


def _detail_excerpts(component: dict) -> list[dict]:
    excerpts = []
    for detail in component.get("details", [])[:3]:
        text = str(detail)
        excerpts.append(
            {
                "text": text[:4000],
                "truncated": len(text) > 4000,
                "original_characters": len(text),
            }
        )
    return excerpts


def _packet_component(component: dict) -> dict:
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
        "behavioral_evidence",
        "repair_evidence",
        "application_repository",
        "application_mapping",
        "duplicate_matches",
        "repair_claims",
        "range_claims",
        "invalid_repair_claims",
        "invalid_range_claims",
    )
    packet = {key: component.get(key) for key in fields}
    packet["detail_excerpts"] = _detail_excerpts(component)
    packet["full_evidence_sources"] = component.get("sources", [])
    if "stage1_5_resolution" in component:
        packet["stage1_5_resolution"] = component["stage1_5_resolution"]
    return packet


def _markdown(result: dict) -> str:
    lines = [
        f"# {result['repository']} revision candidates",
        "",
        "> Maintainer-only. Each candidate is the sole parent of one claimed repair; vulnerability reproduction remains unproven.",
        "",
        f"- Input vulnerabilities: {result['input_component_count']}",
        f"- Candidate-bearing vulnerabilities: {result['component_count']}",
        f"- Excluded vulnerabilities: {result['excluded_component_count']}",
        f"- Independent revision candidates: {result['revision_candidate_count']}",
        "",
        "| Candidate | Primary commit | Repair commit | Fallback range claims |",
        "| --- | --- | --- | ---: |",
    ]
    lines.extend(
        f"| `{item['candidate_id']}` | `{item['primary_commit']}` | "
        f"`{item['repair_commit']}` | {len(item['fallback_range_claim_ids'])} |"
        for item in result["revision_candidates"]
    )
    if not result["revision_candidates"]:
        lines.append("| — | — | — | 0 |")
    lines.extend(
        [
            "",
            "Affected ranges are fallback search bounds only. Stage 2 does not merge them or assert that every commit in a range is vulnerable.",
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
        packet = {
            "schema_version": 3,
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
            "semantic_review_performed": False,
            "ready_for_semantic_review": bool(result["revision_candidates"]),
            "revision_candidates": result["revision_candidates"],
            "components": [
                _packet_component(component) for component in result["components"]
            ],
            "programmatic_exclusions": result["excluded_components"],
            "claim_boundary": (
                "Repair parents are trial commits and affected ranges are fallback search "
                "bounds. Neither is reproduced vulnerability evidence."
            ),
        }
        (packet_dir / f"{name}.json").write_text(
            json.dumps(packet, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        rows.append(
            f"| [{result['repository']}]({name}.md) | {result['input_component_count']} | "
            f"{result['component_count']} | {result['excluded_component_count']} | "
            f"{result['revision_candidate_count']} |"
        )
    index = [
        "# Independent revision-candidate index",
        "",
        "> Repair-parent trials resolved against immutable upstream commits. No semantic filtering or reproduction has run.",
        "",
        "| Project | Input | Candidate-bearing | Excluded | Revision candidates |",
        "| --- | ---: | ---: | ---: | ---: |",
        *rows,
        "",
    ]
    (output_dir / "INDEX.md").write_text("\n".join(index), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--claim-dir", type=Path, required=True)
    parser.add_argument("--repo-cache", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument(
        "--offline-cache",
        action="store_true",
        help="use cached Git objects without refreshing refs",
    )
    args = parser.parse_args()
    try:
        projects = [
            json.loads(path.read_text(encoding="utf-8"))
            for path in sorted(args.claim_dir.glob("*.json"))
        ]
        results = []
        for project in projects:
            if project.get("schema_version") != 1:
                raise ResolutionError("revision-claim input must use schema version 1")
            print(f"resolving {project['repository']}", flush=True)
            repository_path, created = clone_if_missing(
                project["repository"], args.repo_cache
            )
            if not args.offline_cache and not created:
                refresh_repository(repository_path)
            failed_fetches = fetch_missing_boundaries(project, repository_path)
            if failed_fetches:
                print(
                    f"  unavailable boundary commits: {', '.join(failed_fetches)}",
                    flush=True,
                )
            results.append(resolve_project(project, repository_path))
        write_outputs(results, args.output_dir)
    except (OSError, ResolutionError, KeyError, json.JSONDecodeError) as error:
        parser.error(str(error))
    print(f"wrote independent revision candidates for {len(results)} projects")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
