#!/usr/bin/env python3
"""Compute pre-semantic OSV overlap for every project in a retained shortlist."""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from scripts.challenge_research.osv_history import (  # noqa: E402
    affected_keys,
    analyze_overlap,
    iter_raw_records,
    record_ids,
)
from scripts.challenge_research._lib import canonical_github_repo  # noqa: E402


def _report_name(repository: str) -> str:
    return "__".join(
        re.sub(r"[^A-Z0-9]+", "_", part.upper()).strip("_")
        for part in repository.split("/")
    )


def _relevant_units(component: dict, repository: str) -> set[str]:
    units = set()
    git_unit = f"GIT:{repository}"
    for wrapped in component["records"]:
        for affected in wrapped["record"].get("affected", []):
            for unit in affected_keys(affected)[0]:
                if not unit.startswith("GIT:") or unit == git_unit:
                    units.add(unit)
    return units


def _compact_component(
    seed: dict, record_count: int, units: set[str], git_ranges: list[dict]
) -> dict:
    return {
        "component_id": seed["component_id"],
        "ids": seed["ids"],
        "earliest_osv_publication": seed["earliest_osv_publication"],
        "summaries": seed["summaries"],
        "details": seed.get("details", []),
        "packages": seed.get("packages", []),
        "references": seed.get("references", []),
        "severities": seed.get("severities", []),
        "sources": seed.get("sources", []),
        "source_databases": seed.get("source_databases", []),
        "cwes": seed.get("cwes", []),
        "behavioral_evidence": seed.get("behavioral_evidence", []),
        "repair_evidence": seed.get("repair_evidence", []),
        "fixes": seed["fixes"],
        "priority_context_only": seed.get("priority", False),
        "priority_exclusion_reason_context_only": seed.get(
            "priority_exclusion_reason"
        ),
        "raw_record_count": record_count,
        "affected_units": sorted(units),
        "project_git_ranges": git_ranges,
    }


def _project_git_ranges(component: dict, repository: str) -> list[dict]:
    ranges: dict[str, dict] = {}
    for wrapped in component["records"]:
        for affected in wrapped["record"].get("affected", []):
            for affected_range in affected.get("ranges", []):
                if affected_range.get("type") != "GIT":
                    continue
                if canonical_github_repo(affected_range.get("repo")) != repository:
                    continue
                compact = {
                    "repo": affected_range.get("repo"),
                    "events": affected_range.get("events", []),
                }
                key = json.dumps(compact, sort_keys=True)
                ranges[key] = compact
    return [ranges[key] for key in sorted(ranges)]


def _components_with_ranges(components: list[dict], unit: str) -> list[str]:
    return sorted(
        {
            component["component_id"]
            for component in components
            for wrapped in component["records"]
            for affected in wrapped["record"].get("affected", [])
            if unit in affected_keys(affected)[0] and affected.get("ranges")
        }
    )


def generate(*, candidates_path: Path, raw_dir: Path) -> dict:
    payload = json.loads(candidates_path.read_text(encoding="utf-8"))
    selected_repositories = [
        item["repository"].lower() for item in payload.get("projects", [])
    ]
    project_rows = {
        item["repository"].lower(): item for item in payload.get("projects", [])
    }

    seeds: dict[tuple[str, str], dict] = {}
    id_index: dict[str, set[tuple[str, str]]] = defaultdict(set)
    for repository in selected_repositories:
        project = project_rows.get(repository)
        if not project:
            raise ValueError(f"selected project missing from projects: {repository}")
        for component in project["components"]:
            key = (repository, component["component_id"])
            seeds[key] = component
            for identifier in component["ids"]:
                id_index[identifier].add(key)

    matched_records: dict[tuple[str, str], dict[tuple[str, str], dict]] = defaultdict(dict)
    scanned = 0
    for wrapped in iter_raw_records(raw_dir):
        scanned += 1
        record = wrapped["record"]
        if record.get("withdrawn"):
            continue
        matches = {
            key
            for identifier in record_ids(record)
            for key in id_index.get(identifier, ())
        }
        source_key = (wrapped["source_archive"], wrapped["source_member"])
        for key in matches:
            matched_records[key][source_key] = wrapped

    projects = []
    for repository in selected_repositories:
        project = project_rows[repository]
        components = []
        compact_components = []
        no_raw_records = []
        for key, seed in seeds.items():
            if key[0] != repository:
                continue
            records = list(matched_records[key].values())
            if not records:
                no_raw_records.append(seed["component_id"])
            component = {
                "component_id": seed["component_id"],
                "ids": seed["ids"],
                "summary": seed["summaries"][0] if seed["summaries"] else "",
                "records": records,
            }
            units = _relevant_units(component, repository)
            components.append(component)
            compact_components.append(
                _compact_component(
                    seed,
                    len(records),
                    units,
                    _project_git_ranges(component, repository),
                )
            )

        units = sorted(
            {
                unit
                for component in components
                for unit in _relevant_units(component, repository)
            }
        )
        lanes = []
        for unit in units:
            overlap = analyze_overlap(components, {unit})
            maximal = set(overlap["selection"]["maximal_checkpoints"])
            maximal_rows = [
                checkpoint
                for checkpoint in overlap["checkpoints"]
                if checkpoint["label"] in maximal
            ]
            top_components = sorted(
                {
                    component_id
                    for checkpoint in maximal_rows
                    for component_id in checkpoint["reported_present"]
                }
            )
            range_components = sorted(
                {
                    component_id
                    for checkpoint in maximal_rows
                    for component_id in checkpoint["range_evaluation_required"]
                }
            )
            grouped_maxima: dict[tuple[str, ...], list[str]] = defaultdict(list)
            for checkpoint in maximal_rows:
                grouped_maxima[tuple(sorted(checkpoint["reported_present"]))].append(
                    checkpoint["label"]
                )
            lanes.append(
                {
                    "affected_unit": unit,
                    "checkpoint_order": overlap["checkpoint_order"],
                    "checkpoint_count": len(overlap["checkpoints"]),
                    "selection": overlap["selection"],
                    "provisional_semantic_review_components": top_components,
                    "range_evaluation_required_at_maxima": range_components,
                    "components_with_unevaluated_ranges": _components_with_ranges(
                        components, unit
                    ),
                    "maximal_component_groups": [
                        {
                            "component_ids": list(component_ids),
                            "checkpoint_count": len(labels),
                            "checkpoints": labels,
                        }
                        for component_ids, labels in sorted(grouped_maxima.items())
                    ],
                    "overlap": overlap,
                }
            )

        unit_components = {
            component["component_id"]
            for component in compact_components
            if component["affected_units"]
        }
        projects.append(
            {
                "repository": repository,
                "project": project.get("project", {}),
                "popularity_score": project.get("popularity_score"),
                "popularity_score_components": project.get(
                    "popularity_score_components", {}
                ),
                "application_review_required": project.get(
                    "application_review_required", True
                ),
                "license_review_required": project.get(
                    "license_review_required", True
                ),
                "source_provenance": {
                    "candidate_sources": payload.get("sources", {}),
                    "date_cutoff": payload.get("date_cutoff"),
                },
                "component_count": len(components),
                "affected_unit_count": len(units),
                "components_without_affected_unit": sorted(
                    set(seeds[key]["component_id"] for key in seeds if key[0] == repository)
                    - unit_components
                ),
                "components_without_raw_records": sorted(no_raw_records),
                "components": sorted(
                    compact_components, key=lambda item: item["component_id"]
                ),
                "lanes": lanes,
            }
        )

    return {
        "schema_version": 2,
        "method": "pre_semantic_exact_version_overlap",
        "evidence_semantics": (
            "Maxima use exact positive OSV affected.versions matches only. "
            "Native ecosystem and Git ranges remain explicit blockers and may change them."
        ),
        "candidate_source": str(candidates_path),
        "candidate_sources": payload.get("sources", {}),
        "date_cutoff": payload.get("date_cutoff"),
        "scanned_osv_records": scanned,
        "project_count": len(projects),
        "component_count": sum(item["component_count"] for item in projects),
        "projects": projects,
    }


def _short(values: list[str], limit: int = 6) -> str:
    if not values:
        return "—"
    head = values[:limit]
    suffix = f" (+{len(values) - limit})" if len(values) > limit else ""
    return ", ".join(f"`{value}`" for value in head) + suffix


def _project_markdown(project: dict, payload: dict) -> str:
    lines = [
        f"# {project['repository']} overlap",
        "",
        "> Maintainer-only pre-semantic overlap report. Keep out of agent/researcher prompts and challenge workspaces.",
        "",
        f"- Hard-gated components: {project['component_count']}",
        f"- Exact affected-unit lanes: {project['affected_unit_count']}",
        f"- Date cutoff: `{payload.get('date_cutoff', {}).get('published_after')}`",
        "- Evidence: exact OSV `affected.versions` matches; unresolved ranges are not treated as absence.",
        "",
        "## Affected-unit overlap",
        "",
        "| Affected unit | Checkpoints | Maximum reported overlap | Distinct maximal groups | Provisional review components | Range gaps at maxima |",
        "| --- | ---: | ---: | --- | --- | --- |",
    ]
    for lane in project["lanes"]:
        selection = lane["selection"]
        lines.append(
            "| {unit} | {checkpoints} | {maximum} | {maxima} | {top} | {ranges} |".format(
                unit=f"`{lane['affected_unit']}`",
                checkpoints=lane["checkpoint_count"],
                maximum=selection["maximum_count"],
                maxima=len(lane["maximal_component_groups"]),
                top=_short(lane["provisional_semantic_review_components"]),
                ranges=_short(lane["range_evaluation_required_at_maxima"]),
            )
        )
    if not project["lanes"]:
        lines.append("| — | 0 | 0 | — | — | — |")

    lines.extend(["", "## Distinct maximal groups", ""])
    for lane in project["lanes"]:
        for index, group in enumerate(lane["maximal_component_groups"], start=1):
            lines.append(
                "- `{unit}` group {index}: {components}; {count} checkpoint label(s), "
                "including {checkpoints}.".format(
                    unit=lane["affected_unit"],
                    index=index,
                    components=_short(group["component_ids"]),
                    count=group["checkpoint_count"],
                    checkpoints=_short(group["checkpoints"], 3),
                )
            )
    if not any(lane["maximal_component_groups"] for lane in project["lanes"]):
        lines.append("- None; no exact affected versions were available.")

    lines.extend(["", "## Mandatory stops before semantic filtering", ""])
    stops = []
    if any(lane["components_with_unevaluated_ranges"] for lane in project["lanes"]):
        stops.append(
            "Evaluate native/Git ranges before treating the reported maximum as exhaustive."
        )
    if any(lane["range_evaluation_required_at_maxima"] for lane in project["lanes"]):
        stops.append(
            "Resolve range-only states at the reported maximal checkpoints; they may raise the count."
        )
    if project["components_without_affected_unit"]:
        stops.append(
            "Resolve affected units for: "
            + _short(project["components_without_affected_unit"], 20)
            + "."
        )
    if project["components_without_raw_records"]:
        stops.append(
            "Recover raw records for: "
            + _short(project["components_without_raw_records"], 20)
            + "."
        )
    lines.extend(f"- {stop}" for stop in stops)
    if not stops:
        lines.append("- None from retained OSV structure.")
    lines.extend(
        [
            "- Do not apply semantic verdicts until these programmatic range gaps are resolved or explicitly retained as uncertainty.",
            "",
            "The full checkpoint matrices are retained in the adjacent JSON file.",
            "",
        ]
    )
    return "\n".join(lines)


def write_reports(payload: dict, output_dir: Path) -> None:
    data_dir = output_dir / "overlap_data"
    data_dir.mkdir(parents=True, exist_ok=True)
    index_rows = []
    for project in payload["projects"]:
        name = _report_name(project["repository"])
        data_path = data_dir / f"{name}.json"
        report_path = output_dir / f"POTENTIAL_CHALLENGE_{name}_OVERLAP.md"
        data_path.write_text(
            json.dumps(project, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        report_path.write_text(_project_markdown(project, payload), encoding="utf-8")
        unresolved = len(
            {
                component_id
                for lane in project["lanes"]
                for component_id in lane["range_evaluation_required_at_maxima"]
            }
        )
        range_bearing = len(
            {
                component_id
                for lane in project["lanes"]
                for component_id in lane["components_with_unevaluated_ranges"]
            }
        )
        top_components = len(
            {
                component_id
                for lane in project["lanes"]
                for group in lane["maximal_component_groups"]
                for component_id in group["component_ids"]
            }
        )
        groups = sum(len(lane["maximal_component_groups"]) for lane in project["lanes"])
        index_rows.append(
            "| [{repo}]({report}) | {components} | {lanes} | {groups} | {top} | {unresolved} | {range_bearing} |".format(
                repo=project["repository"],
                report=report_path.name,
                components=project["component_count"],
                lanes=project["affected_unit_count"],
                groups=groups,
                top=top_components,
                unresolved=unresolved,
                range_bearing=range_bearing,
            )
        )
    maximal_groups = sum(
        len(lane["maximal_component_groups"])
        for project in payload["projects"]
        for lane in project["lanes"]
    )
    top_group_components = {
        component_id
        for project in payload["projects"]
        for lane in project["lanes"]
        for group in lane["maximal_component_groups"]
        for component_id in group["component_ids"]
    }
    range_gaps = {
        component_id
        for project in payload["projects"]
        for lane in project["lanes"]
        for component_id in lane["range_evaluation_required_at_maxima"]
    }
    index = [
        "# OSS candidate pre-semantic overlap index",
        "",
        "> Maintainer-only. Exact-version overlap is provisional while listed ranges remain unresolved.",
        "",
        f"- Projects: {payload['project_count']}",
        f"- Hard-gated components: {payload['component_count']}",
        f"- Distinct lane-specific maximal groups: {maximal_groups}",
        f"- Components in at least one maximal group: {len(top_group_components)}",
        f"- Components with range gaps at a reported maximum: {len(range_gaps)}",
        f"- OSV records scanned once: {payload['scanned_osv_records']}",
        "",
        "| Project | Components | Lanes | Maximal groups | Top-group components | Range gaps at maxima | Components with ranges |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
        *index_rows,
        "",
    ]
    (output_dir / "OSS_CANDIDATE_OVERLAP_INDEX.md").write_text(
        "\n".join(index), encoding="utf-8"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidates", type=Path, required=True)
    parser.add_argument("--raw-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        payload = generate(candidates_path=args.candidates, raw_dir=args.raw_dir)
        write_reports(payload, args.output_dir)
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as error:
        parser.error(str(error))
    print(
        f"wrote overlap reports for {payload['project_count']} projects and "
        f"{payload['component_count']} hard-gated components"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
