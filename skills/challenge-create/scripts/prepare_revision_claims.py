#!/usr/bin/env python3
"""Prepare source-linked repair and affected-range claims for Stage 2."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path


def _report_name(repository: str) -> str:
    return "__".join(
        re.sub(r"[^A-Z0-9]+", "_", part.upper()).strip("_")
        for part in repository.split("/")
    )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _component(seed: dict) -> dict:
    fields = (
        "component_id",
        "ids",
        "earliest_manifested_publication",
        "summaries",
        "details",
        "packages",
        "references",
        "severities",
        "sources",
        "source_databases",
        "fast_lane_memberships",
        "cwes",
        "behavioral_evidence",
        "repair_evidence",
        "application_repository",
        "application_mapping",
        "duplicate_matches",
    )
    result = {key: seed.get(key) for key in fields}
    result["repair_claims"] = seed.get("fixes", [])
    result["range_claims"] = seed.get("application_range_claims", [])
    if resolution := seed.get("stage1_5_resolution"):
        result["stage1_5_resolution"] = resolution
    return result


def generate(
    *,
    candidates_path: Path,
    manifest_path: Path,
    repository: str | None = None,
) -> dict:
    payload = json.loads(candidates_path.read_text(encoding="utf-8"))
    if payload.get("schema_version") != 5:
        raise ValueError("Stage 2 requires candidate schema version 5")
    recorded_manifest = payload.get("sources", {}).get("advisory_manifest", {})
    if recorded_manifest.get("sha256") != _sha256(manifest_path):
        raise ValueError("candidate advisory-manifest hash does not match --manifest")

    projects = {
        item["repository"].lower(): item for item in payload.get("projects", [])
    }
    requested = repository.strip().lower() if repository else None
    if requested and requested not in projects:
        raise ValueError(f"project missing from candidates: {requested}")
    selected = [requested] if requested else list(projects)

    prepared = []
    for repository_name in selected:
        project = projects[repository_name]
        components = [_component(item) for item in project["components"]]
        prepared.append(
            {
                "schema_version": 1,
                "repository": repository_name,
                "repository_aliases": project.get(
                    "repository_aliases", [repository_name]
                ),
                "project": project.get("project", {}),
                "duplicate_matches": project.get("duplicate_matches", []),
                "source_provenance": {
                    "candidate_source": str(candidates_path),
                    "candidate_source_sha256": _sha256(candidates_path),
                    "candidate_sources": payload.get("sources", {}),
                },
                "component_count": len(components),
                "repair_claim_count": sum(
                    len(item["repair_claims"]) for item in components
                ),
                "range_claim_count": sum(
                    len(item["range_claims"]) for item in components
                ),
                "components": sorted(
                    components, key=lambda item: item["component_id"]
                ),
            }
        )

    return {
        "schema_version": 1,
        "method": "source_linked_revision_claims",
        "claim_boundary": (
            "Each repair and affected range remains an independent upstream claim. "
            "No cross-vulnerability overlap or affected-state truth is computed."
        ),
        "project_count": len(prepared),
        "component_count": sum(item["component_count"] for item in prepared),
        "projects": prepared,
    }


def _project_markdown(project: dict) -> str:
    return "\n".join(
        [
            f"# {project['repository']} revision claims",
            "",
            "> Maintainer-only Stage 2 input. Claims are source-linked assertions, not reproduced vulnerability states.",
            "",
            f"- Deduplicated vulnerabilities: {project['component_count']}",
            f"- Direct repair claims: {project['repair_claim_count']}",
            f"- Affected-range claims: {project['range_claim_count']}",
            "- Cross-vulnerability overlap: not computed",
            "",
        ]
    )


def write_reports(payload: dict, output_dir: Path) -> None:
    data_dir = output_dir / "revision_data"
    data_dir.mkdir(parents=True, exist_ok=True)
    rows = []
    for project in payload["projects"]:
        name = _report_name(project["repository"])
        (data_dir / f"{name}.json").write_text(
            json.dumps(project, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        report = output_dir / f"POTENTIAL_CHALLENGE_{name}_REVISION_CLAIMS.md"
        report.write_text(_project_markdown(project), encoding="utf-8")
        rows.append(
            f"| [{project['repository']}]({report.name}) | {project['component_count']} | "
            f"{project['repair_claim_count']} | {project['range_claim_count']} |"
        )
    index = [
        "# OSS candidate revision-claim index",
        "",
        "> Maintainer-only. Alias records are deduplicated; vulnerabilities remain independent.",
        "",
        "| Project | Vulnerabilities | Repair claims | Range claims |",
        "| --- | ---: | ---: | ---: |",
        *rows,
        "",
    ]
    (output_dir / "OSS_CANDIDATE_REVISION_CLAIM_INDEX.md").write_text(
        "\n".join(index), encoding="utf-8"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidates", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument(
        "--repository",
        help="limit output to one OWNER/REPOSITORY from the candidate index",
    )
    args = parser.parse_args()
    try:
        payload = generate(
            candidates_path=args.candidates,
            repository=args.repository,
            manifest_path=args.manifest,
        )
        write_reports(payload, args.output_dir)
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as error:
        parser.error(str(error))
    print(
        f"wrote revision claims for {payload['project_count']} projects and "
        f"{payload['component_count']} deduplicated vulnerabilities"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
