#!/usr/bin/env python3
"""Rank candidate components by expected usefulness in later stages."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


class InputError(ValueError):
    pass


WEIGHTS = {
    "application_repository": 51,
    "exploit_evidence": 20,
    "exact_git_repair": 14,
    "fixed_release_without_exact_git_repair": 7,
    "usable_application_git_range": 5,
    "repository_metadata": 3,
}
ASSET_FIELDS = (
    "application_repository",
    "exploit_evidence",
    "exact_git_repair",
    "fixed_release",
    "usable_application_git_range",
    "repository_metadata",
)
DISPOSITIONS = {"all", "resolved", "unresolved"}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _score(row: dict) -> tuple[int, dict[str, int]]:
    assets = row.get("assets")
    if not isinstance(assets, dict) or any(
        not isinstance(assets.get(field), bool) for field in ASSET_FIELDS
    ):
        raise InputError(f"candidate {row.get('component_id')} has invalid assets")
    if not assets["application_repository"]:
        return 0, {field: 0 for field in WEIGHTS}
    contributions = {
        "application_repository": 51,
        "exploit_evidence": 20 if assets["exploit_evidence"] else 0,
        "exact_git_repair": 14 if assets["exact_git_repair"] else 0,
        "fixed_release_without_exact_git_repair": (
            7 if assets["fixed_release"] and not assets["exact_git_repair"] else 0
        ),
        "usable_application_git_range": (
            5 if assets["usable_application_git_range"] else 0
        ),
        "repository_metadata": 3 if assets["repository_metadata"] else 0,
    }
    return sum(contributions.values()), contributions


def _view_selection(
    view_path: Path, candidates_sha256: str, bucket_name: str, disposition: str
) -> tuple[set[str], dict]:
    view = json.loads(view_path.read_text(encoding="utf-8"))
    if view.get("schema_version") != 1:
        raise InputError("candidate ranking requires candidate-view schema version 1")
    if view.get("candidate_source", {}).get("sha256") != candidates_sha256:
        raise InputError("candidate-view source hash does not match --candidates")
    bucket = view.get("buckets", {}).get(bucket_name)
    if not isinstance(bucket, dict):
        raise InputError(f"candidate view has no bucket {bucket_name!r}")
    projects = bucket.get("projects")
    unresolved = bucket.get("unresolved_component_ids")
    if not isinstance(projects, list) or not isinstance(unresolved, list):
        raise InputError(f"candidate-view bucket {bucket_name!r} is incomplete")
    resolved = [
        value
        for project in projects
        if isinstance(project, dict)
        for value in project.get("component_ids", [])
    ]
    values = (
        resolved + unresolved
        if disposition == "all"
        else unresolved
        if disposition == "unresolved"
        else resolved
    )
    if not isinstance(values, list) or not all(
        isinstance(value, str) and value for value in values
    ):
        raise InputError(f"invalid {disposition} set in candidate-view bucket")
    selected = set(values)
    if len(selected) != len(values):
        raise InputError(f"duplicate {disposition} component in candidate-view bucket")
    return selected, {
        "path": str(view_path),
        "sha256": _sha256(view_path),
        "schema_version": 1,
        "bucket": bucket_name,
    }


def generate(
    *,
    candidates_path: Path,
    disposition: str = "all",
    view_path: Path | None = None,
    bucket_name: str | None = None,
) -> dict:
    if disposition not in DISPOSITIONS:
        raise InputError(f"invalid disposition: {disposition!r}")
    if (view_path is None) != (bucket_name is None):
        raise InputError("--view and --bucket must be used together")

    candidates_sha256 = _sha256(candidates_path)
    payload = json.loads(candidates_path.read_text(encoding="utf-8"))
    if payload.get("schema_version") != 5:
        raise InputError("candidate ranking requires candidate schema version 5")
    matrix = payload.get("evidence_matrix")
    if not isinstance(matrix, dict) or not isinstance(matrix.get("rows"), list):
        raise InputError("candidate index requires evidence_matrix rows")

    selected = None
    source_view = None
    if view_path is not None and bucket_name is not None:
        selected, source_view = _view_selection(
            view_path, candidates_sha256, bucket_name, disposition
        )

    ranked = []
    seen = set()
    for row in matrix["rows"]:
        if not isinstance(row, dict) or not isinstance(row.get("component_id"), str):
            raise InputError("candidate evidence-matrix row requires component_id")
        component_id = row["component_id"]
        if component_id in seen:
            raise InputError(f"duplicate candidate component: {component_id}")
        seen.add(component_id)
        row_disposition = row.get("disposition")
        if row_disposition == "rejected":
            continue
        if row_disposition not in {"resolved", "unresolved"}:
            raise InputError(f"candidate {component_id} has invalid disposition")
        if (disposition != "all" and row_disposition != disposition) or (
            selected is not None and component_id not in selected
        ):
            continue
        score, contributions = _score(row)
        ranked.append(
            {
                "component_id": component_id,
                "disposition": row_disposition,
                "repository": row.get("repository"),
                "reason": row.get("reason"),
                "score": score,
                "score_contributions": contributions,
                "assets": row["assets"],
            }
        )

    ranked_ids = {item["component_id"] for item in ranked}
    if selected is not None and selected != ranked_ids:
        raise InputError(
            f"candidate-view {disposition} set disagrees with candidate report"
        )
    ranked.sort(
        key=lambda item: (
            item["disposition"] != "resolved",
            -item["score"],
            item["component_id"],
        )
    )
    for rank, item in enumerate(ranked, 1):
        item["rank"] = rank

    result = {
        "schema_version": 1,
        "method": {
            "name": "downstream_usefulness_weighted_sum_v1",
            "repository_gate": "score is zero without an application repository",
            "weights": WEIGHTS,
            "notes": [
                "exploit_evidence is an EVIDENCE-reference signal, not a verified runnable PoC",
                "fixed release contributes only when an exact Git repair is absent",
                "resolved candidates precede unresolved candidates",
                "equal scores are ordered by component_id",
            ],
        },
        "candidate_source": {
            "path": str(candidates_path),
            "sha256": candidates_sha256,
            "schema_version": 4,
        },
        "selection": {"disposition": disposition},
        "summary": {
            "candidate_count": len(ranked),
            "disposition_counts": {
                value: sum(item["disposition"] == value for item in ranked)
                for value in ("resolved", "unresolved")
            },
            "repository_mapped_count": sum(
                item["assets"]["application_repository"] for item in ranked
            ),
        },
        "ranked_candidates": ranked,
    }
    if source_view:
        result["selection"]["candidate_view"] = source_view
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidates", type=Path, required=True)
    parser.add_argument("--disposition", choices=sorted(DISPOSITIONS), default="all")
    parser.add_argument("--view", type=Path)
    parser.add_argument("--bucket")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        payload = generate(
            candidates_path=args.candidates,
            disposition=args.disposition,
            view_path=args.view,
            bucket_name=args.bucket,
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    except (InputError, OSError, KeyError, json.JSONDecodeError) as error:
        parser.error(str(error))
    print(
        f"wrote {payload['summary']['candidate_count']} ranked "
        f"{args.disposition} candidates to {args.output}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
