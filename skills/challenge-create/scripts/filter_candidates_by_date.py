#!/usr/bin/env python3
"""Create a hash-linked publication-date view of a complete candidate index."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path


class InputError(ValueError):
    pass


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _timestamp(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise InputError(f"invalid timestamp {value!r}") from error
    if parsed.tzinfo is None:
        raise InputError(f"timestamp lacks timezone: {value!r}")
    return parsed.astimezone(timezone.utc)


def _bucket(publication: str | None, cutoff: datetime) -> str:
    if publication is None:
        return "unknown"
    return "after" if _timestamp(publication) > cutoff else "at_or_before"


def _empty_bucket() -> dict:
    return {"projects": defaultdict(set), "unresolved_component_ids": set()}


def _materialize(bucket: dict) -> dict:
    projects = [
        {"repository": repository, "component_ids": sorted(component_ids)}
        for repository, component_ids in sorted(bucket["projects"].items())
    ]
    unresolved = sorted(bucket["unresolved_component_ids"])
    project_components = sum(len(item["component_ids"]) for item in projects)
    return {
        "component_count": project_components + len(unresolved),
        "project_count": len(projects),
        "project_component_count": project_components,
        "unresolved_component_count": len(unresolved),
        "projects": projects,
        "unresolved_component_ids": unresolved,
    }


def generate(*, candidates_path: Path, cutoff_value: str) -> dict:
    cutoff = _timestamp(cutoff_value)
    payload = json.loads(candidates_path.read_text(encoding="utf-8"))
    if payload.get("schema_version") != 3:
        raise InputError("candidate date views require candidate schema version 3")
    if payload.get("date_cutoff", {}).get("enabled"):
        raise InputError("candidate date views require an unfiltered candidate index")

    buckets = {name: _empty_bucket() for name in ("after", "at_or_before", "unknown")}
    seen = set()
    for project in payload.get("projects", []):
        repository = project.get("repository")
        if not isinstance(repository, str) or not repository:
            raise InputError("candidate project requires repository")
        for component in project.get("components", []):
            component_id = component.get("component_id")
            if not isinstance(component_id, str) or not component_id:
                raise InputError("candidate project component requires component_id")
            if component_id in seen:
                raise InputError(f"duplicate retained component: {component_id}")
            seen.add(component_id)
            name = _bucket(component.get("earliest_manifested_publication"), cutoff)
            buckets[name]["projects"][repository].add(component_id)

    for item in payload.get("unresolved_candidates", []):
        if component_id := item.get("component_id"):
            publications = [
                {
                    "component_id": component_id,
                    "earliest_manifested_publication": item.get(
                        "earliest_manifested_publication"
                    ),
                }
            ]
        else:
            component_ids = item.get("component_ids")
            publications = item.get("component_publications")
            if not isinstance(component_ids, list) or not isinstance(
                publications, list
            ):
                raise InputError(
                    "repository-level unresolved candidate requires component publications"
                )
            publication_ids = [
                publication.get("component_id")
                if isinstance(publication, dict)
                else None
                for publication in publications
            ]
            if any(
                not isinstance(component_id, str) or not component_id
                for component_id in [*component_ids, *publication_ids]
            ) or sorted(component_ids) != sorted(publication_ids):
                raise InputError(
                    "unresolved component publications do not match component_ids"
                )
        for publication in publications:
            component_id = publication.get("component_id")
            if not isinstance(component_id, str) or not component_id:
                raise InputError("unresolved candidate requires component_id")
            if component_id in seen:
                raise InputError(f"duplicate retained component: {component_id}")
            seen.add(component_id)
            name = _bucket(
                publication.get("earliest_manifested_publication"), cutoff
            )
            buckets[name]["unresolved_component_ids"].add(component_id)

    materialized = {name: _materialize(bucket) for name, bucket in buckets.items()}
    return {
        "schema_version": 1,
        "method": "candidate_publication_date_view",
        "candidate_source": {
            "path": str(candidates_path),
            "sha256": _sha256(candidates_path),
            "schema_version": payload["schema_version"],
        },
        "filter": {
            "published_after": cutoff.isoformat(),
            "comparison": (
                "earliest active manifested-record publication is strictly later"
            ),
            "unknown_dates": "retained in a separate bucket",
        },
        "summary": {
            "retained_components": len(seen),
            "bucket_component_counts": {
                name: bucket["component_count"]
                for name, bucket in materialized.items()
            },
        },
        "buckets": materialized,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidates", type=Path, required=True)
    parser.add_argument("--published-after", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        payload = generate(
            candidates_path=args.candidates,
            cutoff_value=args.published_after,
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    except (InputError, OSError, KeyError, json.JSONDecodeError) as error:
        parser.error(str(error))
    counts = payload["summary"]["bucket_component_counts"]
    print(
        f"wrote date view with {counts['after']} after, "
        f"{counts['at_or_before']} at-or-before, and "
        f"{counts['unknown']} unknown components to {args.output}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
