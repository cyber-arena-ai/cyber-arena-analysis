#!/usr/bin/env python3
"""Validate Stage 3 study linkage and required artifact presence."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path


HEX40 = re.compile(r"[0-9a-f]{40}")
HEX64 = re.compile(r"[0-9a-f]{64}")
OUTCOMES = {"ready_for_authoring", "needs_study", "rejected"}


def _text(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _artifact(
    study_dir: Path, value: object, location: str, errors: list[str]
) -> Path | None:
    if not _text(value):
        errors.append(f"{location} must be a non-empty relative path")
        return None
    path = Path(str(value))
    if path.is_absolute() or ".." in path.parts:
        errors.append(f"{location} must stay inside the study directory")
        return None
    resolved = study_dir / path
    if not resolved.is_file():
        errors.append(f"{location} does not exist: {path}")
        return None
    return resolved


def validate(packet_path: Path, review_path: Path, study_dir: Path) -> list[str]:
    packet_bytes = packet_path.read_bytes()
    packet = json.loads(packet_bytes)
    review = json.loads(review_path.read_text(encoding="utf-8"))
    result = json.loads((study_dir / "result.json").read_text(encoding="utf-8"))
    if not isinstance(packet, dict) or packet.get("schema_version") != 3:
        return ["source packet must be a schema-version 3 JSON object"]
    if not isinstance(review, dict) or review.get("schema_version") != 5:
        return ["source review must be a schema-version 5 JSON object"]
    if not isinstance(result, dict):
        return ["result.json must be a JSON object"]

    errors: list[str] = []
    decision = review.get("decision")
    if not isinstance(decision, dict) or decision.get("verdict") != "promising":
        errors.append("semantic review is not eligible for Stage 3")
        decision = {}
    if review.get("repository") != packet.get("repository"):
        errors.append("semantic review repository does not match source packet")
    if review.get("source_packet") != packet_path.name:
        errors.append("semantic review source_packet does not match source packet")
    if review.get("source_packet_sha256") != hashlib.sha256(packet_bytes).hexdigest():
        errors.append("semantic review is not hash-linked to the source packet")
    if result.get("schema_version") != 4:
        errors.append("schema_version must be 4")
    if result.get("repository") != packet.get("repository"):
        errors.append("repository does not match source packet")
    if result.get("source_packet") != packet_path.name:
        errors.append("source_packet must equal the packet filename")
    digest = result.get("source_packet_sha256")
    if not isinstance(digest, str) or not HEX64.fullmatch(digest):
        errors.append("source_packet_sha256 must be 64 lowercase hex characters")
    elif digest != hashlib.sha256(packet_bytes).hexdigest():
        errors.append("source_packet_sha256 does not match source packet")

    candidates = {
        item.get("candidate_id"): item
        for item in packet.get("revision_candidates", [])
        if isinstance(item, dict) and _text(item.get("candidate_id"))
    }
    candidate = candidates.get(result.get("candidate_id"))
    if candidate is None:
        errors.append("candidate_id does not identify a source-packet candidate")
        candidate = {}
    if result.get("candidate_id") != decision.get("candidate_id"):
        errors.append("candidate_id does not match the semantic review")
    for field in ("repair_commit", "primary_commit", "fallback_range_claim_id"):
        if result.get(field) != decision.get(field):
            errors.append(f"{field} does not match the semantic review")
    for field in ("repair_commit", "primary_commit"):
        if result.get(field) != candidate.get(field):
            errors.append(f"{field} does not match the source-packet candidate")
    if result.get("fallback_range_claim_id") not in candidate.get(
        "fallback_range_claim_ids", []
    ):
        errors.append("fallback_range_claim_id is outside the source-packet candidate")

    outcome = result.get("outcome")
    if outcome not in OUTCOMES:
        errors.append("outcome is invalid")
    reproduced = result.get("reproduced_commit")
    if reproduced is not None and (
        not isinstance(reproduced, str) or not HEX40.fullmatch(reproduced)
    ):
        errors.append("reproduced_commit must be null or 40 lowercase hex characters")
    if outcome == "ready_for_authoring" and not isinstance(reproduced, str):
        errors.append("ready_for_authoring requires reproduced_commit")
    search_used = result.get("fallback_search_used")
    if not isinstance(search_used, bool):
        errors.append("fallback_search_used must be boolean")
    elif (
        not search_used
        and reproduced is not None
        and reproduced != result.get("primary_commit")
    ):
        errors.append(
            "reproduced_commit must equal primary_commit when fallback search was not used"
        )

    components = result.get("selected_component_ids")
    if (
        not isinstance(components, list)
        or not components
        or any(not _text(item) for item in components)
        or len(components) != len(set(components))
    ):
        errors.append("selected_component_ids must be unique non-empty strings")
        components = []
    packet_components = {
        item.get("component_id")
        for item in packet.get("components", [])
        if isinstance(item, dict)
    }
    if not set(components).issubset(packet_components):
        errors.append("selected_component_ids contains a component outside the packet")
    if components != decision.get("selected_component_ids"):
        errors.append("selected_component_ids does not match the semantic review")

    artifacts = result.get("artifacts")
    if not isinstance(artifacts, dict):
        errors.append("artifacts must be an object")
        artifacts = {}
    study_path = _artifact(study_dir, artifacts.get("study"), "artifacts.study", errors)
    if study_path is not None:
        study_text = study_path.read_text(encoding="utf-8")
        for value in (
            reproduced,
            result.get("repair_commit"),
            result.get("fallback_range_claim_id"),
            *components,
        ):
            if isinstance(value, str) and value not in study_text:
                errors.append(f"study does not name {value}")

    if outcome == "ready_for_authoring":
        environment = artifacts.get("environment")
        if not isinstance(environment, list) or not environment:
            errors.append("artifacts.environment must be a non-empty list")
        else:
            environment_paths = [
                _artifact(
                    study_dir,
                    item,
                    f"artifacts.environment[{index}]",
                    errors,
                )
                for index, item in enumerate(environment)
            ]
            if not any(
                path is not None
                and (path.name == "Dockerfile" or path.suffix in {".yaml", ".yml"})
                for path in environment_paths
            ):
                errors.append(
                    "artifacts.environment must include a Dockerfile or Compose YAML"
                )
        _artifact(
            study_dir,
            artifacts.get("reproduction"),
            "artifacts.reproduction",
            errors,
        )
        evidence = artifacts.get("evidence")
        if not isinstance(evidence, list) or len(evidence) < 2:
            errors.append(
                "ready_for_authoring requires vulnerable and fixed evidence artifacts"
            )
        else:
            for index, item in enumerate(evidence):
                _artifact(study_dir, item, f"artifacts.evidence[{index}]", errors)
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--packet", required=True, type=Path)
    parser.add_argument("--review", required=True, type=Path)
    parser.add_argument("--study-dir", required=True, type=Path)
    args = parser.parse_args()
    try:
        errors = validate(args.packet, args.review, args.study_dir)
    except (OSError, KeyError, json.JSONDecodeError) as error:
        errors = [str(error)]
    if errors:
        for error in errors:
            print(f"FAIL {args.study_dir}: {error}")
        return 1
    print(f"PASS {args.study_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
