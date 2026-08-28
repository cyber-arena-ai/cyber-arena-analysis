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
    result_path = study_dir / "result.json"
    result = json.loads(result_path.read_text(encoding="utf-8"))
    errors: list[str] = []

    if not isinstance(packet, dict) or packet.get("schema_version") != 2:
        return ["source packet must be a schema-version 2 JSON object"]
    if not isinstance(review, dict) or review.get("schema_version") != 4:
        return ["source review must be a schema-version 4 JSON object"]
    if not isinstance(result, dict):
        return ["result.json must be a JSON object"]
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
    if result.get("schema_version") != 3:
        errors.append("schema_version must be 3")
    if result.get("repository") != packet.get("repository"):
        errors.append("repository does not match source packet")
    if result.get("source_packet") != packet_path.name:
        errors.append("source_packet must equal the packet filename")
    digest = result.get("source_packet_sha256")
    if not isinstance(digest, str) or not HEX64.fullmatch(digest):
        errors.append("source_packet_sha256 must be 64 lowercase hex characters")
    elif digest != hashlib.sha256(packet_bytes).hexdigest():
        errors.append("source_packet_sha256 does not match source packet")

    windows = {
        item.get("window_id"): item
        for item in packet.get("candidate_windows", [])
        if isinstance(item, dict) and _text(item.get("window_id"))
    }
    window = windows.get(result.get("window_id"))
    if window is None:
        errors.append("window_id does not identify a source-packet window")
    if result.get("window_id") != decision.get("window_id"):
        errors.append("window_id does not match the semantic review")
    commit = result.get("commit")
    if not isinstance(commit, str) or not HEX40.fullmatch(commit):
        errors.append("commit must be 40 lowercase hex characters")
    elif window is not None and commit != window.get("representative_checkpoint"):
        errors.append("commit does not match the selected source-packet window")
    if commit != decision.get("commit"):
        errors.append("commit does not match the semantic review")

    components = result.get("selected_component_ids")
    if (
        not isinstance(components, list)
        or not components
        or any(not _text(item) for item in components)
        or len(components) != len(set(components))
    ):
        errors.append("selected_component_ids must be unique non-empty strings")
        components = []
    if window is not None and not set(components).issubset(
        set(window.get("component_ids", []))
    ):
        errors.append("selected_component_ids contains a component outside the window")
    if components != decision.get("selected_component_ids"):
        errors.append("selected_component_ids does not match the semantic review")

    outcome = result.get("outcome")
    if outcome not in OUTCOMES:
        errors.append("outcome is invalid")
    artifacts = result.get("artifacts")
    if not isinstance(artifacts, dict):
        errors.append("artifacts must be an object")
        artifacts = {}

    study_path = _artifact(study_dir, artifacts.get("study"), "artifacts.study", errors)
    if study_path is not None:
        study_text = study_path.read_text(encoding="utf-8")
        if isinstance(commit, str) and commit not in study_text:
            errors.append("study does not name the selected commit")
        for component in components:
            if component not in study_text:
                errors.append(f"study does not name selected component {component}")

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
