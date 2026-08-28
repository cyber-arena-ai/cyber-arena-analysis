#!/usr/bin/env python3
"""Validate Stage 2 semantic-review batches."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import datetime
from pathlib import Path


STATUSES = {"promising", "uncertain", "low_potential"}
HEX64 = re.compile(r"[0-9a-f]{64}")
EVIDENCE_KINDS = {"attack_chain", "repair", "operability"}
OPERABILITY_RISKS = {"low", "medium", "high", "unknown"}


def _text(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _string_list(value: object, location: str, errors: list[str]) -> list[str]:
    if not isinstance(value, list) or any(not _text(item) for item in value):
        errors.append(f"{location} must be a list of non-empty strings")
        return []
    return list(value)


def _retained_evidence(
    review_path: Path, item: dict, location: str, errors: list[str]
) -> str | None:
    allowed = {"kind", "url", "observed_at", "artifact", "sha256", "claim"}
    unexpected = set(item) - allowed
    if unexpected:
        errors.append(f"{location} has unexpected fields: {sorted(unexpected)}")
    kind = item.get("kind")
    if kind not in EVIDENCE_KINDS:
        errors.append(f"{location}.kind is invalid")
        kind = None
    if not _text(item.get("url")) or not str(item["url"]).startswith(
        ("https://", "http://")
    ):
        errors.append(f"{location}.url must be an HTTP(S) URL")
    try:
        observed = datetime.fromisoformat(
            str(item.get("observed_at")).replace("Z", "+00:00")
        )
        if observed.tzinfo is None:
            raise ValueError
    except (TypeError, ValueError):
        errors.append(f"{location}.observed_at must be timezone-qualified ISO-8601")
    if not _text(item.get("claim")):
        errors.append(f"{location}.claim must be non-empty")

    artifact = item.get("artifact")
    digest = item.get("sha256")
    if not _text(artifact) or Path(str(artifact)).is_absolute():
        errors.append(f"{location}.artifact must be a nonempty relative path")
        return kind
    if not isinstance(digest, str) or not HEX64.fullmatch(digest):
        errors.append(f"{location}.sha256 must be 64 lowercase hex characters")
        return kind
    root = review_path.parent.resolve()
    path = review_path.parent / str(artifact)
    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError):
        errors.append(f"{location}.artifact must resolve inside the review directory")
        return kind
    if path.is_symlink() or not resolved.is_file():
        errors.append(f"{location}.artifact must be a regular retained file")
        return kind
    if hashlib.sha256(resolved.read_bytes()).hexdigest() != digest:
        errors.append(f"{location}.sha256 does not match the retained artifact")
    return kind


def validate(
    packet_path: Path,
    review_path: Path,
    scopes: dict[str, str],
    technical_impacts: set[str],
    custom_scope_fields: set[str],
) -> list[str]:
    packet_bytes = packet_path.read_bytes()
    packet = json.loads(packet_bytes)
    review = json.loads(review_path.read_text(encoding="utf-8"))
    if not isinstance(packet, dict) or packet.get("schema_version") != 3:
        return ["source packet must be a schema-version 3 JSON object"]
    if not isinstance(review, dict) or review.get("schema_version") != 5:
        return ["semantic review must be a schema-version 5 JSON object"]

    errors: list[str] = []
    allowed_fields = {
        "schema_version",
        "repository",
        "source_packet",
        "source_packet_sha256",
        "review_basis",
        "decision",
        "evidence",
        "custom_scopes",
    }
    unexpected = set(review) - allowed_fields
    if unexpected:
        errors.append(f"unexpected top-level fields: {sorted(unexpected)}")
    if review.get("repository") != packet.get("repository"):
        errors.append("repository does not match source packet")
    if review.get("source_packet") != packet_path.name:
        errors.append("source_packet must equal the packet filename")
    digest = review.get("source_packet_sha256")
    if not isinstance(digest, str) or not HEX64.fullmatch(digest):
        errors.append("source_packet_sha256 must be 64 lowercase hex characters")
    elif digest != hashlib.sha256(packet_bytes).hexdigest():
        errors.append("source_packet_sha256 does not match source packet")
    if review.get("review_basis") != "public_evidence_and_bounded_source_review":
        errors.append(
            "review_basis must be public_evidence_and_bounded_source_review"
        )

    custom_scopes = review.get("custom_scopes", [])
    custom_scope_ids: set[str] = set()
    if not isinstance(custom_scopes, list):
        errors.append("custom_scopes must be a list")
        custom_scopes = []
    for index, scope in enumerate(custom_scopes):
        location = f"custom_scopes[{index}]"
        if not isinstance(scope, dict):
            errors.append(f"{location} must be an object")
            continue
        scope_id = scope.get("id")
        if not _text(scope_id) or not str(scope_id).startswith("custom."):
            errors.append(f"{location}.id must start with custom.")
        elif scope_id in custom_scope_ids:
            errors.append(f"duplicate custom scope {scope_id}")
        else:
            custom_scope_ids.add(scope_id)
        for field in sorted(custom_scope_fields - {"id", "technical_impact"}):
            if not _text(scope.get(field)):
                errors.append(f"{location}.{field} must be non-empty")
        if scope.get("technical_impact") not in technical_impacts:
            errors.append(f"{location}.technical_impact is not registered")

    decision = review.get("decision")
    if not isinstance(decision, dict):
        errors.append("decision must be an object")
        decision = {}
    else:
        expected = {
            "verdict",
            "candidate_id",
            "repair_commit",
            "primary_commit",
            "fallback_range_claim_id",
            "selected_component_ids",
            "candidate_scope_ids",
            "case",
            "next_focus",
            "operability",
        }
        unexpected = set(decision) - expected
        if unexpected:
            errors.append(f"unexpected decision fields: {sorted(unexpected)}")

    verdict = decision.get("verdict")
    if verdict not in STATUSES:
        errors.append("decision.verdict is invalid")
    candidates = {
        item.get("candidate_id"): item
        for item in packet.get("revision_candidates", [])
        if isinstance(item, dict) and _text(item.get("candidate_id"))
    }
    candidate = candidates.get(decision.get("candidate_id"))
    if candidate is None:
        errors.append("decision.candidate_id is outside the source packet")
        candidate = {}
    for field in ("repair_commit", "primary_commit"):
        if decision.get(field) != candidate.get(field):
            errors.append(f"decision.{field} does not match the selected candidate")
    fallback = decision.get("fallback_range_claim_id")
    if fallback not in candidate.get("fallback_range_claim_ids", []):
        errors.append(
            "decision.fallback_range_claim_id is outside the selected candidate"
        )

    packet_component_ids = {
        item.get("component_id")
        for item in packet.get("components", [])
        if isinstance(item, dict) and _text(item.get("component_id"))
    }
    component_ids = _string_list(
        decision.get("selected_component_ids"),
        "decision.selected_component_ids",
        errors,
    )
    if not component_ids:
        errors.append("decision must select at least one component")
    if len(component_ids) != len(set(component_ids)):
        errors.append("decision.selected_component_ids contains duplicates")
    if not set(component_ids).issubset(packet_component_ids):
        errors.append("decision selects a component outside the source packet")
    if candidate.get("component_id") not in component_ids:
        errors.append("decision must include the selected candidate's component")

    scope_ids = _string_list(
        decision.get("candidate_scope_ids"),
        "decision.candidate_scope_ids",
        errors,
    )
    if verdict in {"promising", "uncertain"} and not scope_ids:
        errors.append(f"{verdict} decision requires a candidate scope")
    known_scope_ids = set(scopes) | custom_scope_ids
    for scope_id in scope_ids:
        if scope_id not in known_scope_ids:
            errors.append(f"decision uses unregistered scope {scope_id}")
    unused_custom_scopes = custom_scope_ids - set(scope_ids)
    if unused_custom_scopes:
        errors.append(f"unused custom scopes: {sorted(unused_custom_scopes)}")
    if not _text(decision.get("case")):
        errors.append("decision.case must be non-empty")
    next_focus = decision.get("next_focus")
    if verdict in {"promising", "uncertain"} and not _text(next_focus):
        errors.append(f"{verdict} decision requires decision.next_focus")
    if verdict == "low_potential" and next_focus is not None:
        errors.append("low_potential decision.next_focus must be null")

    operability = decision.get("operability")
    if operability is None and verdict != "promising":
        pass
    elif not isinstance(operability, dict):
        errors.append("decision.operability must be an object")
    else:
        unexpected = set(operability) - {"risk", "deployment"}
        if unexpected:
            errors.append(
                f"decision.operability has unexpected fields: {sorted(unexpected)}"
            )
        if operability.get("risk") not in OPERABILITY_RISKS:
            errors.append("decision.operability.risk is invalid")
        if not _text(operability.get("deployment")):
            errors.append("decision.operability.deployment must be non-empty")

    evidence = review.get("evidence")
    evidence_kinds: set[str] = set()
    if not isinstance(evidence, list) or not evidence:
        errors.append("evidence must be a non-empty list")
    else:
        for index, item in enumerate(evidence):
            location = f"evidence[{index}]"
            if not isinstance(item, dict):
                errors.append(f"{location} must be an object")
                continue
            kind = _retained_evidence(review_path, item, location, errors)
            if kind:
                evidence_kinds.add(kind)
    if verdict == "promising":
        for kind in ("attack_chain", "repair", "operability"):
            if kind not in evidence_kinds:
                errors.append(f"{verdict} decision requires {kind} evidence")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--packet-dir", required=True, type=Path)
    parser.add_argument("--review-dir", required=True, type=Path)
    parser.add_argument("--scope-registry", required=True, type=Path)
    args = parser.parse_args()
    try:
        scopes_payload = json.loads(args.scope_registry.read_text(encoding="utf-8"))
        impact_items = scopes_payload["technical_impact_standard"]["impacts"]
        technical_impacts = {str(item["id"]) for item in impact_items}
        scopes = {
            str(item["id"]): str(item["technical_impact"])
            for item in scopes_payload.get("scopes", [])
        }
        unknown_parents = set(scopes.values()) - technical_impacts
        if unknown_parents:
            parser.error(
                f"scope registry uses unknown technical impacts: {sorted(unknown_parents)}"
            )
        custom_scope_fields = set(
            scopes_payload["policy"]["custom_scope_required_fields"]
        )
        packets = sorted(args.packet_dir.glob("*.json"))
        reviews = {path.name: path for path in args.review_dir.glob("*.json")}
    except (OSError, KeyError, json.JSONDecodeError) as error:
        parser.error(str(error))
    if not packets:
        parser.error("no semantic packets found")

    failures = 0
    packet_names = {path.name for path in packets}
    for packet_path in packets:
        review_path = reviews.get(packet_path.name)
        if review_path is None:
            failures += 1
            print(f"FAIL {packet_path}: missing semantic review")
            continue
        try:
            errors = validate(
                packet_path,
                review_path,
                scopes,
                technical_impacts,
                custom_scope_fields,
            )
        except (OSError, KeyError, json.JSONDecodeError) as error:
            errors = [str(error)]
        if errors:
            failures += 1
            for error in errors:
                print(f"FAIL {review_path}: {error}")
        else:
            print(f"PASS {review_path}")
    for name in sorted(set(reviews) - packet_names):
        failures += 1
        print(f"FAIL {reviews[name]}: no matching semantic packet")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
