#!/usr/bin/env python3
"""Validate budgeted public-evidence semantic-review batches."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path


STATUSES = {"promising", "uncertain", "low_potential"}
FACT_STATES = {"yes", "no", "uncertain"}
CONFIDENCE = {"supported", "plausible", "uncertain"}
POLICY_RESULTS = {"eligible", "uncertain"}
EVIDENCE_TYPES = {
    "advisory",
    "documentation",
    "fix",
    "patch",
    "poc",
    "pull_request",
    "regression",
    "upstream",
}
BEHAVIOR_EVIDENCE = {"advisory", "poc", "regression"}
REPAIR_EVIDENCE = {"fix", "patch", "pull_request"}
HEX64 = re.compile(r"[0-9a-f]{64}")


def _text(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _string_list(value: object, location: str, errors: list[str]) -> list[str]:
    if not isinstance(value, list) or any(not _text(item) for item in value):
        errors.append(f"{location} must be a list of non-empty strings")
        return []
    return list(value)


def _evidence(items: object, location: str, errors: list[str]) -> set[str]:
    if not isinstance(items, list) or not items:
        errors.append(f"{location}.evidence must be a non-empty list")
        return set()
    kinds = set()
    for index, item in enumerate(items):
        prefix = f"{location}.evidence[{index}]"
        if not isinstance(item, dict):
            errors.append(f"{prefix} must be an object")
            continue
        kind = item.get("type")
        if kind not in EVIDENCE_TYPES:
            errors.append(f"{prefix}.type is invalid")
        else:
            kinds.add(kind)
        if not _text(item.get("url")) or not str(item["url"]).startswith(
            ("https://", "http://")
        ):
            errors.append(f"{prefix}.url must be an HTTP(S) URL")
        if not _text(item.get("claim")):
            errors.append(f"{prefix}.claim must be non-empty")
    return kinds


def _validate_application(application: object, errors: list[str]) -> str | None:
    if not isinstance(application, dict):
        errors.append("application must be an object")
        return None
    status = application.get("status")
    if status not in STATUSES:
        errors.append("application.status is invalid")
    for field in ("self_hosted_network_app", "natural_security_boundary"):
        if application.get(field) not in FACT_STATES:
            errors.append(f"application.{field} is invalid")
    for field in ("deployment_model", "rationale"):
        if not _text(application.get(field)):
            errors.append(f"application.{field} must be non-empty")
    for field in (
        "public_surfaces",
        "identities",
        "protected_assets",
        "legitimate_workflows",
        "uncertainties",
    ):
        values = _string_list(application.get(field), f"application.{field}", errors)
        if status == "promising" and field != "uncertainties" and not values:
            errors.append(f"promising application needs {field}")
    _evidence(application.get("evidence"), "application", errors)
    if status == "promising":
        if application.get("self_hosted_network_app") != "yes":
            errors.append("promising application must be a self-hosted network app")
        if application.get("natural_security_boundary") != "yes":
            errors.append("promising application must have a natural security boundary")
    return status if status in STATUSES else None


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
    errors: list[str] = []

    if not isinstance(packet, dict) or packet.get("schema_version") != 2:
        return ["source packet must be a schema-version 2 JSON object"]
    if not isinstance(review, dict):
        return ["semantic review must be a JSON object"]
    if review.get("schema_version") != 3:
        errors.append("schema_version must be 3")
    if review.get("repository") != packet.get("repository"):
        errors.append("repository does not match source packet")
    if review.get("source_packet") != packet_path.name:
        errors.append("source_packet must equal the packet filename")
    digest = review.get("source_packet_sha256")
    if not isinstance(digest, str) or not HEX64.fullmatch(digest):
        errors.append("source_packet_sha256 must be 64 lowercase hex characters")
    elif digest != hashlib.sha256(packet_bytes).hexdigest():
        errors.append("source_packet_sha256 does not match source packet")
    if review.get("review_basis") != "public_evidence_only":
        errors.append("review_basis must be public_evidence_only")
    if review.get("dynamic_testing_performed") is not False:
        errors.append("dynamic_testing_performed must be false")

    app_status = _validate_application(review.get("application"), errors)
    clusters = review.get("clusters")
    assessments = review.get("advisory_assessments")
    windows = review.get("windows")
    if not isinstance(clusters, list):
        errors.append("clusters must be a list")
        clusters = []
    if not isinstance(assessments, list):
        errors.append("advisory_assessments must be a list")
        assessments = []
    if not isinstance(windows, list):
        errors.append("windows must be a list")
        windows = []

    budget = review.get("review_budget")
    if not isinstance(budget, dict):
        errors.append("review_budget must be an object")
    else:
        maximum = budget.get("maximum_advisory_assessments")
        reviewed = budget.get("reviewed_advisory_assessments")
        if not isinstance(maximum, int) or maximum < 0:
            errors.append("review_budget.maximum_advisory_assessments is invalid")
        if reviewed != len(assessments):
            errors.append("review_budget.reviewed_advisory_assessments must match assessments")
        if isinstance(maximum, int) and maximum < len(assessments):
            errors.append("review budget was exceeded")
        if not _text(budget.get("early_stop_reason")):
            errors.append("review_budget.early_stop_reason must be non-empty")

    if app_status != "promising":
        if clusters or assessments or windows:
            errors.append("non-promising application review must stop before clustering")
        expected_status = app_status
    else:
        packet_components = {
            item.get("component_id")
            for item in packet.get("components", [])
            if isinstance(item, dict) and _text(item.get("component_id"))
        }
        cluster_index: dict[str, set[str]] = {}
        component_clusters: dict[str, str] = {}
        for index, cluster in enumerate(clusters):
            location = f"clusters[{index}]"
            if not isinstance(cluster, dict):
                errors.append(f"{location} must be an object")
                continue
            cluster_id = cluster.get("cluster_id")
            if not _text(cluster_id):
                errors.append(f"{location}.cluster_id must be non-empty")
                continue
            if cluster_id in cluster_index:
                errors.append(f"duplicate cluster {cluster_id}")
            component_ids = _string_list(
                cluster.get("component_ids"), f"{location}.component_ids", errors
            )
            if not component_ids:
                errors.append(f"{location} must contain a component")
            cluster_index[cluster_id] = set(component_ids)
            for component_id in component_ids:
                if component_id in component_clusters:
                    errors.append(f"component {component_id} occurs in multiple clusters")
                component_clusters[component_id] = cluster_id
            for field in (
                "entry_surface",
                "affected_component",
                "starting_privilege",
                "rationale",
            ):
                if not _text(cluster.get(field)):
                    errors.append(f"{location}.{field} must be non-empty")
            if not _string_list(
                cluster.get("likely_capabilities"),
                f"{location}.likely_capabilities",
                errors,
            ):
                errors.append(f"{location} needs a likely capability or uncertainty")
        if set(component_clusters) != packet_components:
            errors.append("clusters do not cover packet components exactly once")

        assessment_index: dict[str, dict] = {}
        assessment_scopes: dict[str, set[str]] = {}
        for index, assessment in enumerate(assessments):
            location = f"advisory_assessments[{index}]"
            if not isinstance(assessment, dict):
                errors.append(f"{location} must be an object")
                continue
            component_id = assessment.get("component_id")
            if component_id in assessment_index:
                errors.append(f"duplicate advisory assessment {component_id}")
            elif component_id not in packet_components:
                errors.append(f"{location}.component_id is outside the packet")
            elif isinstance(component_id, str):
                assessment_index[component_id] = assessment
            if assessment.get("cluster_id") != component_clusters.get(component_id):
                errors.append(f"{location}.cluster_id does not match clustering")
            status = assessment.get("status")
            if status not in STATUSES:
                errors.append(f"{location}.status is invalid")
            for field in (
                "attacker_start",
                "public_feature",
                "protected_target",
                "security_boundary",
                "primitive_hypothesis",
            ):
                if not _text(assessment.get(field)):
                    errors.append(f"{location}.{field} must be non-empty")
            types = _evidence(assessment.get("evidence"), location, errors)
            if not types.intersection(BEHAVIOR_EVIDENCE):
                errors.append(f"{location} lacks behavioral evidence")
            if not types.intersection(REPAIR_EVIDENCE):
                errors.append(f"{location} lacks repair evidence")
            _string_list(assessment.get("uncertainties"), f"{location}.uncertainties", errors)

            scope_ids = set()
            candidate_scopes = assessment.get("candidate_scopes")
            if not isinstance(candidate_scopes, list):
                errors.append(f"{location}.candidate_scopes must be a list")
                candidate_scopes = []
            for scope_index, scope in enumerate(candidate_scopes):
                prefix = f"{location}.candidate_scopes[{scope_index}]"
                if not isinstance(scope, dict):
                    errors.append(f"{prefix} must be an object")
                    continue
                scope_id = scope.get("scope_id")
                custom_scope = scope.get("custom_scope")
                if scope_id in scopes:
                    if custom_scope is not None:
                        errors.append(f"{prefix} registered scope must not define custom_scope")
                elif not str(scope_id).startswith("custom."):
                    errors.append(f"{prefix} uses unregistered scope {scope_id}")
                elif not isinstance(custom_scope, dict):
                    errors.append(f"{prefix} custom scope requires custom_scope definition")
                else:
                    if custom_scope.get("id") != scope_id:
                        errors.append(f"{prefix}.custom_scope.id must equal scope_id")
                    for field in sorted(custom_scope_fields - {"id", "technical_impact"}):
                        if not _text(custom_scope.get(field)):
                            errors.append(f"{prefix}.custom_scope.{field} must be non-empty")
                    if custom_scope.get("technical_impact") not in technical_impacts:
                        errors.append(
                            f"{prefix}.custom_scope.technical_impact is not registered"
                        )
                if isinstance(scope_id, str) and (
                    scope_id in scopes
                    or (scope_id.startswith("custom.") and isinstance(custom_scope, dict))
                ):
                    scope_ids.add(scope_id)
                if scope.get("confidence") not in CONFIDENCE:
                    errors.append(f"{prefix}.confidence is invalid")
                if scope.get("policy_result") not in POLICY_RESULTS:
                    errors.append(f"{prefix}.policy_result is invalid")
                for field in ("capability_hypothesis", "witness_hypothesis"):
                    if not _text(scope.get(field)):
                        errors.append(f"{prefix}.{field} must be non-empty")
                if not _string_list(
                    scope.get("required_effects"), f"{prefix}.required_effects", errors
                ):
                    errors.append(f"{prefix} needs a required effect")
                _string_list(scope.get("assumptions"), f"{prefix}.assumptions", errors)
                if not _string_list(
                    scope.get("deferred_checks"), f"{prefix}.deferred_checks", errors
                ):
                    errors.append(f"{prefix} needs a deferred implementation check")
            if status == "promising" and not any(
                scope.get("policy_result") == "eligible"
                and scope.get("confidence") in {"supported", "plausible"}
                for scope in candidate_scopes
                if isinstance(scope, dict)
            ):
                errors.append(f"{location} is promising without an eligible plausible scope")
            assessment_scopes[component_id] = scope_ids

        packet_windows = {
            item.get("window_id"): item
            for item in packet.get("candidate_windows", [])
            if isinstance(item, dict) and _text(item.get("window_id"))
        }
        review_windows: dict[str, dict] = {}
        window_statuses = []
        for index, window in enumerate(windows):
            location = f"windows[{index}]"
            if not isinstance(window, dict):
                errors.append(f"{location} must be an object")
                continue
            window_id = window.get("window_id")
            if window_id in review_windows:
                errors.append(f"duplicate window {window_id}")
            elif isinstance(window_id, str):
                review_windows[window_id] = window
            source_window = packet_windows.get(window_id, {})
            if window.get("commit") != source_window.get("representative_checkpoint"):
                errors.append(f"{location}.commit does not match the source window")
            component_ids = _string_list(
                window.get("component_ids"), f"{location}.component_ids", errors
            )
            if component_ids != source_window.get("component_ids", []):
                errors.append(
                    f"{location}.component_ids must equal the source-window component set"
                )
            status = window.get("status")
            if status not in STATUSES:
                errors.append(f"{location}.status is invalid")
            else:
                window_statuses.append(status)
            representatives = _string_list(
                window.get("representative_component_ids"),
                f"{location}.representative_component_ids",
                errors,
            )
            if not set(representatives).issubset(set(source_window.get("component_ids", []))):
                errors.append(f"{location} cites a component outside the source window")
            if not set(representatives).issubset(set(assessment_index)):
                errors.append(f"{location} cites an unassessed representative")
            scope_ids = _string_list(
                window.get("candidate_scope_ids"),
                f"{location}.candidate_scope_ids",
                errors,
            )
            available_scopes = {
                scope_id
                for component_id in representatives
                for scope_id in assessment_scopes.get(component_id, set())
            }
            if not set(scope_ids).issubset(available_scopes):
                errors.append(f"{location} cites a scope outside its representatives")
            if status == "promising" and (not representatives or not scope_ids):
                errors.append(f"{location} is promising without representative scope evidence")
            for field in ("scenario_hypothesis", "rationale"):
                if not _text(window.get(field)):
                    errors.append(f"{location}.{field} must be non-empty")
            _string_list(window.get("assumptions"), f"{location}.assumptions", errors)
            if not _string_list(
                window.get("deferred_checks"), f"{location}.deferred_checks", errors
            ):
                errors.append(f"{location} needs a deferred implementation check")
        if set(review_windows) != set(packet_windows):
            errors.append("window reviews do not exactly cover packet windows")
        if "promising" in window_statuses:
            expected_status = "promising"
        elif "uncertain" in window_statuses:
            expected_status = "uncertain"
        else:
            expected_status = "low_potential"

    if review.get("status") != expected_status:
        errors.append(f"status must be derived as {expected_status}")
    if not _text(review.get("rationale")):
        errors.append("rationale must be non-empty")
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
            parser.error(f"scope registry uses unknown technical impacts: {sorted(unknown_parents)}")
        custom_scope_fields = set(scopes_payload["policy"]["custom_scope_required_fields"])
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
