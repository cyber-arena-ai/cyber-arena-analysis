#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

from _contracts import (
    ACTIVE_STAGES, ANTIPATTERNS, CHECK_STATUSES, CHECKS, CONTEXT_KEYS,
    EVIDENCE_KINDS, OBJECTIVE_ORACLES, OBJECTIVE_OUTCOMES, ORCHESTRATOR_COMMIT,
    SCHEMA_VERSION, SEVERITY_ORDER, STAGE_ORDER, STAGE_STATUSES, VERDICT_EFFECTS,
    VERDICTS, WIP_OBSERVATIONS,
)


COMMIT = re.compile(r"^[0-9a-f]{40}$")
IMAGE_HASH = re.compile(r"^sha256:[0-9a-f]{64}$")
EVIDENCE = re.compile(r"^(source|verifier|dynamic):\s+(.+?)\s+—\s+(.+)$")
TOP_LEVEL_KEYS = {
    "schema_version", "scope", "context", "objectives", "stages", "checks",
    "findings", "unresolved", "wip_observations", "verdict",
}
MISSING = object()
VERIFIER_CHECK_TIERS = {
    "VERIFY-INTERFACE": {0},
    "VERIFY-BUILD": {1},
    "VERIFY-HEALTH": {2},
    "VERIFY-FLAG": {1, 2},
    "VERIFY-RESTART": {2},
}


def exact_keys(value: object, expected: set[str], path: str, errors: list[str]) -> bool:
    if not isinstance(value, dict):
        errors.append(f"{path}: expected object")
        return False
    actual = set(value)
    missing = sorted(expected - actual)
    extra = sorted(actual - expected)
    if missing:
        errors.append(f"{path}: missing keys {missing}")
    if extra:
        errors.append(f"{path}: unexpected keys {extra}")
    return not missing


def nonempty(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def string_list(value: object) -> bool:
    return isinstance(value, list) and all(nonempty(item) for item in value)


def validate_evidence(
    value: object,
    path: str,
    errors: list[str],
    *,
    stage: str | None = None,
    report_dir: Path | None = None,
    verifier_artifact: dict | None = None,
) -> list[tuple[str, str, str]]:
    if not string_list(value):
        errors.append(f"{path}: expected an array of non-empty strings")
        return []
    parsed: list[tuple[str, str, str]] = []
    for index, item in enumerate(value):
        match = EVIDENCE.fullmatch(item)
        if not match:
            errors.append(
                f"{path}[{index}]: expected '<source|verifier|dynamic>: <locator> — <fact>'"
            )
            continue
        kind, locator, fact = match.groups()
        if kind not in EVIDENCE_KINDS:
            errors.append(f"{path}[{index}]: unknown evidence kind {kind!r}")
            continue
        if stage == "static" and kind != "source":
            errors.append(f"{path}[{index}]: static evidence must use source")
        if stage == "verifier" and kind != "verifier":
            errors.append(f"{path}[{index}]: verifier evidence must use verifier")
        if kind == "dynamic" and read_artifact_line(locator, report_dir) is None:
            errors.append(
                f"{path}[{index}]: dynamic locator must name an existing "
                "run-relative artifact line"
            )
        if kind == "verifier":
            resolved = resolve_verifier_pointer(locator, verifier_artifact)
            if resolved is MISSING:
                errors.append(
                    f"{path}[{index}]: verifier locator must resolve a JSON Pointer "
                    "inside verifier.json"
                )
        parsed.append((kind, locator, fact))
    return parsed


def read_artifact_line(locator: str, report_dir: Path | None) -> str | None:
    if report_dir is None:
        return None
    if ":" not in locator:
        return None
    artifact_text, line_text = locator.rsplit(":", 1)
    artifact = Path(artifact_text)
    if (
        artifact.is_absolute()
        or ".." in artifact.parts
        or not line_text.isdigit()
        or int(line_text) < 1
    ):
        return None
    resolved = confined_artifact(report_dir, artifact)
    if resolved is None:
        return None
    try:
        return resolved.read_text(encoding="utf-8").splitlines()[
            int(line_text) - 1
        ]
    except (OSError, IndexError):
        return None


def confined_artifact(report_dir: Path, artifact: Path) -> Path | None:
    try:
        root = report_dir.resolve(strict=True)
        resolved = (root / artifact).resolve(strict=True)
    except OSError:
        return None
    if not resolved.is_relative_to(root) or not resolved.is_file():
        return None
    return resolved


def resolve_verifier_pointer(locator: str, artifact: dict | None) -> object:
    if artifact is None or not locator.startswith("verifier.json#/"):
        return MISSING
    value: object = artifact
    for raw_part in locator.removeprefix("verifier.json#/").split("/"):
        part = raw_part.replace("~1", "/").replace("~0", "~")
        if isinstance(value, dict) and part in value:
            value = value[part]
        elif isinstance(value, list) and part.isdigit() and int(part) < len(value):
            value = value[int(part)]
        else:
            return MISSING
    return value


def verifier_evidence_supports(
    evidence: list[tuple[str, str, str]], status: str, artifact: dict | None,
    check_id: str,
) -> bool:
    required = {
        f"verifier.json#/tiers/{index}/status"
        for index in VERIFIER_CHECK_TIERS.get(check_id, set())
    }
    matching: set[str] = set()
    for kind, locator, _fact in evidence:
        if kind != "verifier" or locator not in required:
            continue
        value = resolve_verifier_pointer(locator, artifact)
        observed = value.get("status") if isinstance(value, dict) else value
        if isinstance(observed, str) and observed.upper() == status:
            matching.add(locator)
    if status == "PASS":
        return required <= matching
    return bool(matching)


def has_direct_acceptance(
    evidence: list[tuple[str, str, str]], report_dir: Path | None,
    context: dict, objectives: list[dict],
) -> bool:
    declared = {
        (item["store"], item["outcome"], item["scope"], item["oracle"])
        for item in objectives
        if isinstance(item, dict)
        and set(item) == {"store", "outcome", "scope", "oracle"}
    }
    for kind, locator, _fact in evidence:
        if kind != "dynamic":
            continue
        line = read_artifact_line(locator, report_dir)
        if line is None:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(event, dict) or event.get("type") != "FLAG_SUBMITTED":
            continue
        payload = event.get("payload")
        if not isinstance(payload, dict):
            continue
        actor = payload.get("submitter_team_id")
        victim = payload.get("victim_team_id")
        phase = event.get("phase")
        round_id = event.get("round_id")
        objective = (
            payload.get("store"), payload.get("outcome"),
            payload.get("scope"), payload.get("oracle"),
        )
        if not all(nonempty(value) for value in objective):
            continue
        if (
            payload.get("accepted") is True
            and payload.get("reason") == "ACCEPTED"
            and isinstance(actor, str) and bool(actor)
            and event.get("team_id") == actor
            and isinstance(victim, str) and bool(victim)
            and actor != victim
            and isinstance(round_id, int) and not isinstance(round_id, bool)
            and round_id >= 0
            and isinstance(phase, str) and phase in {"ATTACK", "LIVE"}
            and payload.get("phase") == phase
            and payload.get("service") == context.get("challenge_id")
            and objective in declared
        ):
            return True
    return False


def validate_objectives(value: object, errors: list[str]) -> list[dict]:
    if not isinstance(value, list):
        errors.append("$.objectives: expected array")
        return []
    valid: list[dict] = []
    required = {"store", "outcome", "scope", "oracle"}
    for index, item in enumerate(value):
        path = f"$.objectives[{index}]"
        if not exact_keys(item, required, path, errors):
            continue
        assert isinstance(item, dict)
        store = item["store"]
        outcome = item["outcome"]
        scope = item["scope"]
        oracle = item["oracle"]
        if not nonempty(store):
            errors.append(f"{path}.store: expected non-empty string")
        if not isinstance(outcome, str) or outcome not in OBJECTIVE_OUTCOMES:
            errors.append(f"{path}.outcome: unknown outcome {outcome!r}")
        elif oracle != OBJECTIVE_ORACLES[outcome]:
            errors.append(
                f"{path}.oracle: expected {OBJECTIVE_ORACLES[outcome]!r} "
                f"for {outcome!r}"
            )
        if scope is not None and not isinstance(scope, str):
            errors.append(f"{path}.scope: expected string or null")
        if nonempty(store) and isinstance(outcome, str) and outcome in OBJECTIVE_OUTCOMES and (
            oracle == OBJECTIVE_ORACLES[outcome]
        ) and (scope is None or isinstance(scope, str)):
            valid.append(item)
    return valid


def load_verifier_artifact(
    report_dir: Path | None, errors: list[str],
) -> dict | None:
    if report_dir is None:
        errors.append("verifier.json: report directory is unavailable")
        return None
    artifact_path = confined_artifact(report_dir, Path("verifier.json"))
    if artifact_path is None:
        errors.append("verifier.json: expected a run-relative regular file")
        return None
    try:
        artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        errors.append(f"verifier.json: {exc}")
        return None
    if not isinstance(artifact, dict):
        errors.append("verifier.json: expected object")
        return None
    return artifact


def validate_verifier_artifact(
    artifact: dict | None,
    context: dict,
    stage_status: dict[str, str],
    objectives: list[dict],
    errors: list[str],
) -> None:
    if artifact is None:
        return
    if artifact.get("mode") != "execute":
        errors.append("verifier.json.mode: expected 'execute'")
    for key in ("challenge_id", "orchestrator_commit", "warehouse_path", "run_id"):
        if artifact.get(key) != context.get(key):
            errors.append(f"verifier.json.{key}: does not match report context")

    artifact_status = artifact.get("status")
    if not isinstance(artifact_status, str) or artifact_status not in {
        "PASS", "FAIL", "BLOCKED",
    }:
        errors.append("verifier.json.status: expected PASS, FAIL, or BLOCKED")
    elif stage_status.get("verifier") != artifact_status:
        errors.append(
            "$.stages[verifier].status: does not match verifier.json status"
        )

    tiers = artifact.get("tiers")
    if not isinstance(tiers, list) or [
        tier.get("name") for tier in tiers if isinstance(tier, dict)
    ] != ["static", "build", "game"]:
        errors.append("verifier.json.tiers: expected static, build, and game tiers")
        tiers = []
    tier_statuses: list[str] = []
    for index, tier in enumerate(tiers):
        if not isinstance(tier, dict):
            errors.append(f"verifier.json.tiers[{index}]: expected object")
            continue
        status = tier.get("status")
        if not isinstance(status, str) or status not in {
            "PASS", "FAIL", "BLOCKED", "NOT_RUN",
        }:
            errors.append(f"verifier.json.tiers[{index}].status: invalid status")
            continue
        tier_statuses.append(status)
        if status == "PASS":
            parsed = tier.get("parsed_json")
            if not (
                isinstance(parsed, dict)
                and parsed.get("ok") is True
                and isinstance(parsed.get("checks"), list)
                and bool(parsed["checks"])
            ):
                errors.append(
                    f"verifier.json.tiers[{index}]: PASS requires successful checker JSON"
                )

    if artifact_status == "PASS" and tier_statuses != ["PASS", "PASS", "PASS"]:
        errors.append("verifier.json.status: PASS requires all tiers to pass")
    if artifact_status == "FAIL" and "FAIL" not in tier_statuses and not nonempty(
        artifact.get("error")
    ):
        errors.append("verifier.json.status: FAIL requires a failed tier or error")
    if artifact_status == "BLOCKED" and "BLOCKED" not in tier_statuses and not nonempty(
        artifact.get("error")
    ):
        errors.append("verifier.json.status: BLOCKED requires blocked evidence")

    image_hash = artifact.get("image_hash")
    if image_hash is not None and (
        not isinstance(image_hash, str) or not IMAGE_HASH.fullmatch(image_hash)
    ):
        errors.append("verifier.json.image_hash: expected immutable Docker image ID or null")
    if artifact_status == "PASS" and not (
        isinstance(image_hash, str) and IMAGE_HASH.fullmatch(image_hash)
    ):
        errors.append("verifier.json.image_hash: PASS requires immutable Docker image ID")
    if context.get("image_hash") != image_hash:
        errors.append("$.context.image_hash: does not match verifier.json")

    artifact_objectives = artifact.get("objectives")
    if artifact_objectives is not None:
        artifact_errors: list[str] = []
        frozen = validate_objectives(artifact_objectives, artifact_errors)
        if artifact_errors:
            errors.append("verifier.json.objectives: invalid frozen objective contract")
        elif frozen != objectives:
            errors.append("$.objectives: does not match verifier.json")
    elif artifact_status == "PASS":
        errors.append("verifier.json.objectives: PASS requires frozen objective contract")


def expected_verdict(report: dict) -> str:
    if report.get("scope") != "all":
        return "PARTIAL"
    findings = report.get("findings", [])
    effects = {item.get("verdict_effect") for item in findings if isinstance(item, dict)}
    statuses = {
        item.get("stage"): item.get("status")
        for item in report.get("stages", []) if isinstance(item, dict)
    }
    if statuses.get("verifier") == "FAIL":
        return "REJECT"
    if "REJECT" in effects:
        return "REJECT"
    if "BLOCKED" in statuses.values():
        return "BLOCKED"
    unresolved_stages = {
        item.get("stage")
        for item in report.get("unresolved", [])
        if isinstance(item, dict)
    }
    if (
        "REVISE" in effects
        or statuses.get("static") in {"FAIL", "NOT_RUN"}
        or statuses.get("cheat") in {"FAIL", "NOT_RUN"}
        or statuses.get("exploitability") in {"FAIL", "NOT_RUN"}
        or bool(unresolved_stages)
    ):
        return "REVISE"
    if all(statuses.get(stage) == "PASS" for stage in STAGE_ORDER):
        return "ACCEPT"
    return "BLOCKED"


def validate(report: object, report_dir: Path | None = None) -> list[str]:
    errors: list[str] = []
    if not exact_keys(report, TOP_LEVEL_KEYS, "$", errors):
        return errors
    assert isinstance(report, dict)

    if report["schema_version"] != SCHEMA_VERSION:
        errors.append(f"$.schema_version: expected {SCHEMA_VERSION!r}")
    scope = report["scope"]
    if scope not in ACTIVE_STAGES:
        errors.append(f"$.scope: expected one of {sorted(ACTIVE_STAGES)}")
        active: set[str] = set()
    else:
        active = ACTIVE_STAGES[scope]

    context_value = report["context"]
    if exact_keys(context_value, set(CONTEXT_KEYS), "$.context", errors):
        assert isinstance(context_value, dict)
        for key in CONTEXT_KEYS:
            if key == "image_hash":
                continue
            if not nonempty(context_value.get(key)):
                errors.append(f"$.context.{key}: expected non-empty string")
        if (
            isinstance(context_value.get("orchestrator_commit"), str)
            and not COMMIT.fullmatch(context_value["orchestrator_commit"])
        ):
            errors.append(
                "$.context.orchestrator_commit: expected 40-character lowercase commit"
            )
        if context_value.get("orchestrator_commit") != ORCHESTRATOR_COMMIT:
            errors.append(
                "$.context.orchestrator_commit: expected pinned commit "
                f"{ORCHESTRATOR_COMMIT}"
            )
        if (
            isinstance(context_value.get("warehouse_path"), str)
            and not Path(context_value["warehouse_path"]).is_absolute()
        ):
            errors.append("$.context.warehouse_path: expected absolute path")
        image_hash = context_value.get("image_hash")
        if image_hash is not None and (
            not isinstance(image_hash, str) or not IMAGE_HASH.fullmatch(image_hash)
        ):
            errors.append("$.context.image_hash: expected immutable Docker image ID or null")
        if "verifier" not in active and image_hash is not None:
            errors.append("$.context.image_hash: stage scope did not run verifier")
    context = context_value if isinstance(context_value, dict) else {}

    objectives = validate_objectives(report["objectives"], errors)

    stages = report["stages"]
    stage_status: dict[str, str] = {}
    if not isinstance(stages, list):
        errors.append("$.stages: expected array")
        stages = []
    if [item.get("stage") for item in stages if isinstance(item, dict)] != list(STAGE_ORDER):
        errors.append(f"$.stages: expected exact order {list(STAGE_ORDER)}")
    for index, item in enumerate(stages):
        path = f"$.stages[{index}]"
        if not exact_keys(item, {"stage", "status", "summary"}, path, errors):
            continue
        stage = item["stage"]
        status = item["status"]
        if stage not in STAGE_ORDER:
            errors.append(f"{path}.stage: unknown stage {stage!r}")
        if status not in STAGE_STATUSES:
            errors.append(f"{path}.status: unknown status {status!r}")
        if not nonempty(item["summary"]):
            errors.append(f"{path}.summary: expected non-empty string")
        if stage in STAGE_ORDER and status in STAGE_STATUSES:
            stage_status[stage] = status
            if stage not in active and status != "NOT_RUN":
                errors.append(f"{path}.status: stage outside scope must be NOT_RUN")

    verifier_gate = stage_status.get("verifier")
    for stage in active:
        if stage_status.get(stage) != "NOT_RUN":
            continue
        gated = stage != "verifier" and verifier_gate in {"FAIL", "BLOCKED"}
        if not gated:
            errors.append(f"$.stages[{stage}].status: selected stage must run")
    if verifier_gate in {"FAIL", "BLOCKED"}:
        for stage in active - {"verifier"}:
            if stage_status.get(stage) != "NOT_RUN":
                errors.append(
                    f"$.stages[{stage}].status: must be NOT_RUN behind verifier gate"
                )

    verifier_artifact = None
    if "verifier" in active:
        verifier_artifact = load_verifier_artifact(report_dir, errors)
        validate_verifier_artifact(
            verifier_artifact, context, stage_status, objectives, errors,
        )

    expected_checks = [(check_id, stage) for check_id, stage in CHECKS if stage in active]
    checks = report["checks"]
    if not isinstance(checks, list):
        errors.append("$.checks: expected array")
        checks = []
    actual_checks = [
        (item.get("check_id"), item.get("stage"))
        for item in checks if isinstance(item, dict)
    ]
    if actual_checks != expected_checks:
        errors.append("$.checks: expected the selected checks in canonical order")
    check_status: dict[str, str] = {}
    check_entries: dict[str, dict] = {}
    for index, item in enumerate(checks):
        path = f"$.checks[{index}]"
        required = {"check_id", "stage", "status", "summary", "evidence", "next_check"}
        if not exact_keys(item, required, path, errors):
            continue
        check_id = item["check_id"]
        stage = item["stage"]
        status = item["status"]
        if status not in CHECK_STATUSES:
            errors.append(f"{path}.status: unknown status {status!r}")
        else:
            check_status[check_id] = status
            check_entries[check_id] = item
        if not nonempty(item["summary"]):
            errors.append(f"{path}.summary: expected non-empty string")
        parsed_evidence = validate_evidence(
            item["evidence"], f"{path}.evidence", errors, stage=stage,
            report_dir=report_dir, verifier_artifact=verifier_artifact,
        )
        if status in {"PASS", "FAIL", "UNKNOWN"} and not item["evidence"]:
            errors.append(f"{path}.evidence: {status} requires concise evidence")
        if status == "NOT_RUN" and item["evidence"]:
            errors.append(f"{path}.evidence: NOT_RUN cannot carry evidence")
        if stage == "verifier" and status == "UNKNOWN":
            errors.append(f"{path}.status: verifier checks cannot be UNKNOWN")
        if stage == "verifier" and status in {"PASS", "FAIL"} and not (
            verifier_evidence_supports(
                parsed_evidence, status, verifier_artifact, check_id,
            )
        ):
            errors.append(
                f"{path}.evidence: verifier evidence must point to this check's "
                "matching tier status"
            )
        if check_id == "STATIC-FLAG" and status == "PASS":
            stores = [item["store"] for item in objectives]
            if not stores:
                errors.append(f"{path}: PASS requires at least one objective")
            if len(stores) != len(set(stores)):
                errors.append(f"{path}: PASS requires unique objective stores")
            if any(not nonempty(item["scope"]) for item in objectives):
                errors.append(f"{path}: PASS requires a scope for every objective")
            missing = sorted(
                item["store"]
                for item in objectives
                if not any(
                    fact.startswith(
                        f"store={item['store']}; outcome={item['outcome']}; "
                        f"scope={item['scope']}; oracle={item['oracle']};"
                    )
                    for _kind, _locator, fact in parsed_evidence
                )
            )
            if missing:
                errors.append(
                    f"{path}.evidence: missing per-store evidence for {missing}"
                )
        if (
            check_id == "EXPLOIT-ACCEPT"
            and status == "PASS"
            and not has_direct_acceptance(
                parsed_evidence, report_dir, context, objectives,
            )
        ):
            errors.append(
                f"{path}.evidence: EXPLOIT-ACCEPT PASS requires direct dynamic "
                "accepted FLAG_SUBMITTED evidence matching one objective"
            )
        if status == "UNKNOWN":
            if not nonempty(item["next_check"]):
                errors.append(f"{path}: UNKNOWN requires next_check")
        elif item["next_check"] is not None:
            errors.append(f"{path}.next_check: only UNKNOWN may define it")
        if stage_status.get(stage) == "NOT_RUN" and status != "NOT_RUN":
            errors.append(f"{path}.status: NOT_RUN stage requires NOT_RUN checks")
        if stage_status.get(stage) == "PASS" and status in {"FAIL", "NOT_RUN"}:
            errors.append(f"{path}.status: PASS stage cannot contain {status}")
        if status == "FAIL" and stage_status.get(stage) != "FAIL":
            errors.append(f"{path}.status: failed check requires failed stage")

    for stage, status in stage_status.items():
        if stage in active and status == "FAIL" and not any(
            check_stage == stage and check_status.get(check_id) == "FAIL"
            for check_id, check_stage in CHECKS
        ):
            errors.append(f"$.stages[{stage}].status: FAIL requires a failed check")
    if verifier_artifact is not None and verifier_artifact.get("status") == "PASS":
        missing = [
            check_id for check_id, stage in CHECKS
            if stage == "verifier" and check_status.get(check_id) != "PASS"
        ]
        if missing:
            errors.append(
                f"$.checks: passing verifier requires PASS for {missing}"
            )

    findings = report["findings"]
    if not isinstance(findings, list):
        errors.append("$.findings: expected array")
        findings = []
    finding_ids: set[str] = set()
    finding_order: list[tuple[int, str]] = []
    for index, item in enumerate(findings):
        path = f"$.findings[{index}]"
        required = {
            "finding_id", "stage", "severity", "antipattern_id", "title",
            "evidence", "impact", "required_action", "verdict_effect",
        }
        if not exact_keys(item, required, path, errors):
            continue
        finding_id = item["finding_id"]
        if not nonempty(finding_id) or not re.fullmatch(r"F-[0-9]{3}", finding_id):
            errors.append(f"{path}.finding_id: expected F-NNN")
        elif finding_id in finding_ids:
            errors.append(f"{path}.finding_id: duplicate {finding_id}")
        else:
            finding_ids.add(finding_id)
        if item["stage"] not in active:
            errors.append(f"{path}.stage: finding is outside selected scope")
        if item["severity"] not in SEVERITY_ORDER:
            errors.append(f"{path}.severity: unknown severity")
        else:
            finding_order.append((SEVERITY_ORDER[item["severity"]], finding_id))
        if item["antipattern_id"] not in ANTIPATTERNS:
            errors.append(f"{path}.antipattern_id: unknown identifier")
        for key in ("title", "impact", "required_action"):
            if not nonempty(item[key]):
                errors.append(f"{path}.{key}: expected non-empty string")
        parsed_evidence = validate_evidence(
            item["evidence"], f"{path}.evidence", errors, stage=item["stage"],
            report_dir=report_dir, verifier_artifact=verifier_artifact,
        )
        if not parsed_evidence:
            errors.append(f"{path}.evidence: finding requires concise evidence")
        if item["verdict_effect"] not in VERDICT_EFFECTS:
            errors.append(f"{path}.verdict_effect: unknown effect")
    if finding_order != sorted(finding_order):
        errors.append("$.findings: sort by severity, then finding_id")

    unresolved = report["unresolved"]
    if not isinstance(unresolved, list):
        errors.append("$.unresolved: expected array")
        unresolved = []
    unresolved_checks: set[str] = set()
    concern_ids: set[str] = set()
    for index, item in enumerate(unresolved):
        path = f"$.unresolved[{index}]"
        required = {
            "concern_id", "stage", "check_id", "concern", "evidence",
            "resolving_check", "owner_stage",
        }
        if not exact_keys(item, required, path, errors):
            continue
        concern_id = item["concern_id"]
        if not nonempty(concern_id) or not re.fullmatch(r"U-[0-9]{3}", concern_id):
            errors.append(f"{path}.concern_id: expected U-NNN")
        elif concern_id in concern_ids:
            errors.append(f"{path}.concern_id: duplicate {concern_id}")
        else:
            concern_ids.add(concern_id)
        if item["stage"] not in active:
            errors.append(f"{path}.stage: concern is outside selected scope")
        check = check_entries.get(item["check_id"])
        if check is None:
            errors.append(f"{path}.check_id: unknown selected check")
        else:
            unresolved_checks.add(item["check_id"])
            if check["status"] != "UNKNOWN":
                errors.append(f"{path}.check_id: unresolved check must be UNKNOWN")
            if item["stage"] != check["stage"]:
                errors.append(f"{path}.stage: must match the unresolved check stage")
        if item["owner_stage"] not in STAGE_ORDER:
            errors.append(f"{path}.owner_stage: unknown stage")
        for key in ("concern", "resolving_check"):
            if not nonempty(item[key]):
                errors.append(f"{path}.{key}: expected non-empty string")
        if check is not None and item["resolving_check"] != check["next_check"]:
            errors.append(
                f"{path}.resolving_check: must match the check next_check"
            )
        parsed_evidence = validate_evidence(
            item["evidence"], f"{path}.evidence", errors, stage=item["stage"],
            report_dir=report_dir, verifier_artifact=verifier_artifact,
        )
        if not parsed_evidence:
            errors.append(f"{path}.evidence: concern requires concise evidence")
    for check_id, status in check_status.items():
        if status == "UNKNOWN" and check_id not in unresolved_checks:
            errors.append(f"$.unresolved: UNKNOWN check {check_id} requires a matching concern")

    observations = report["wip_observations"]
    if not isinstance(observations, list):
        errors.append("$.wip_observations: expected array")
        observations = []
    seen_observations: set[str] = set()
    for index, item in enumerate(observations):
        path = f"$.wip_observations[{index}]"
        if not exact_keys(item, {"observation_id", "note", "evidence"}, path, errors):
            continue
        observation_id = item["observation_id"]
        if observation_id not in WIP_OBSERVATIONS:
            errors.append(f"{path}.observation_id: unknown WIP identifier")
        elif observation_id in seen_observations:
            errors.append(f"{path}.observation_id: duplicate {observation_id}")
        else:
            seen_observations.add(observation_id)
        if not nonempty(item["note"]):
            errors.append(f"{path}.note: expected non-empty string")
        parsed_evidence = validate_evidence(
            item["evidence"], f"{path}.evidence", errors,
            report_dir=report_dir, verifier_artifact=verifier_artifact,
        )
        if not parsed_evidence:
            errors.append(f"{path}.evidence: observation requires concise evidence")

    verdict = report["verdict"]
    if exact_keys(verdict, {"value", "summary"}, "$.verdict", errors):
        assert isinstance(verdict, dict)
        if verdict["value"] not in VERDICTS:
            errors.append(f"$.verdict.value: expected one of {sorted(VERDICTS)}")
        expected = expected_verdict(report)
        if verdict["value"] != expected:
            errors.append(f"$.verdict.value: expected {expected}, got {verdict['value']}")
        if not nonempty(verdict["summary"]):
            errors.append("$.verdict.summary: expected non-empty string")

    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate a compact challenge-review report.")
    parser.add_argument("report", type=Path)
    args = parser.parse_args(argv)
    try:
        report = json.loads(args.report.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    errors = validate(report, args.report.parent)
    if errors:
        for error in errors:
            print(f"error: {error}", file=sys.stderr)
        return 1
    print("valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
