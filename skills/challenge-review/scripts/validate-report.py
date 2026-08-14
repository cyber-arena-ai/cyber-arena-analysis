#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

from _contracts import (
    ACTIVE_STAGES, ANTIPATTERNS, CHECK_STATUSES, CHECKS, CONTEXT_KEYS,
    EVIDENCE_KINDS, SEVERITY_ORDER, STAGE_ORDER, STAGE_STATUSES,
    VERDICT_EFFECTS, VERDICTS, WIP_OBSERVATIONS,
)


COMMIT = re.compile(r"^[0-9a-f]{40}$")
EVIDENCE = re.compile(r"^(source|verifier|dynamic):\s+(.+?)\s+—\s+(.+)$")
ACCEPTED = re.compile(r"\bACCEPTED\b|[\"']?accepted[\"']?\s*[:=]\s*true", re.IGNORECASE)
TOP_LEVEL_KEYS = {
    "schema_version", "scope", "context", "stages", "checks", "findings",
    "unresolved", "wip_observations", "verdict",
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
        parsed.append((kind, locator, fact))
    return parsed


def has_direct_acceptance(
    evidence: list[tuple[str, str, str]], report_dir: Path | None,
) -> bool:
    if report_dir is None:
        return False
    for kind, locator, _fact in evidence:
        if kind != "dynamic" or ":" not in locator:
            continue
        artifact_text, line_text = locator.rsplit(":", 1)
        artifact = Path(artifact_text)
        if (
            artifact.is_absolute()
            or ".." in artifact.parts
            or not line_text.isdigit()
            or int(line_text) < 1
        ):
            continue
        try:
            line = (report_dir / artifact).read_text(encoding="utf-8").splitlines()[
                int(line_text) - 1
            ]
        except (OSError, IndexError):
            continue
        if ACCEPTED.search(line):
            return True
    return False


def expected_verdict(report: dict) -> str:
    if report.get("scope") != "all":
        return "PARTIAL"
    findings = report.get("findings", [])
    effects = {item.get("verdict_effect") for item in findings if isinstance(item, dict)}
    statuses = {
        item.get("stage"): item.get("status")
        for item in report.get("stages", []) if isinstance(item, dict)
    }
    if statuses.get("verifier") in {"FAIL", "NOT_RUN"}:
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
        or bool(unresolved_stages - {"exploitability"})
    ):
        return "REVISE"
    if statuses.get("exploitability") != "PASS" or "exploitability" in unresolved_stages:
        return "ACCEPT_WITH_CAVEATS"
    if all(statuses.get(stage) == "PASS" for stage in STAGE_ORDER):
        return "ACCEPT"
    return "BLOCKED"


def validate(report: object, report_dir: Path | None = None) -> list[str]:
    errors: list[str] = []
    if not exact_keys(report, TOP_LEVEL_KEYS, "$", errors):
        return errors
    assert isinstance(report, dict)

    if report["schema_version"] != "2.0":
        errors.append("$.schema_version: expected '2.0'")
    scope = report["scope"]
    if scope not in ACTIVE_STAGES:
        errors.append(f"$.scope: expected one of {sorted(ACTIVE_STAGES)}")
        active: set[str] = set()
    else:
        active = ACTIVE_STAGES[scope]

    context = report["context"]
    if exact_keys(context, set(CONTEXT_KEYS), "$.context", errors):
        assert isinstance(context, dict)
        for key in CONTEXT_KEYS:
            if not nonempty(context.get(key)):
                errors.append(f"$.context.{key}: expected non-empty string")
        for key in ("orchestrator_commit", "warehouse_commit", "verifier_commit"):
            if isinstance(context.get(key), str) and not COMMIT.fullmatch(context[key]):
                errors.append(f"$.context.{key}: expected 40-character lowercase commit")

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
        if not nonempty(item["summary"]):
            errors.append(f"{path}.summary: expected non-empty string")
        parsed_evidence = validate_evidence(
            item["evidence"], f"{path}.evidence", errors, stage=stage,
        )
        if status in {"PASS", "FAIL", "UNKNOWN"} and not item["evidence"]:
            errors.append(f"{path}.evidence: {status} requires concise evidence")
        if (
            check_id == "EXPLOIT-ACCEPT"
            and status == "PASS"
            and not has_direct_acceptance(parsed_evidence, report_dir)
        ):
            errors.append(
                f"{path}.evidence: EXPLOIT-ACCEPT PASS requires direct dynamic "
                "ACCEPTED evidence from a run-relative artifact line"
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
        if item["check_id"] not in check_status:
            errors.append(f"{path}.check_id: unknown selected check")
        else:
            unresolved_checks.add(item["check_id"])
        if item["owner_stage"] not in STAGE_ORDER:
            errors.append(f"{path}.owner_stage: unknown stage")
        for key in ("concern", "resolving_check"):
            if not nonempty(item[key]):
                errors.append(f"{path}.{key}: expected non-empty string")
        parsed_evidence = validate_evidence(
            item["evidence"], f"{path}.evidence", errors, stage=item["stage"],
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
