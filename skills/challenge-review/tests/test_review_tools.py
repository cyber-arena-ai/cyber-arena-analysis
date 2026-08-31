from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


SKILL_DIR = Path(__file__).resolve().parents[1]
SCRIPTS = SKILL_DIR / "scripts"
sys.path.insert(0, str(SCRIPTS))

from _contracts import CHECKS, ORCHESTRATOR_COMMIT, STAGE_ORDER  # noqa: E402

_VERIFIER_SPEC = importlib.util.spec_from_file_location(
    "challenge_review_run_verifier", SCRIPTS / "run-verifier.py",
)
assert _VERIFIER_SPEC and _VERIFIER_SPEC.loader
_VERIFIER_MODULE = importlib.util.module_from_spec(_VERIFIER_SPEC)
_VERIFIER_SPEC.loader.exec_module(_VERIFIER_MODULE)
built_image_reference = _VERIFIER_MODULE.built_image_reference

_CONTEXT_SPEC = importlib.util.spec_from_file_location(
    "challenge_review_collect_context", SCRIPTS / "collect-review-context.py",
)
assert _CONTEXT_SPEC and _CONTEXT_SPEC.loader
_CONTEXT_MODULE = importlib.util.module_from_spec(_CONTEXT_SPEC)
_CONTEXT_SPEC.loader.exec_module(_CONTEXT_MODULE)


def check_evidence(check_id: str, stage: str) -> str:
    if stage == "static":
        return "source: challenge-warehouse/example/example/challenge.py:10 — behavior is wired"
    if stage == "verifier":
        return f"verifier: verifier.json#{check_id} — canonical check passed"
    if stage == "cheat":
        return f"dynamic: cheat.log:1 — {check_id} control produced the required result"
    if check_id == "EXPLOIT-ACCEPT":
        return "dynamic: exploit.log:1 — current opponent flag submission was ACCEPTED"
    return f"dynamic: exploit.log:1 — {check_id} was observed in band"


def valid_report() -> dict:
    return {
        "schema_version": "3.0",
        "scope": "all",
        "context": {
            "challenge_id": "example",
            "challenge_dir": "challenge-warehouse/example/example",
            "timestamp": "2026-07-13T12:00:00Z",
            "run_id": "20260713T120000Z-a1b2c3d4",
            "orchestrator_commit": ORCHESTRATOR_COMMIT,
            "warehouse_commit": "2" * 40,
        },
        "stages": [
            {"stage": stage, "status": "PASS", "summary": f"{stage} passed."}
            for stage in STAGE_ORDER
        ],
        "checks": [
            {
                "check_id": check_id,
                "stage": stage,
                "status": "PASS",
                "summary": "Required behavior is supported.",
                "evidence": [check_evidence(check_id, stage)],
                "next_check": None,
            }
            for check_id, stage in CHECKS
        ],
        "findings": [],
        "unresolved": [],
        "wip_observations": [],
        "verdict": {"value": "ACCEPT", "summary": "All four stages passed."},
    }


class ReviewToolTests(unittest.TestCase):
    def run_script(self, name: str, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(SCRIPTS / name), *args],
            text=True,
            capture_output=True,
            check=False,
        )

    def test_context_collector_routes_output_under_review_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "orche"
            warehouse = root / "challenge-warehouse"
            challenge_dir = warehouse / "example" / "package"
            challenge_dir.mkdir(parents=True)
            (root / ".git").mkdir()
            output = Path(tmp) / "context.json"
            review_root = Path(tmp) / "analysis" / "artifacts" / "review"

            def fake_git(repo: Path, *args: str) -> str:
                if args[0] == "status" or args[0] == "cat-file":
                    return ""
                if args == ("rev-parse", f"{ORCHESTRATOR_COMMIT}^{{commit}}"):
                    return ORCHESTRATOR_COMMIT
                if args == ("rev-parse", "HEAD"):
                    return "2" * 40
                raise AssertionError((repo, args))

            with (
                patch.object(_CONTEXT_MODULE, "registry_package", return_value="package"),
                patch.object(
                    _CONTEXT_MODULE,
                    "resolve_challenge_dir",
                    return_value=challenge_dir,
                ),
                patch.object(_CONTEXT_MODULE, "git", side_effect=fake_git),
            ):
                result = _CONTEXT_MODULE.main([
                    "example",
                    "--repo-root", str(root),
                    "--review-root", str(review_root),
                    "--output", str(output),
                ])

            self.assertEqual(result, 0)
            context = json.loads(output.read_text(encoding="utf-8"))
            expected = review_root / ("2" * 40) / context["run_id"]
            self.assertEqual(Path(context["recommended_output_dir"]), expected)
            self.assertEqual(context["orchestrator_commit"], ORCHESTRATOR_COMMIT)
            self.assertNotIn("verifier_ref", context)
            self.assertNotIn("verifier_commit", context)

    def test_valid_report_validates_and_renders_compact_markdown(self) -> None:
        report = valid_report()
        report["findings"] = [{
            "finding_id": "F-001",
            "stage": "static",
            "severity": "LOW",
            "antipattern_id": "UNCLASSIFIED",
            "title": "Minor actionable issue",
            "evidence": ["source: challenge-warehouse/example/example/challenge.py:10 — issue exists"],
            "impact": "Limited benchmark impact.",
            "required_action": "Clarify the implementation.",
            "verdict_effect": "NONE",
        }]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "review.json"
            output = root / "review.md"
            (root / "exploit.log").write_text("submission result: ACCEPTED\n", encoding="utf-8")
            source.write_text(json.dumps(report), encoding="utf-8")

            checked = self.run_script("validate-report.py", str(source))
            self.assertEqual(checked.returncode, 0, checked.stderr)
            rendered = self.run_script(
                "render-report.py", str(source), "--output", str(output),
            )
            self.assertEqual(rendered.returncode, 0, rendered.stderr)
            text = output.read_text(encoding="utf-8")
            self.assertIn("**ACCEPT**", text)
            self.assertIn("[x] `STATIC-PACKAGE`", text)
            self.assertIn("F-001", text)
            self.assertNotIn("Independent perspectives", text)
            self.assertNotIn("Execution traces", text)

    def test_validator_rejects_runtime_evidence_in_static_check(self) -> None:
        report = valid_report()
        static_check = next(item for item in report["checks"] if item["stage"] == "static")
        static_check["evidence"] = [
            "dynamic: cheat.log:1 — runtime behavior appeared correct",
        ]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "exploit.log").write_text("submission result: ACCEPTED\n", encoding="utf-8")
            source = root / "review.json"
            source.write_text(json.dumps(report), encoding="utf-8")
            checked = self.run_script("validate-report.py", str(source))
            self.assertNotEqual(checked.returncode, 0)
            self.assertIn("static evidence must use source", checked.stderr)

    def test_validator_requires_direct_acceptance_artifact(self) -> None:
        report = valid_report()
        accept = next(
            item for item in report["checks"] if item["check_id"] == "EXPLOIT-ACCEPT"
        )
        accept["evidence"] = [
            "verifier: verifier.json#game — submission wiring was exercised",
        ]
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "review.json"
            source.write_text(json.dumps(report), encoding="utf-8")
            checked = self.run_script("validate-report.py", str(source))
            self.assertNotEqual(checked.returncode, 0)
            self.assertIn("direct dynamic ACCEPTED evidence", checked.stderr)

    def test_validator_rejects_missing_acceptance_artifact(self) -> None:
        report = valid_report()
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "review.json"
            source.write_text(json.dumps(report), encoding="utf-8")
            checked = self.run_script("validate-report.py", str(source))
            self.assertNotEqual(checked.returncode, 0)
            self.assertIn("direct dynamic ACCEPTED evidence", checked.stderr)

    def test_all_scope_verifier_failure_rejects_and_skips_specialists(self) -> None:
        report = valid_report()
        for stage in report["stages"]:
            if stage["stage"] == "verifier":
                stage.update(status="FAIL", summary="Canonical verification failed.")
            else:
                stage.update(status="NOT_RUN", summary="Skipped after verifier failure.")
        for check in report["checks"]:
            if check["check_id"] == "VERIFY-INTERFACE":
                check.update(
                    status="FAIL",
                    summary="Canonical interface verification failed.",
                    evidence=["verifier: verifier.json#static — interface tier failed"],
                )
            else:
                check.update(
                    status="NOT_RUN", summary="Skipped after verifier failure.", evidence=[],
                )
        report["verdict"] = {
            "value": "REJECT", "summary": "The verifier gate failed.",
        }
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "review.json"
            source.write_text(json.dumps(report), encoding="utf-8")
            checked = self.run_script("validate-report.py", str(source))
            self.assertEqual(checked.returncode, 0, checked.stderr)

    def test_all_scope_missing_exploit_proof_accepts_with_caveats(self) -> None:
        report = valid_report()
        next(
            stage for stage in report["stages"] if stage["stage"] == "exploitability"
        ).update(status="FAIL", summary="No accepted exploit proof.")
        next(
            check for check in report["checks"] if check["check_id"] == "EXPLOIT-ACCEPT"
        ).update(
            status="FAIL",
            summary="No current opponent flag was accepted.",
            evidence=["dynamic: exploit.log:1 — submission was not accepted"],
        )
        report["verdict"] = {
            "value": "ACCEPT_WITH_CAVEATS",
            "summary": "The challenge is sound, but exploitability was not proven.",
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "review.json"
            output = root / "review.md"
            (root / "exploit.log").write_text(
                "submission was not accepted\n", encoding="utf-8",
            )
            source.write_text(json.dumps(report), encoding="utf-8")
            checked = self.run_script("validate-report.py", str(source))
            self.assertEqual(checked.returncode, 0, checked.stderr)
            rendered = self.run_script(
                "render-report.py", str(source), "--output", str(output),
            )
            self.assertEqual(rendered.returncode, 0, rendered.stderr)
            self.assertIn("**ACCEPT WITH CAVEATS**", output.read_text(encoding="utf-8"))

    def test_external_verifier_block_remains_blocked(self) -> None:
        report = valid_report()
        for stage in report["stages"]:
            if stage["stage"] == "verifier":
                stage.update(status="BLOCKED", summary="Docker infrastructure unavailable.")
            else:
                stage.update(status="NOT_RUN", summary="Blocked by verifier prerequisite.")
        for check in report["checks"]:
            check.update(
                status="NOT_RUN", summary="Blocked by verifier prerequisite.", evidence=[],
            )
        report["verdict"] = {
            "value": "BLOCKED", "summary": "External infrastructure blocked review.",
        }
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "review.json"
            source.write_text(json.dumps(report), encoding="utf-8")
            checked = self.run_script("validate-report.py", str(source))
            self.assertEqual(checked.returncode, 0, checked.stderr)

    def test_renderer_does_not_duplicate_failed_check_evidence(self) -> None:
        report = valid_report()
        failed = next(item for item in report["checks"] if item["check_id"] == "STATIC-BUILD")
        failed.update(
            status="FAIL",
            summary="Build provenance is missing; see F-001.",
            evidence=["source: image/Dockerfile:1 — base image is mutable"],
        )
        next(item for item in report["stages"] if item["stage"] == "static")["status"] = "FAIL"
        report["findings"] = [{
            "finding_id": "F-001",
            "stage": "static",
            "severity": "MEDIUM",
            "antipattern_id": "AP-VERSION-UNPINNED",
            "title": "Build input is mutable",
            "evidence": ["source: image/Dockerfile:1 — base image is mutable"],
            "impact": "Rebuild behavior can drift.",
            "required_action": "Pin the behavior-changing build input.",
            "verdict_effect": "REVISE",
        }]
        report["verdict"] = {"value": "REVISE", "summary": "Build input must be pinned."}
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "exploit.log").write_text("submission result: ACCEPTED\n", encoding="utf-8")
            source = root / "review.json"
            output = root / "review.md"
            source.write_text(json.dumps(report), encoding="utf-8")
            rendered = self.run_script(
                "render-report.py", str(source), "--output", str(output),
            )
            self.assertEqual(rendered.returncode, 0, rendered.stderr)
            text = output.read_text(encoding="utf-8")
            self.assertEqual(text.count("source: image/Dockerfile:1"), 1)

    def test_validator_rejects_verdict_contradiction(self) -> None:
        report = valid_report()
        report["findings"] = [{
            "finding_id": "F-001",
            "stage": "static",
            "severity": "HIGH",
            "antipattern_id": "AP-VULN-DEAD",
            "title": "Vulnerability is absent",
            "evidence": ["source: challenge.py:20 — vulnerable operation is absent"],
            "impact": "The intended benchmark cannot be exercised.",
            "required_action": "Ship the intended vulnerable implementation.",
            "verdict_effect": "REJECT",
        }]
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "review.json"
            source.write_text(json.dumps(report), encoding="utf-8")
            checked = self.run_script("validate-report.py", str(source))
            self.assertNotEqual(checked.returncode, 0)
            self.assertIn("expected REJECT", checked.stderr)

    def test_validator_rejects_unpinned_orchestrator_commit(self) -> None:
        report = valid_report()
        report["context"]["orchestrator_commit"] = "1" * 40
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "exploit.log").write_text(
                "submission result: ACCEPTED\n", encoding="utf-8",
            )
            source = root / "review.json"
            source.write_text(json.dumps(report), encoding="utf-8")
            checked = self.run_script("validate-report.py", str(source))
            self.assertNotEqual(checked.returncode, 0)
            self.assertIn("expected pinned commit", checked.stderr)

    def test_unknown_check_requires_matching_unresolved_concern(self) -> None:
        report = valid_report()
        report["scope"] = "static"
        report["verdict"] = {"value": "PARTIAL", "summary": "Static-only review."}
        for stage in report["stages"]:
            if stage["stage"] != "static":
                stage.update(status="NOT_RUN", summary="Outside selected scope.")
        report["checks"] = [item for item in report["checks"] if item["stage"] == "static"]
        report["checks"][0].update(status="UNKNOWN", next_check=None)
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "review.json"
            source.write_text(json.dumps(report), encoding="utf-8")
            checked = self.run_script("validate-report.py", str(source))
            self.assertNotEqual(checked.returncode, 0)
            self.assertIn("UNKNOWN requires next_check", checked.stderr)

    def test_initializer_uses_compact_v2_shape(self) -> None:
        context = valid_report()["context"]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            context_path = root / "context.json"
            report_path = root / "review.json"
            context_path.write_text(json.dumps(context), encoding="utf-8")
            initialized = self.run_script(
                "init-report.py", "--context", str(context_path),
                "--scope", "static", "--output", str(report_path),
            )
            self.assertEqual(initialized.returncode, 0, initialized.stderr)
            report = json.loads(report_path.read_text(encoding="utf-8"))
            self.assertEqual(report["schema_version"], "3.0")
            self.assertEqual(set(report), {
                "schema_version", "scope", "context", "stages", "checks",
                "findings", "unresolved", "wip_observations", "verdict",
            })
            self.assertNotIn("perspective_reviews", report)
            self.assertNotIn("execution_traces", report)
            self.assertNotIn("candidate_dispositions", report)
            self.assertEqual(
                [stage["stage"] for stage in report["stages"]],
                ["verifier", "static", "cheat", "exploitability"],
            )
            check_ids = [check_id for check_id, _stage in CHECKS]
            self.assertIn("EXPLOIT-SCOPE", check_ids)
            self.assertNotIn("EXPLOIT-INTENDED", check_ids)

    def test_verifier_dry_run_preserves_canonical_three_tiers(self) -> None:
        context = valid_report()["context"]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            context_path = root / "context.json"
            output_path = root / "verifier.json"
            context_path.write_text(json.dumps(context), encoding="utf-8")
            result = self.run_script(
                "run-verifier.py", "example", "--context", str(context_path),
                "--repo-root", str(SKILL_DIR.parents[1]),
                "--output", str(output_path), "--dry-run",
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual([tier["name"] for tier in payload["tiers"]], [
                "static", "build", "game",
            ])
            self.assertEqual(payload["tiers"][0]["command"][-2:], ["example", "--json"])
            self.assertIn("--build", payload["tiers"][1]["command"])
            self.assertIn("--game", payload["tiers"][2]["command"])
            self.assertIsNone(payload["image_reference"])
            self.assertIsNone(payload["image_hash"])

    def test_verifier_executes_one_clean_orchestrator_tree(self) -> None:
        context = valid_report()["context"]
        context["orchestrator_commit"] = ORCHESTRATOR_COMMIT
        git_calls: list[tuple[Path, tuple[str, ...]]] = []

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            context["run_id"] = f"test-{root.name}"
            context_path = root / "context.json"
            output_path = root / "verifier.json"
            context_path.write_text(json.dumps(context), encoding="utf-8")
            worktree = Path("/tmp") / f"cyberarena-verifier-{context['run_id']}"

            def fake_git(
                repo: Path, *args: str, timeout: float = 180.0,
            ) -> subprocess.CompletedProcess[str]:
                del timeout
                git_calls.append((repo, args))
                stdout = ""
                if args == ("rev-parse", "HEAD"):
                    stdout = (
                        context["warehouse_commit"]
                        if repo == worktree / "challenge-warehouse"
                        else context["orchestrator_commit"]
                    )
                return subprocess.CompletedProcess([], 0, stdout, "")

            def fake_command_result(command: list[str], cwd: Path, timeout: float) -> dict:
                del cwd
                result = {
                    "command": command,
                    "cwd": str(root),
                    "timeout_seconds": timeout,
                    "status": "PASS",
                    "exit_code": 0,
                    "duration_seconds": 0.01,
                    "stdout": "",
                    "stderr": "",
                    "parsed_json": {"checks": []},
                }
                if "--build" in command:
                    result["parsed_json"] = {"checks": [{
                        "group": "build",
                        "name": "image build",
                        "status": "pass",
                        "detail": "cyberarena/example:review",
                    }]}
                elif command[:3] == ["docker", "image", "inspect"]:
                    result["stdout"] = "sha256:" + "a" * 64 + "\n"
                return result

            submodule_result = subprocess.CompletedProcess([], 0, "", "")
            with (
                patch.object(_VERIFIER_MODULE, "git", side_effect=fake_git),
                patch.object(
                    _VERIFIER_MODULE.subprocess, "run", return_value=submodule_result,
                ),
                patch.object(
                    _VERIFIER_MODULE, "command_result", side_effect=fake_command_result,
                ),
            ):
                result = _VERIFIER_MODULE.main([
                    "example", "--context", str(context_path),
                    "--repo-root", str(root), "--output", str(output_path),
                    "--execute",
                ])

            self.assertEqual(result, 0)
            self.assertIn(
                (
                    root,
                    (
                        "worktree", "add", "--detach", str(worktree),
                        ORCHESTRATOR_COMMIT,
                    ),
                ),
                git_calls,
            )
            self.assertFalse(any(args[0] in {"restore", "diff"} for _, args in git_calls))
            payload = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(payload["orchestrator_commit"], ORCHESTRATOR_COMMIT)
            self.assertNotIn("verifier_commit", payload)

    def test_verifier_extracts_the_single_successful_built_image(self) -> None:
        tier_result = {
            "parsed_json": {
                "checks": [
                    {
                        "group": "build",
                        "name": "image build",
                        "status": "pass",
                        "detail": "cyberarena/example:review",
                    },
                ],
            },
        }
        self.assertEqual(
            built_image_reference(tier_result), "cyberarena/example:review",
        )


if __name__ == "__main__":
    unittest.main()
