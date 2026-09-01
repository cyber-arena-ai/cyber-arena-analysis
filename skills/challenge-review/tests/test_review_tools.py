from __future__ import annotations

import importlib.util
import json
import os
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


def make_warehouse(root: Path) -> Path:
    warehouse = root / "selected-warehouse"
    (warehouse / "_registry").mkdir(parents=True)
    (warehouse / "_registry" / "index.json").write_text("{}", encoding="utf-8")
    challenge_dir = warehouse / "example" / "package"
    challenge_dir.mkdir(parents=True)
    (challenge_dir / "challenge.py").write_text("# challenge\n", encoding="utf-8")
    return warehouse


def process_result(
    stdout: str, returncode: int = 0, stderr: str = "",
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(
        ["command"], returncode, stdout=stdout, stderr=stderr,
    )


def checker_stdout(*, ok: bool = True, checks: list[dict] | None = None) -> str:
    if checks is None:
        checks = [{
            "group": "import",
            "name": "instantiate",
            "status": "pass" if ok else "fail",
            "detail": "fresh instance" if ok else "failed",
        }]
    return json.dumps({"challenge": "package", "ok": ok, "checks": checks})


def valid_report() -> dict:
    return {
        "schema_version": "5.0",
        "scope": "all",
        "context": {
            "challenge_id": "example",
            "challenge_dir": "example/package",
            "timestamp": "2026-07-13T12:00:00Z",
            "run_id": "20260713T120000Z-a1b2c3d4",
            "orchestrator_commit": ORCHESTRATOR_COMMIT,
            "warehouse_path": "/tmp/selected-warehouse",
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
            text=True, capture_output=True, check=False,
        )

    def run_verifier_main(
        self,
        root: Path,
        command_results: list[subprocess.CompletedProcess[str] | BaseException],
    ) -> tuple[int, dict]:
        repo = root / "orche"
        repo.mkdir()
        warehouse = make_warehouse(root)
        context = valid_report()["context"]
        context.update(
            warehouse_path=str(warehouse),
            run_id=f"verifier-{root.name}",
        )
        context_path = root / "context.json"
        output_path = root / "verifier.json"
        context_path.write_text(json.dumps(context), encoding="utf-8")

        def fake_git(
            repo: Path, *args: str, timeout: float = 180.0,
        ) -> subprocess.CompletedProcess[str]:
            stdout = ORCHESTRATOR_COMMIT if args == ("rev-parse", "HEAD") else ""
            return subprocess.CompletedProcess(
                ["git", "-C", str(repo), *args], 0, stdout=stdout, stderr="",
            )

        with (
            patch.object(_VERIFIER_MODULE, "git", side_effect=fake_git),
            patch.object(
                _VERIFIER_MODULE.subprocess,
                "run",
                side_effect=command_results,
            ),
        ):
            result = _VERIFIER_MODULE.main([
                "example",
                "--warehouse", str(warehouse),
                "--context", str(context_path),
                "--repo-root", str(repo),
                "--output", str(output_path),
                "--execute",
            ])

        return result, json.loads(output_path.read_text(encoding="utf-8"))

    def test_context_collector_routes_output_under_review_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "orche"
            warehouse = make_warehouse(Path(tmp))
            (root / ".git").mkdir(parents=True)
            output = Path(tmp) / "context.json"
            review_root = Path(tmp) / "analysis" / "artifacts" / "review"

            def fake_git(repo: Path, *args: str) -> str:
                if args[0] == "cat-file":
                    return ""
                if args == ("rev-parse", f"{ORCHESTRATOR_COMMIT}^{{commit}}"):
                    return ORCHESTRATOR_COMMIT
                raise AssertionError((repo, args))

            with (
                patch.dict(os.environ, {}, clear=False),
                patch.object(_CONTEXT_MODULE, "registry_package", return_value="package"),
                patch.object(_CONTEXT_MODULE, "git", side_effect=fake_git),
            ):
                result = _CONTEXT_MODULE.main([
                    "example",
                    "--warehouse", str(warehouse),
                    "--repo-root", str(root),
                    "--review-root", str(review_root),
                    "--output", str(output),
                ])

            self.assertEqual(result, 0)
            context = json.loads(output.read_text(encoding="utf-8"))
            expected = review_root / "example" / context["run_id"]
            self.assertEqual(Path(context["recommended_output_dir"]), expected)
            self.assertEqual(context["orchestrator_commit"], ORCHESTRATOR_COMMIT)
            self.assertEqual(context["warehouse_path"], str(warehouse))
            self.assertEqual(context["challenge_dir"], "example/package")

    def test_context_collector_requires_valid_explicit_warehouse(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "orche"
            (root / ".git").mkdir(parents=True)
            cases = ([], ["--warehouse", "relative/path"], [
                "--warehouse", str(Path(tmp) / "missing"),
            ])
            for warehouse_args in cases:
                with self.subTest(warehouse_args=warehouse_args):
                    result = self.run_script(
                        "collect-review-context.py", "example",
                        *warehouse_args,
                        "--repo-root", str(root),
                        "--review-root", str(Path(tmp) / "review"),
                        "--output", str(Path(tmp) / "context.json"),
                    )
                    self.assertNotEqual(result.returncode, 0)

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

    def test_all_scope_missing_required_pov_requires_revision(self) -> None:
        report = valid_report()
        next(
            stage for stage in report["stages"] if stage["stage"] == "exploitability"
        ).update(status="FAIL", summary="No accepted exploit proof.")
        next(
            check for check in report["checks"] if check["check_id"] == "EXPLOIT-ACCEPT"
        ).update(
            status="FAIL",
            summary="No current opponent objective was accepted.",
            evidence=["dynamic: exploit.log:1 — submission was not accepted"],
        )
        report["verdict"] = {
            "value": "REVISE",
            "summary": "The required PoV must produce an accepted outcome.",
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "review.json"
            (root / "exploit.log").write_text(
                "submission was not accepted\n", encoding="utf-8",
            )
            source.write_text(json.dumps(report), encoding="utf-8")
            checked = self.run_script("validate-report.py", str(source))
            self.assertEqual(checked.returncode, 0, checked.stderr)

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

    def test_initializer_uses_compact_v5_shape(self) -> None:
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
            self.assertEqual(report["schema_version"], "5.0")
            self.assertEqual(set(report), {
                "schema_version", "scope", "context", "stages", "checks",
                "findings", "unresolved", "wip_observations", "verdict",
            })
            self.assertEqual(
                [stage["stage"] for stage in report["stages"]],
                ["verifier", "static", "cheat", "exploitability"],
            )

    def test_verifier_dry_run_preserves_canonical_three_tiers(self) -> None:
        context = valid_report()["context"]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            warehouse = make_warehouse(root)
            context["warehouse_path"] = str(warehouse)
            context_path = root / "context.json"
            output_path = root / "verifier.json"
            context_path.write_text(json.dumps(context), encoding="utf-8")
            result = self.run_script(
                "run-verifier.py", "example", "--warehouse", str(warehouse),
                "--context", str(context_path),
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
            self.assertEqual(payload["warehouse_path"], str(warehouse))

            other_warehouse = make_warehouse(root / "other")
            mismatch = self.run_script(
                "run-verifier.py", "example", "--warehouse", str(other_warehouse),
                "--context", str(context_path),
                "--repo-root", str(SKILL_DIR.parents[1]),
                "--output", str(root / "mismatch.json"), "--dry-run",
            )
            self.assertNotEqual(mismatch.returncode, 0)

    def test_verifier_accepts_valid_checker_outputs(self) -> None:
        build = checker_stdout(checks=[{
            "group": "build",
            "name": "image build",
            "status": "pass",
            "detail": "cyberarena/example:review",
        }])
        image_hash = f"sha256:{'a' * 64}"
        with tempfile.TemporaryDirectory() as tmp:
            result, payload = self.run_verifier_main(Path(tmp), [
                process_result(checker_stdout()),
                process_result('"27.0"'),
                process_result(build),
                process_result(image_hash),
                process_result(checker_stdout()),
            ])

        self.assertEqual(result, 0)
        self.assertEqual(payload["status"], "PASS")
        self.assertEqual(payload["image_hash"], image_hash)
        self.assertEqual(
            [tier["status"] for tier in payload["tiers"]],
            ["PASS", "PASS", "PASS"],
        )

    def test_verifier_rejects_malformed_checker_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result, payload = self.run_verifier_main(
                Path(tmp), [process_result("not json")],
            )

        self.assertNotEqual(result, 0)
        self.assertEqual(payload["status"], "FAIL")
        self.assertEqual(payload["tiers"][0]["status"], "FAIL")

    def test_verifier_tier_timeout_is_a_failed_artifact(self) -> None:
        timeout = subprocess.TimeoutExpired(["command"], 1.0)
        with tempfile.TemporaryDirectory() as tmp:
            result, payload = self.run_verifier_main(Path(tmp), [timeout])

        self.assertNotEqual(result, 0)
        self.assertEqual(payload["status"], "FAIL")
        self.assertEqual(payload["tiers"][0]["status"], "FAIL")

    def test_unavailable_docker_blocks_dynamic_tiers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result, payload = self.run_verifier_main(Path(tmp), [
                process_result(checker_stdout()),
                process_result("", returncode=1, stderr="daemon unavailable"),
            ])

        self.assertNotEqual(result, 0)
        self.assertEqual(payload["status"], "BLOCKED")
        self.assertEqual(payload["tiers"][0]["status"], "PASS")
        self.assertEqual(payload["tiers"][1]["status"], "BLOCKED")
        self.assertEqual(payload["tiers"][2]["status"], "NOT_RUN")

    def test_lock_contention_writes_blocked_verifier_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "orche"
            repo.mkdir()
            warehouse = make_warehouse(root)
            context = valid_report()["context"]
            context.update(
                warehouse_path=str(warehouse),
                run_id=f"lock-{root.name}",
            )
            context_path = root / "context.json"
            output_path = root / "verifier.json"
            context_path.write_text(json.dumps(context), encoding="utf-8")
            key = _VERIFIER_MODULE.hashlib.sha256(str(repo).encode()).hexdigest()[:16]
            lock_path = Path("/tmp") / f"cyberarena-challenge-review-{key}.lock"

            try:
                with lock_path.open("a+", encoding="utf-8") as lock:
                    _VERIFIER_MODULE.fcntl.flock(
                        lock,
                        _VERIFIER_MODULE.fcntl.LOCK_EX
                        | _VERIFIER_MODULE.fcntl.LOCK_NB,
                    )
                    result = _VERIFIER_MODULE.main([
                        "example",
                        "--warehouse", str(warehouse),
                        "--context", str(context_path),
                        "--repo-root", str(repo),
                        "--output", str(output_path),
                        "--execute",
                        "--lock-timeout", "0.01",
                    ])
            finally:
                lock_path.unlink(missing_ok=True)

            self.assertNotEqual(result, 0)
            payload = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(payload["status"], "BLOCKED")
            self.assertTrue(payload["error"])

    def test_setup_failure_writes_blocked_verifier_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "orche"
            repo.mkdir()
            warehouse = make_warehouse(root)
            context = valid_report()["context"]
            context.update(
                warehouse_path=str(warehouse),
                run_id=f"setup-{root.name}",
            )
            context_path = root / "context.json"
            output_path = root / "verifier.json"
            context_path.write_text(json.dumps(context), encoding="utf-8")
            failed_git = subprocess.CompletedProcess(
                ["git"], 1, stdout="", stderr="git failed",
            )

            with patch.object(_VERIFIER_MODULE, "git", return_value=failed_git):
                result = _VERIFIER_MODULE.main([
                    "example",
                    "--warehouse", str(warehouse),
                    "--context", str(context_path),
                    "--repo-root", str(repo),
                    "--output", str(output_path),
                    "--execute",
                ])

            self.assertNotEqual(result, 0)
            payload = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(payload["status"], "BLOCKED")
            self.assertTrue(payload["error"])


if __name__ == "__main__":
    unittest.main()
