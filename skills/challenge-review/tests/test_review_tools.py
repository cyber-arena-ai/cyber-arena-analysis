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

from _contracts import CHECKS, SCHEMA_VERSION, STAGE_ORDER  # noqa: E402

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

_PARTICIPANT_TOOL_SPEC = importlib.util.spec_from_file_location(
    "challenge_review_call_participant_tool", SCRIPTS / "call-participant-tool.py",
)
assert _PARTICIPANT_TOOL_SPEC and _PARTICIPANT_TOOL_SPEC.loader
_PARTICIPANT_TOOL_MODULE = importlib.util.module_from_spec(_PARTICIPANT_TOOL_SPEC)
_PARTICIPANT_TOOL_SPEC.loader.exec_module(_PARTICIPANT_TOOL_MODULE)


def check_evidence(check_id: str, stage: str) -> str:
    if stage == "static":
        if check_id == "STATIC-FLAG":
            return (
                "source: warehouse:example/package/challenge.py:20 — "
                "store=default; outcome=read; scope=app.cross_boundary.read; "
                "oracle=submit; declaration and scoring path agree"
            )
        return "source: warehouse:example/package/challenge.py:10 — behavior is wired"
    if stage == "verifier":
        tier = {
            "VERIFY-INTERFACE": 0,
            "VERIFY-BUILD": 1,
            "VERIFY-HEALTH": 2,
            "VERIFY-ORACLES": 2,
            "VERIFY-RESTART": 1,
        }[check_id]
        return f"verifier: verifier.json#/tiers/{tier}/status — canonical tier passed"
    if stage == "cheat":
        return f"dynamic: cheat.log:1 — {check_id} control produced the required result"
    if check_id == "EXPLOIT-ACCEPT":
        return "dynamic: events.jsonl:1 — current opponent objective was accepted"
    return f"dynamic: exploit.log:1 — {check_id} was observed in band"


def report_evidence(check_id: str, stage: str) -> list[str]:
    evidence = [check_evidence(check_id, stage)]
    if check_id == "VERIFY-ORACLES":
        evidence.insert(
            0,
            "verifier: verifier.json#/tiers/1/status — handler round-trip passed",
        )
    return evidence


IMAGE_HASH = f"sha256:{'a' * 64}"
TEST_ORCHESTRATOR_COMMIT = "a" * 40
OBJECTIVES = [{
    "store": "default",
    "outcome": "read",
    "scope": "app.cross_boundary.read",
    "oracle": "submit",
}]


def accepted_event(**payload_overrides: object) -> dict:
    payload = {
        "accepted": True,
        "reason": "ACCEPTED",
        "submitter_team_id": "team1",
        "victim_team_id": "team2",
        "service": "example",
        "store": "default",
        "phase": "ATTACK",
        "outcome": "read",
        "scope": "app.cross_boundary.read",
        "oracle": "submit",
    }
    payload.update(payload_overrides)
    return {
        "id": "event-1",
        "ts": 1.0,
        "type": "FLAG_SUBMITTED",
        "team_id": payload["submitter_team_id"],
        "round_id": 1,
        "phase": payload["phase"],
        "payload": payload,
    }


def make_warehouse(root: Path) -> Path:
    warehouse = root / "selected-warehouse"
    (warehouse / "_registry").mkdir(parents=True)
    (warehouse / "_registry" / "index.json").write_text("{}", encoding="utf-8")
    challenge_dir = warehouse / "example" / "package"
    challenge_dir.mkdir(parents=True)
    (challenge_dir / "challenge.py").write_text("# challenge\n", encoding="utf-8")
    return warehouse


def make_fake_orchestrator(root: Path) -> Path:
    repo = root / "orche"
    for package in (
        "challenges", "challenges/check", "gamemgr", "orchestrator",
    ):
        path = repo / package
        path.mkdir(parents=True, exist_ok=True)
        (path / "__init__.py").write_text("", encoding="utf-8")
    (repo / "main.py").write_text("# fake orchestrator\n", encoding="utf-8")
    (repo / "challenges" / "check" / "docker_env.py").write_text(
        "def free_ports(count):\n"
        "    return [8100, 9100, 9200, 9300][:count]\n",
        encoding="utf-8",
    )
    (repo / "challenges" / "check" / "resolve.py").write_text(
        "def resolve_challenge(target):\n"
        "    return target, object(), ''\n",
        encoding="utf-8",
    )
    (repo / "challenges" / "check" / "game_phase.py").write_text(
        "import json\n"
        "def _free_subnet_octet(namespace):\n"
        "    return 150\n"
        "def build_game_config(name, challenge, *, api_port, flag_port, "
        "health_port, subnet_octet, mode='async'):\n"
        "    return {\n"
        "        'teams': [\n"
        "            {'id': 'team1', 'token': 'team1-token', "
        "'agent': {'provider': 'script', 'cli': 'old'}},\n"
        "            {'id': 'team2', 'token': 'team2-token', "
        "'agent': {'provider': 'script', 'cli': 'old'}},\n"
        "        ],\n"
        "        'nodes': [],\n"
        "        'networks': {},\n"
        "        'challenges': [{'name': name, 'type': name, 'port': 80, "
        "'deploy_on': ['team1', 'team2']}],\n"
        "        'round_config': {},\n"
        "    }\n"
        "def yaml_dump(config):\n"
        "    return json.dumps(config)\n",
        encoding="utf-8",
    )
    (repo / "gamemgr" / "config.py").write_text(
        "import json, os\n"
        "from types import SimpleNamespace\n"
        "def load(path, env_file=None):\n"
        "    raw = json.load(open(path))\n"
        "    challenges = [SimpleNamespace(\n"
        "        name=item['name'],\n"
        "        level='easy' if os.environ.get('FAKE_DROP_LEVEL') else "
        "item.get('level', 'easy'),\n"
        "    ) for item in raw['challenges']]\n"
        "    return SimpleNamespace(\n"
        "        challenges=challenges,\n"
        "        topology=SimpleNamespace(teams=raw['teams']),\n"
        "        mcp_gateway=SimpleNamespace(**raw.get('mcp_gateway', {})),\n"
        "    )\n",
        encoding="utf-8",
    )
    (repo / "orchestrator" / "naming.py").write_text(
        "def qualify(name, namespace=''):\n"
        "    return f'{namespace}-{name}' if namespace else name\n",
        encoding="utf-8",
    )
    return repo


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
        "schema_version": SCHEMA_VERSION,
        "scope": "all",
        "context": {
            "challenge_id": "example",
            "challenge_dir": "example/package",
            "timestamp": "2026-07-13T12:00:00Z",
            "run_id": "20260713T120000Z-a1b2c3d4",
            "orchestrator_commit": TEST_ORCHESTRATOR_COMMIT,
            "warehouse_path": "/tmp/selected-warehouse",
            "image_hash": IMAGE_HASH,
        },
        "objectives": [dict(item) for item in OBJECTIVES],
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
                "evidence": report_evidence(check_id, stage),
                "next_check": None,
            }
            for check_id, stage in CHECKS
        ],
        "findings": [],
        "unresolved": [],
        "wip_observations": [],
        "verdict": {"value": "ACCEPT", "summary": "All four stages passed."},
    }


def static_report() -> dict:
    report = valid_report()
    report["scope"] = "static"
    report["context"]["image_hash"] = None
    report["checks"] = [item for item in report["checks"] if item["stage"] == "static"]
    for stage in report["stages"]:
        if stage["stage"] != "static":
            stage.update(status="NOT_RUN", summary="Outside selected scope.")
    report["verdict"] = {"value": "PARTIAL", "summary": "Static-only review."}
    return report


class ReviewToolTests(unittest.TestCase):
    def run_script(self, name: str, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(SCRIPTS / name), *args],
            text=True, capture_output=True, check=False,
        )

    def verifier_payload(self, report: dict) -> dict:
        status = next(
            item["status"] for item in report["stages"]
            if item["stage"] == "verifier"
        )
        passed = json.loads(checker_stdout())
        failed = json.loads(checker_stdout(ok=False))
        if status == "PASS":
            tier_statuses = ["PASS", "PASS", "PASS"]
            parsed = [passed, passed, passed]
            objectives = report["objectives"]
            error = None
        elif status == "FAIL":
            tier_statuses = ["FAIL", "NOT_RUN", "NOT_RUN"]
            parsed = [failed, None, None]
            objectives = None
            error = None
        else:
            tier_statuses = ["PASS", "BLOCKED", "NOT_RUN"]
            parsed = [passed, None, None]
            objectives = report["objectives"]
            error = "Docker infrastructure unavailable"
        return {
            "mode": "execute",
            "challenge_id": report["context"]["challenge_id"],
            "run_id": report["context"]["run_id"],
            "orchestrator_commit": report["context"]["orchestrator_commit"],
            "warehouse_path": report["context"]["warehouse_path"],
            "image_hash": report["context"]["image_hash"],
            "objectives": objectives,
            "status": status,
            "tiers": [
                {"name": name, "status": tier_status, "parsed_json": parsed_json}
                for name, tier_status, parsed_json in zip(
                    ("static", "build", "game"), tier_statuses, parsed, strict=True,
                )
            ],
            "error": error,
        }

    def write_artifacts(
        self,
        root: Path,
        report: dict,
        *,
        include_acceptance: bool = True,
        event: dict | None = None,
        verifier: dict | None = None,
    ) -> None:
        (root / "cheat.log").write_text("control completed\n", encoding="utf-8")
        (root / "exploit.log").write_text("PoV completed\n", encoding="utf-8")
        if include_acceptance:
            (root / "events.jsonl").write_text(
                json.dumps(event or accepted_event()) + "\n", encoding="utf-8",
            )
        if any(item["stage"] == "verifier" for item in report["checks"]):
            (root / "verifier.json").write_text(
                json.dumps(verifier or self.verifier_payload(report)), encoding="utf-8",
            )

    def run_verifier_main(
        self,
        root: Path,
        command_results: list[subprocess.CompletedProcess[str] | BaseException],
        *,
        orchestrator_head: str = TEST_ORCHESTRATOR_COMMIT,
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
            stdout = (
                orchestrator_head
                if args == ("rev-parse", "HEAD") else ""
            )
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
            (root / "challenges" / "check").mkdir(parents=True)
            (root / "challenges" / "check" / "__main__.py").write_text(
                "", encoding="utf-8",
            )
            output = Path(tmp) / "context.json"
            review_root = Path(tmp) / "analysis" / "artifacts" / "review"

            def fake_git(repo: Path, *args: str) -> str:
                if args == ("rev-parse", "HEAD"):
                    return TEST_ORCHESTRATOR_COMMIT
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
            self.assertEqual(
                context["orchestrator_commit"], TEST_ORCHESTRATOR_COMMIT,
            )
            self.assertEqual(context["warehouse_path"], str(warehouse))
            self.assertEqual(context["challenge_dir"], "example/package")
            self.assertIsNone(context["image_hash"])

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

    def test_cheat_game_helper_builds_hard_long_running_participant_game(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = make_fake_orchestrator(root)
            warehouse = make_warehouse(root)
            output = root / "review" / "game.yaml"
            runtime_output = root / "review" / "runtime.json"

            result = self.run_script(
                "prepare-cheat-game.py", "example",
                "--warehouse", str(warehouse),
                "--repo-root", str(repo),
                "--namespace", "review-example",
                "--output", str(output),
                "--runtime-output", str(runtime_output),
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            config = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(config["challenges"][0]["level"], "hard")
            self.assertEqual(config["round_config"], {
                "mode": "async", "round_secs": 86400, "total_rounds": 1,
            })
            self.assertEqual(
                [team["agent"] for team in config["teams"]],
                [
                    {"provider": "script", "cli": "exec sleep 86400"},
                    {"provider": "script", "cli": "exec sleep 86400"},
                ],
            )
            self.assertEqual(config["mcp_gateway"]["agent_url"],
                             "http://mcp-gateway:8080")
            self.assertIn("mcp-gateway", [node["id"] for node in config["nodes"]])

            runtime = json.loads(runtime_output.read_text(encoding="utf-8"))
            self.assertEqual(runtime["config_path"], str(output))
            self.assertEqual(runtime["namespace"], "review-example")
            self.assertEqual(runtime["host_port"], 8100)
            self.assertEqual(
                runtime["participant_mcp_url"], "http://127.0.0.1:9300/mcp/",
            )
            self.assertEqual(
                runtime["participant_shells"]["team1"][3],
                "review-example-team1_dev",
            )
            self.assertEqual(runtime["start_command"][0], sys.executable)
            self.assertEqual(runtime["start_command"][1], str(repo / "main.py"))
            self.assertEqual(
                runtime["participant_tool_commands"]["team1"][0], sys.executable,
            )

    def test_participant_tool_helper_uses_selected_team_gateway_identity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            runtime_path = Path(tmp) / "runtime.json"
            runtime_path.write_text(json.dumps({
                "participant_mcp_url": "http://127.0.0.1:9300/mcp/",
                "participant_tokens": {
                    "team1": "team-one-token", "team2": "team-two-token",
                },
            }), encoding="utf-8")

            with patch.object(
                _PARTICIPANT_TOOL_MODULE, "call_tool",
                return_value={"content": [{"type": "text", "text": "ok"}]},
            ) as call:
                result = _PARTICIPANT_TOOL_MODULE.main([
                    "restart_service",
                    "--runtime", str(runtime_path),
                    "--team", "team2",
                    "--arguments", '{"service":"example"}',
                ])

            self.assertEqual(result, 0)
            call.assert_awaited_once_with(
                "http://127.0.0.1:9300/mcp/",
                "team-two-token",
                "restart_service",
                {"service": "example"},
            )

    def test_cheat_game_helper_rejects_orchestrator_that_drops_hard_mode(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = make_fake_orchestrator(root)
            warehouse = make_warehouse(root)
            output = root / "review" / "game.yaml"
            runtime_output = root / "review" / "runtime.json"
            env = {**os.environ, "FAKE_DROP_LEVEL": "1"}

            result = subprocess.run(
                [
                    sys.executable, str(SCRIPTS / "prepare-cheat-game.py"), "example",
                    "--warehouse", str(warehouse),
                    "--repo-root", str(repo),
                    "--namespace", "review-example",
                    "--output", str(output),
                    "--runtime-output", str(runtime_output),
                ],
                text=True, capture_output=True, check=False, env=env,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("did not preserve challenge level 'hard'", result.stderr)
            self.assertFalse(runtime_output.exists())

    def test_review_tools_require_absolute_orchestrator_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            warehouse = make_warehouse(root)
            cases = (
                (
                    "collect-review-context.py",
                    [
                        "--review-root", str(root / "reviews"),
                        "--output", str(root / "context.json"),
                    ],
                ),
                (
                    "run-verifier.py",
                    [
                        "--context", str(root / "context.json"),
                        "--output", str(root / "verifier.json"),
                        "--execute",
                    ],
                ),
            )
            for script, extra in cases:
                with self.subTest(script=script):
                    result = self.run_script(
                        script, "example",
                        "--warehouse", str(warehouse),
                        "--repo-root", "relative/orche",
                        *extra,
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("--repo-root must be absolute", result.stderr)

    def test_valid_report_validates_and_renders_compact_markdown(self) -> None:
        report = valid_report()
        report["findings"] = [{
            "finding_id": "F-001",
            "stage": "static",
            "severity": "LOW",
            "antipattern_id": "UNCLASSIFIED",
            "title": "Minor actionable issue",
            "evidence": ["source: warehouse:example/package/challenge.py:10 — issue exists"],
            "impact": "Limited benchmark impact.",
            "required_action": "Clarify the implementation.",
            "verdict_effect": "NONE",
        }]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "review.json"
            output = root / "review.md"
            self.write_artifacts(root, report)
            source.write_text(json.dumps(report), encoding="utf-8")

            checked = self.run_script("validate-report.py", str(source))
            self.assertEqual(checked.returncode, 0, checked.stderr)
            rendered = self.run_script(
                "render-report.py", str(source), "--output", str(output),
            )
            self.assertEqual(rendered.returncode, 0, rendered.stderr)
            text = output.read_text(encoding="utf-8")
            self.assertIn("**ACCEPT**", text)
            self.assertIn("[PASS] `STATIC-PACKAGE`", text)
            self.assertIn(check_evidence("STATIC-PACKAGE", "static"), text)
            self.assertIn("F-001", text)

    def test_validator_rejects_not_applicable_check_status(self) -> None:
        report = valid_report()
        report["checks"][0].update(status="NOT_APPLICABLE", evidence=[])
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write_artifacts(root, report)
            source = root / "review.json"
            source.write_text(json.dumps(report), encoding="utf-8")
            checked = self.run_script("validate-report.py", str(source))

        self.assertNotEqual(checked.returncode, 0)
        self.assertIn("unknown status 'NOT_APPLICABLE'", checked.stderr)

    def test_validator_rejects_selected_stage_left_not_run(self) -> None:
        report = static_report()
        next(
            stage for stage in report["stages"] if stage["stage"] == "static"
        ).update(status="NOT_RUN", summary="Static review was not run.")
        for check in report["checks"]:
            check.update(status="NOT_RUN", evidence=[])
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write_artifacts(root, report, include_acceptance=False)
            source = root / "review.json"
            source.write_text(json.dumps(report), encoding="utf-8")
            checked = self.run_script("validate-report.py", str(source))

        self.assertNotEqual(checked.returncode, 0)
        self.assertIn("selected stage must run", checked.stderr)

    def test_static_pass_may_retain_runtime_unknown(self) -> None:
        report = static_report()
        check = next(item for item in report["checks"] if item["check_id"] == "STATIC-BUILD")
        check.update(
            status="UNKNOWN",
            next_check="Run VERIFY-BUILD against the selected warehouse.",
        )
        report["unresolved"] = [{
            "concern_id": "U-001",
            "stage": "static",
            "check_id": "STATIC-BUILD",
            "concern": "Runtime build behavior remains undecided.",
            "evidence": check["evidence"],
            "resolving_check": "Run VERIFY-BUILD against the selected warehouse.",
            "owner_stage": "verifier",
        }]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write_artifacts(root, report, include_acceptance=False)
            source = root / "review.json"
            source.write_text(json.dumps(report), encoding="utf-8")
            checked = self.run_script("validate-report.py", str(source))

        self.assertEqual(checked.returncode, 0, checked.stderr)

    def test_static_flag_pass_requires_evidence_for_every_objective(self) -> None:
        report = static_report()
        report["objectives"].append({
            "store": "profile",
            "outcome": "write",
            "scope": "app.cross_boundary.write",
            "oracle": "claim",
        })
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write_artifacts(root, report, include_acceptance=False)
            source = root / "review.json"
            source.write_text(json.dumps(report), encoding="utf-8")
            checked = self.run_script("validate-report.py", str(source))

        self.assertNotEqual(checked.returncode, 0)
        self.assertIn("missing per-store evidence for ['profile']", checked.stderr)

    def test_static_flag_evidence_must_match_the_full_objective_row(self) -> None:
        report = static_report()
        report["objectives"][0].update(
            outcome="write", scope="app.cross_boundary.write", oracle="claim",
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write_artifacts(root, report, include_acceptance=False)
            source = root / "review.json"
            source.write_text(json.dumps(report), encoding="utf-8")
            checked = self.run_script("validate-report.py", str(source))

        self.assertNotEqual(checked.returncode, 0)
        self.assertIn("missing per-store evidence for ['default']", checked.stderr)

    def test_exploit_accept_requires_matching_authoritative_event(self) -> None:
        cases = {
            "negated-prose": "submission was not accepted",
            "rejected": accepted_event(accepted=False, reason="UNKNOWN"),
            "own-team": accepted_event(victim_team_id="team1"),
            "wrong-scope": accepted_event(scope="host.file.read"),
            "malformed-scope": accepted_event(scope={"name": "not-a-string"}),
        }
        for name, event in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                report = valid_report()
                root = Path(tmp)
                self.write_artifacts(
                    root, report,
                    event=event if isinstance(event, dict) else accepted_event(),
                )
                if isinstance(event, str):
                    (root / "events.jsonl").write_text(event + "\n", encoding="utf-8")
                source = root / "review.json"
                source.write_text(json.dumps(report), encoding="utf-8")
                checked = self.run_script("validate-report.py", str(source))

                self.assertNotEqual(checked.returncode, 0)
                self.assertIn("accepted FLAG_SUBMITTED evidence", checked.stderr)

    def test_exploit_accept_allows_any_confined_raw_event_artifact(self) -> None:
        report = valid_report()
        accept = next(
            item for item in report["checks"] if item["check_id"] == "EXPLOIT-ACCEPT"
        )
        accept["evidence"] = [
            "dynamic: pov-events.jsonl:1 — current opponent objective was accepted",
        ]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write_artifacts(root, report)
            (root / "pov-events.jsonl").write_text(
                json.dumps(accepted_event()) + "\n", encoding="utf-8",
            )
            source = root / "review.json"
            source.write_text(json.dumps(report), encoding="utf-8")
            checked = self.run_script("validate-report.py", str(source))

        self.assertEqual(checked.returncode, 0, checked.stderr)

    def test_validator_binds_verifier_artifact_and_json_pointer(self) -> None:
        mutations = {
            "challenge": lambda artifact: artifact.update(challenge_id="other"),
            "run": lambda artifact: artifact.update(run_id="different-run"),
            "dry-run": lambda artifact: artifact.update(mode="dry-run"),
            "image": lambda artifact: artifact.update(image_hash=f"sha256:{'b' * 64}"),
            "tier": lambda artifact: artifact["tiers"][2].update(status="FAIL"),
            "objectives": lambda artifact: artifact["objectives"][0].update(
                scope="host.file.read"
            ),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                report = valid_report()
                artifact = self.verifier_payload(report)
                mutate(artifact)
                root = Path(tmp)
                self.write_artifacts(root, report, verifier=artifact)
                source = root / "review.json"
                source.write_text(json.dumps(report), encoding="utf-8")
                checked = self.run_script("validate-report.py", str(source))

                self.assertNotEqual(checked.returncode, 0)

        report = valid_report()
        report["checks"][0]["evidence"] = [
            "verifier: verifier.json#/tiers/99/status — nonexistent tier passed",
        ]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write_artifacts(root, report)
            source = root / "review.json"
            source.write_text(json.dumps(report), encoding="utf-8")
            checked = self.run_script("validate-report.py", str(source))

        self.assertNotEqual(checked.returncode, 0)
        self.assertIn("must resolve a JSON Pointer", checked.stderr)

        report = valid_report()
        build = next(
            item for item in report["checks"] if item["check_id"] == "VERIFY-BUILD"
        )
        build["evidence"] = [
            "verifier: verifier.json#/tiers/0/status — wrong tier also passed",
        ]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write_artifacts(root, report)
            source = root / "review.json"
            source.write_text(json.dumps(report), encoding="utf-8")
            checked = self.run_script("validate-report.py", str(source))

        self.assertNotEqual(checked.returncode, 0)
        self.assertIn("this check's matching tier status", checked.stderr)

        report = valid_report()
        oracles = next(
            item for item in report["checks"] if item["check_id"] == "VERIFY-ORACLES"
        )
        oracles["evidence"] = oracles["evidence"][:1]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write_artifacts(root, report)
            source = root / "review.json"
            source.write_text(json.dumps(report), encoding="utf-8")
            checked = self.run_script("validate-report.py", str(source))

        self.assertNotEqual(checked.returncode, 0)
        self.assertIn("this check's matching tier status", checked.stderr)

    def test_validator_requires_verifier_artifact(self) -> None:
        report = valid_report()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write_artifacts(root, report)
            (root / "verifier.json").unlink()
            source = root / "review.json"
            source.write_text(json.dumps(report), encoding="utf-8")
            checked = self.run_script("validate-report.py", str(source))

        self.assertNotEqual(checked.returncode, 0)
        self.assertIn("verifier.json", checked.stderr)

    def test_validator_rejects_artifact_symlink_outside_run_directory(self) -> None:
        report = valid_report()
        with (
            tempfile.TemporaryDirectory() as tmp,
            tempfile.TemporaryDirectory() as outside_tmp,
        ):
            root = Path(tmp)
            outside = Path(outside_tmp) / "events.jsonl"
            outside.write_text(json.dumps(accepted_event()) + "\n", encoding="utf-8")
            self.write_artifacts(root, report)
            (root / "events.jsonl").unlink()
            (root / "events.jsonl").symlink_to(outside)
            source = root / "review.json"
            source.write_text(json.dumps(report), encoding="utf-8")
            checked = self.run_script("validate-report.py", str(source))

        self.assertNotEqual(checked.returncode, 0)
        self.assertIn("run-relative artifact line", checked.stderr)

    def test_validator_rejects_runtime_evidence_in_static_check(self) -> None:
        report = valid_report()
        static_check = next(item for item in report["checks"] if item["stage"] == "static")
        static_check["evidence"] = [
            "dynamic: cheat.log:1 — runtime behavior appeared correct",
        ]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write_artifacts(root, report)
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
            "verifier: verifier.json#/tiers/2/status — submission wiring was exercised",
        ]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write_artifacts(root, report)
            source = root / "review.json"
            source.write_text(json.dumps(report), encoding="utf-8")
            checked = self.run_script("validate-report.py", str(source))
            self.assertNotEqual(checked.returncode, 0)
            self.assertIn("accepted FLAG_SUBMITTED evidence", checked.stderr)

    def test_validator_rejects_missing_acceptance_artifact(self) -> None:
        report = valid_report()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write_artifacts(root, report, include_acceptance=False)
            source = root / "review.json"
            source.write_text(json.dumps(report), encoding="utf-8")
            checked = self.run_script("validate-report.py", str(source))
            self.assertNotEqual(checked.returncode, 0)
            self.assertIn("accepted FLAG_SUBMITTED evidence", checked.stderr)

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
                    evidence=[
                        "verifier: verifier.json#/tiers/0/status — interface tier failed"
                    ],
                )
            else:
                check.update(
                    status="NOT_RUN", summary="Skipped after verifier failure.", evidence=[],
                )
        report["verdict"] = {
            "value": "REJECT", "summary": "The verifier gate failed.",
        }
        report["context"]["image_hash"] = None
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write_artifacts(root, report, include_acceptance=False)
            source = root / "review.json"
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
            self.write_artifacts(root, report, include_acceptance=False)
            (root / "exploit.log").write_text("submission was not accepted\n", encoding="utf-8")
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
        report["context"]["image_hash"] = None
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write_artifacts(root, report, include_acceptance=False)
            source = root / "review.json"
            source.write_text(json.dumps(report), encoding="utf-8")
            checked = self.run_script("validate-report.py", str(source))
            self.assertEqual(checked.returncode, 0, checked.stderr)

    def test_renderer_preserves_failed_status_and_check_evidence(self) -> None:
        report = valid_report()
        failed = next(item for item in report["checks"] if item["check_id"] == "STATIC-BUILD")
        failed.update(
            status="FAIL",
            summary="Build provenance is missing; see F-001.",
            evidence=["source: warehouse:example/package/image/Dockerfile:1 — base image is mutable"],
        )
        next(item for item in report["stages"] if item["stage"] == "static")["status"] = "FAIL"
        report["findings"] = [{
            "finding_id": "F-001",
            "stage": "static",
            "severity": "MEDIUM",
            "antipattern_id": "AP-VERSION-UNPINNED",
            "title": "Build input is mutable",
            "evidence": ["source: warehouse:example/package/image/Dockerfile:1 — base image is mutable"],
            "impact": "Rebuild behavior can drift.",
            "required_action": "Pin the behavior-changing build input.",
            "verdict_effect": "REVISE",
        }]
        report["verdict"] = {"value": "REVISE", "summary": "Build input must be pinned."}
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write_artifacts(root, report)
            source = root / "review.json"
            output = root / "review.md"
            source.write_text(json.dumps(report), encoding="utf-8")
            rendered = self.run_script(
                "render-report.py", str(source), "--output", str(output),
            )
            self.assertEqual(rendered.returncode, 0, rendered.stderr)
            text = output.read_text(encoding="utf-8")
            self.assertIn("[FAIL] `STATIC-BUILD`", text)
            self.assertIn("source: warehouse:example/package/image/Dockerfile:1", text)

    def test_renderer_preserves_literal_not_run_status(self) -> None:
        report = static_report()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "review.json"
            output = root / "review.md"
            source.write_text(json.dumps(report), encoding="utf-8")
            rendered = self.run_script(
                "render-report.py", str(source), "--output", str(output),
            )
            self.assertEqual(rendered.returncode, 0, rendered.stderr)
            self.assertIn(
                "[NOT_RUN] **verifier**", output.read_text(encoding="utf-8"),
            )

    def test_validator_rejects_verdict_contradiction(self) -> None:
        report = valid_report()
        report["findings"] = [{
            "finding_id": "F-001",
            "stage": "static",
            "severity": "HIGH",
            "antipattern_id": "AP-VULN-DEAD",
            "title": "Vulnerability is absent",
            "evidence": ["source: warehouse:example/package/challenge.py:20 — vulnerable operation is absent"],
            "impact": "The intended benchmark cannot be exercised.",
            "required_action": "Ship the intended vulnerable implementation.",
            "verdict_effect": "REJECT",
        }]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write_artifacts(root, report)
            source = root / "review.json"
            source.write_text(json.dumps(report), encoding="utf-8")
            checked = self.run_script("validate-report.py", str(source))
            self.assertNotEqual(checked.returncode, 0)
            self.assertIn("expected REJECT", checked.stderr)

    def test_validator_rejects_malformed_orchestrator_commit(self) -> None:
        report = valid_report()
        report["context"]["orchestrator_commit"] = "not-a-commit"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write_artifacts(root, report)
            source = root / "review.json"
            source.write_text(json.dumps(report), encoding="utf-8")
            checked = self.run_script("validate-report.py", str(source))
            self.assertNotEqual(checked.returncode, 0)
            self.assertIn("expected 40-character lowercase commit", checked.stderr)

    def test_unknown_check_requires_matching_unresolved_concern(self) -> None:
        report = valid_report()
        report["scope"] = "static"
        report["context"]["image_hash"] = None
        report["verdict"] = {"value": "PARTIAL", "summary": "Static-only review."}
        for stage in report["stages"]:
            if stage["stage"] != "static":
                stage.update(status="NOT_RUN", summary="Outside selected scope.")
        report["checks"] = [item for item in report["checks"] if item["stage"] == "static"]
        report["checks"][0].update(status="UNKNOWN", next_check=None)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write_artifacts(root, report)
            source = root / "review.json"
            source.write_text(json.dumps(report), encoding="utf-8")
            checked = self.run_script("validate-report.py", str(source))
            self.assertNotEqual(checked.returncode, 0)
            self.assertIn("UNKNOWN requires next_check", checked.stderr)

    def test_unresolved_concern_requires_matching_unknown_check(self) -> None:
        report = static_report()
        report["unresolved"] = [{
            "concern_id": "U-001",
            "stage": "static",
            "check_id": "STATIC-BUILD",
            "concern": "Runtime build behavior remains undecided.",
            "evidence": [
                "source: warehouse:example/package/challenge.py:10 — "
                "runtime build behavior is not established"
            ],
            "resolving_check": "Run VERIFY-BUILD.",
            "owner_stage": "verifier",
        }]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write_artifacts(root, report, include_acceptance=False)
            source = root / "review.json"
            source.write_text(json.dumps(report), encoding="utf-8")
            checked = self.run_script("validate-report.py", str(source))

        self.assertNotEqual(checked.returncode, 0)
        self.assertIn("unresolved check must be UNKNOWN", checked.stderr)

    def test_initializer_uses_compact_report_shape(self) -> None:
        context = valid_report()["context"]
        context["image_hash"] = None
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
            self.assertEqual(report["schema_version"], SCHEMA_VERSION)
            self.assertEqual(set(report), {
                "schema_version", "scope", "context", "objectives", "stages",
                "checks", "findings", "unresolved", "wip_observations", "verdict",
            })
            self.assertEqual(report["objectives"], [])
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
            self.assertEqual(payload["run_id"], context["run_id"])

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
            root = Path(tmp)
            result, payload = self.run_verifier_main(root, [
                process_result(checker_stdout()),
                process_result(json.dumps(OBJECTIVES)),
                process_result('"27.0"'),
                process_result(build),
                process_result(image_hash),
                process_result(checker_stdout()),
            ])

        self.assertEqual(result, 0)
        self.assertEqual(payload["status"], "PASS")
        self.assertEqual(payload["image_hash"], image_hash)
        self.assertEqual(payload["objectives"], OBJECTIVES)
        self.assertTrue(all(
            Path(tier["cwd"]) == root / "orche" for tier in payload["tiers"]
        ))
        self.assertEqual(
            [tier["status"] for tier in payload["tiers"]],
            ["PASS", "PASS", "PASS"],
        )

    def test_verifier_rejects_changed_orchestrator_checkout(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result, payload = self.run_verifier_main(
                Path(tmp), [], orchestrator_head="1" * 40,
            )

        self.assertNotEqual(result, 0)
        self.assertEqual(payload["status"], "BLOCKED")
        self.assertIn("HEAD changed", payload["error"])

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
                process_result(json.dumps(OBJECTIVES)),
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
