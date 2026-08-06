import json
import subprocess
import sys
from pathlib import Path


VALIDATOR = (
    Path(__file__).parents[1]
    / "skills/auto-curate-oss-challenges/scripts/validate_dossiers.py"
)
REGISTRY = Path(__file__).parents[1] / "docs/attack_scopes.json"


def _write_inputs(tmp_path: Path, *, scope: str = "host.file.read") -> tuple[Path, Path]:
    registry = tmp_path / "attack_scopes.json"
    registry.write_text(
        json.dumps({"scopes": [{"id": "host.file.read", "tier": 1}]}),
        encoding="utf-8",
    )
    dossier = tmp_path / "POTENTIAL_CHALLENGE_EXAMPLE.md"
    dossier.write_text(
        "\n".join(
            [
                "# Example",
                "",
                "> Maintainer-only research dossier. Keep out of agent/researcher prompts and challenge workspaces.",
                "",
                "## Why it is a good candidate",
                "",
                "Deep application boundary.",
                "",
                "## Proposed scenario",
                "",
                "> The attacker begins as a user. The target is protected data. Defenders must preserve normal reads. The task does not grant administrator access.",
                "",
                "## Candidate windows",
                "",
                "| Priority | Checkpoint | Reported advisory components | Scenario potential | Deferred checks |",
                "| ---: | --- | --- | --- | --- |",
                "| 1 | [`aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`](https://github.com/example/example/commit/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa) | `CVE-2026-1234` | promising | Reproduce at the exact checkpoint. |",
                "",
                "## Historical vulnerability-to-scope probes",
                "",
                "| ID | Evidence | Scope | Status |",
                "| --- | --- | --- | --- |",
                f"| V0 | [CVE-2026-1234](https://www.cve.org/CVERecord?id=CVE-2026-1234) | `{scope}` | candidate; PoC pending |",
                "",
                "## Provisional multiflag capability envelope",
                "",
                "| Tier | Store | Proof | Rotation | Scope | Status |",
                "| ---: | --- | --- | --- | --- | --- |",
                f"| 1 | `protected_file` | Unauthorized read. | Rotate path and flag. | `{scope}` | candidate |",
                "",
            ]
        ),
        encoding="utf-8",
    )
    return registry, dossier


def test_validator_accepts_a_complete_dossier_and_rejects_unknown_scopes(tmp_path):
    registry, dossier = _write_inputs(tmp_path)
    command = [sys.executable, str(VALIDATOR), "--scope-registry", str(registry), str(dossier)]

    accepted = subprocess.run(command, capture_output=True, text=True)
    assert accepted.returncode == 0, accepted.stdout + accepted.stderr

    registry, dossier = _write_inputs(tmp_path, scope="host.unknown")
    rejected = subprocess.run(command, capture_output=True, text=True)
    assert rejected.returncode == 1
    assert "unregistered scope `host.unknown`" in rejected.stdout


def test_scope_registry_defines_positive_dimensions_and_disallowed_outcomes():
    payload = json.loads(REGISTRY.read_text(encoding="utf-8"))

    assert payload["schema_version"] == 2
    assert {
        item["id"] for item in payload["policy"]["disallowed_success_conditions"]
    } == {
        "availability.process_crash",
        "availability.resource_exhaustion",
        "availability.health_failure",
        "arena.control_plane_access",
    }
    assert all(
        {"effect", "target", "boundary", "non_examples"}.issubset(scope)
        and scope["non_examples"]
        for scope in payload["scopes"]
    )
