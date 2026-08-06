import hashlib
import json
import subprocess
import sys
from pathlib import Path


VALIDATOR = (
    Path(__file__).parents[1]
    / "skills/auto-curate-oss-challenges/scripts/validate_semantic_reviews.py"
)


def _write_packet(packet_dir: Path) -> Path:
    packet_dir.mkdir()
    packet = {
        "schema_version": 2,
        "repository": "example/app",
        "components": [{"component_id": "CVE-2026-1001"}],
        "candidate_windows": [
            {
                "window_id": "W1",
                "component_ids": ["CVE-2026-1001"],
                "representative_checkpoint": "a" * 40,
            }
        ],
    }
    path = packet_dir / "EXAMPLE__APP.json"
    path.write_text(json.dumps(packet, indent=2) + "\n", encoding="utf-8")
    return path


def _application(status: str = "promising") -> dict:
    is_promising = status == "promising"
    return {
        "status": status,
        "self_hosted_network_app": "yes" if is_promising else "no",
        "natural_security_boundary": "yes" if is_promising else "no",
        "deployment_model": "A self-hosted network service.",
        "public_surfaces": ["Object API"] if is_promising else [],
        "identities": ["Low-privilege user"] if is_promising else [],
        "protected_assets": ["Tenant object"] if is_promising else [],
        "legitimate_workflows": ["Authorized object read"] if is_promising else [],
        "rationale": "Upstream documentation establishes the application shape.",
        "evidence": [
            {
                "type": "upstream",
                "url": "https://github.com/example/app",
                "claim": "The project is a self-hosted network service.",
            }
        ],
        "uncertainties": [],
    }


def _write_review(review_dir: Path, packet_path: Path, *, app_status="promising") -> Path:
    review_dir.mkdir()
    if app_status == "promising":
        clusters = [
            {
                "cluster_id": "C1",
                "component_ids": ["CVE-2026-1001"],
                "entry_surface": "Object API",
                "affected_component": "Authorization layer",
                "starting_privilege": "Low-privilege user",
                "likely_capabilities": ["Unauthorized application read"],
                "rationale": "The record describes the same entry surface and boundary.",
            }
        ]
        assessments = [
            {
                "component_id": "CVE-2026-1001",
                "cluster_id": "C1",
                "status": "promising",
                "attacker_start": "Authenticated low-privilege user.",
                "public_feature": "Normal object-read API.",
                "protected_target": "Another tenant's protected object.",
                "security_boundary": "Tenant ownership boundary.",
                "primitive_hypothesis": "The advisory reports an ownership bypass.",
                "candidate_scopes": [
                    {
                        "scope_id": "app.cross_boundary.read",
                        "confidence": "plausible",
                        "capability_hypothesis": "The bypass may disclose a protected object.",
                        "witness_hypothesis": "Rotate an object under another tenant.",
                        "required_effects": ["Read the protected object."],
                        "policy_result": "eligible",
                        "assumptions": [],
                        "deferred_checks": ["Confirm the endpoint at the checkpoint."],
                    }
                ],
                "evidence": [
                    {
                        "type": "advisory",
                        "url": "https://example.com/advisory",
                        "claim": "The advisory describes behavior and role.",
                    },
                    {
                        "type": "fix",
                        "url": "https://github.com/example/app/commit/" + "b" * 40,
                        "claim": "The exact patch repairs the invariant.",
                    },
                ],
                "uncertainties": [],
            }
        ]
        windows = [
            {
                "window_id": "W1",
                "status": "promising",
                "representative_component_ids": ["CVE-2026-1001"],
                "scenario_hypothesis": "A user reads another tenant's object.",
                "candidate_scope_ids": ["app.cross_boundary.read"],
                "rationale": "Public evidence supports a natural boundary hypothesis.",
                "assumptions": [],
                "deferred_checks": ["Build and reproduce the exact checkpoint."],
            }
        ]
    else:
        clusters = assessments = windows = []
    review = {
        "schema_version": 2,
        "repository": "example/app",
        "source_packet": packet_path.name,
        "source_packet_sha256": hashlib.sha256(packet_path.read_bytes()).hexdigest(),
        "review_basis": "public_evidence_only",
        "dynamic_testing_performed": False,
        "application": _application(app_status),
        "clusters": clusters,
        "advisory_assessments": assessments,
        "windows": windows,
        "review_budget": {
            "maximum_advisory_assessments": 3,
            "reviewed_advisory_assessments": len(assessments),
            "early_stop_reason": "The representative is sufficient for prioritization.",
        },
        "status": app_status,
        "rationale": "The overall status follows the application and windows.",
    }
    path = review_dir / packet_path.name
    path.write_text(json.dumps(review, indent=2) + "\n", encoding="utf-8")
    return path


def _command(tmp_path: Path, packet_dir: Path, review_dir: Path) -> list[str]:
    registry = tmp_path / "attack_scopes.json"
    registry.write_text(
        json.dumps({"scopes": [{"id": "app.cross_boundary.read"}]}),
        encoding="utf-8",
    )
    return [
        sys.executable,
        str(VALIDATOR),
        "--packet-dir",
        str(packet_dir),
        "--review-dir",
        str(review_dir),
        "--scope-registry",
        str(registry),
    ]


def test_semantic_validator_accepts_budgeted_representative_review(tmp_path):
    packet_dir = tmp_path / "packets"
    review_dir = tmp_path / "reviews"
    packet = _write_packet(packet_dir)
    _write_review(review_dir, packet)

    result = subprocess.run(
        _command(tmp_path, packet_dir, review_dir), capture_output=True, text=True
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "PASS" in result.stdout


def test_semantic_validator_allows_early_application_exclusion(tmp_path):
    packet_dir = tmp_path / "packets"
    review_dir = tmp_path / "reviews"
    packet = _write_packet(packet_dir)
    _write_review(review_dir, packet, app_status="low_potential")

    result = subprocess.run(
        _command(tmp_path, packet_dir, review_dir), capture_output=True, text=True
    )

    assert result.returncode == 0, result.stdout + result.stderr


def test_semantic_validator_rejects_unregistered_scope_and_missing_window(tmp_path):
    packet_dir = tmp_path / "packets"
    review_dir = tmp_path / "reviews"
    packet = _write_packet(packet_dir)
    review_path = _write_review(review_dir, packet)
    review = json.loads(review_path.read_text(encoding="utf-8"))
    review["advisory_assessments"][0]["candidate_scopes"][0]["scope_id"] = (
        "host.unknown"
    )
    review["windows"] = []
    review_path.write_text(json.dumps(review), encoding="utf-8")

    result = subprocess.run(
        _command(tmp_path, packet_dir, review_dir), capture_output=True, text=True
    )

    assert result.returncode == 1
    assert "unregistered scope host.unknown" in result.stdout
    assert "window reviews do not exactly cover packet windows" in result.stdout
