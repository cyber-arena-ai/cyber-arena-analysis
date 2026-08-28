import hashlib
import json
import subprocess
import sys
from pathlib import Path


VALIDATOR = Path(__file__).resolve().parents[1] / "scripts/validate_semantic_reviews.py"


def _write_packet(packet_dir: Path) -> Path:
    packet_dir.mkdir()
    packet = {
        "schema_version": 3,
        "repository": "example/app",
        "components": [
            {
                "component_id": "CVE-2026-1001",
                "range_claims": [{"claim_id": "RANGE-1"}],
            }
        ],
        "revision_candidates": [
            {
                "candidate_id": "CVE-2026-1001@" + "b" * 40,
                "component_id": "CVE-2026-1001",
                "repair_commit": "b" * 40,
                "primary_commit": "a" * 40,
                "fallback_range_claim_ids": ["RANGE-1"],
            }
        ],
    }
    path = packet_dir / "EXAMPLE__APP.json"
    path.write_text(json.dumps(packet, indent=2) + "\n", encoding="utf-8")
    return path


def _write_review(
    review_dir: Path, packet_path: Path, *, verdict: str = "promising"
) -> Path:
    review_dir.mkdir()
    evidence_dir = review_dir / "evidence"
    evidence_dir.mkdir()
    attack_artifact = evidence_dir / "advisory.txt"
    repair_artifact = evidence_dir / "repair.patch"
    operability_artifact = evidence_dir / "install.txt"
    attack_artifact.write_text("attacker behavior\n", encoding="utf-8")
    repair_artifact.write_text("repair behavior\n", encoding="utf-8")
    operability_artifact.write_text("official deployment behavior\n", encoding="utf-8")
    review = {
        "schema_version": 5,
        "repository": "example/app",
        "source_packet": packet_path.name,
        "source_packet_sha256": hashlib.sha256(packet_path.read_bytes()).hexdigest(),
        "review_basis": "public_evidence_and_bounded_source_review",
        "decision": {
            "verdict": verdict,
            "candidate_id": "CVE-2026-1001@" + "b" * 40,
            "repair_commit": "b" * 40,
            "primary_commit": "a" * 40,
            "fallback_range_claim_id": "RANGE-1",
            "selected_component_ids": ["CVE-2026-1001"],
            "candidate_scope_ids": (
                [] if verdict == "low_potential" else ["app.cross_boundary.read"]
            ),
            "case": (
                "A normal tenant uses the object API; public evidence shows an ownership "
                "bypass and the exact repair restores that boundary while preserving "
                "authorized reads. The case survives the bounded static pressure test."
            ),
            "next_focus": (
                None
                if verdict == "low_potential"
                else "Confirm vulnerable and repaired behavior for the same actor and target."
            ),
            "operability": {
                "risk": "low",
                "deployment": "Official single-service container.",
            },
        },
        "evidence": [
            {
                "kind": "attack_chain",
                "url": "https://example.com/advisory",
                "observed_at": "2026-08-21T00:00:00Z",
                "artifact": "evidence/advisory.txt",
                "sha256": hashlib.sha256(attack_artifact.read_bytes()).hexdigest(),
                "claim": "The advisory establishes the actor and unauthorized behavior.",
            },
            {
                "kind": "repair",
                "url": "https://github.com/example/app/commit/" + "b" * 40,
                "observed_at": "2026-08-21T00:00:00Z",
                "artifact": "evidence/repair.patch",
                "sha256": hashlib.sha256(repair_artifact.read_bytes()).hexdigest(),
                "claim": "The exact fix establishes the repaired ownership boundary.",
            },
            {
                "kind": "operability",
                "url": "https://example.com/install",
                "observed_at": "2026-08-21T00:00:00Z",
                "artifact": "evidence/install.txt",
                "sha256": hashlib.sha256(operability_artifact.read_bytes()).hexdigest(),
                "claim": "Official documentation establishes compatible self-hosting.",
            },
        ],
    }
    path = review_dir / packet_path.name
    path.write_text(json.dumps(review, indent=2) + "\n", encoding="utf-8")
    return path


def _command(tmp_path: Path, packet_dir: Path, review_dir: Path) -> list[str]:
    registry = tmp_path / "attack_scopes.json"
    registry.write_text(
        json.dumps(
            {
                "policy": {
                    "custom_scope_required_fields": [
                        "id",
                        "technical_impact",
                        "title",
                        "target",
                        "boundary",
                        "capability",
                        "proof_requirement",
                    ]
                },
                "technical_impact_standard": {
                    "impacts": [{"id": "read_data", "title": "Read Data"}]
                },
                "scopes": [
                    {
                        "id": "app.cross_boundary.read",
                        "technical_impact": "read_data",
                    }
                ],
            }
        ),
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


def test_semantic_validator_accepts_compact_review(tmp_path):
    packet_dir = tmp_path / "packets"
    review_dir = tmp_path / "reviews"
    packet = _write_packet(packet_dir)
    _write_review(review_dir, packet)

    result = subprocess.run(
        _command(tmp_path, packet_dir, review_dir), capture_output=True, text=True
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "PASS" in result.stdout


def test_promising_review_requires_retained_operability_evidence(tmp_path):
    packet_dir = tmp_path / "packets"
    review_dir = tmp_path / "reviews"
    packet = _write_packet(packet_dir)
    review_path = _write_review(review_dir, packet)
    review = json.loads(review_path.read_text(encoding="utf-8"))
    review["evidence"] = [
        item for item in review["evidence"] if item["kind"] != "operability"
    ]
    review_path.write_text(json.dumps(review), encoding="utf-8")

    result = subprocess.run(
        _command(tmp_path, packet_dir, review_dir), capture_output=True, text=True
    )

    assert result.returncode == 1
    assert "promising decision requires operability evidence" in result.stdout


def test_uncertain_review_preserves_an_upstream_evidence_gap(tmp_path):
    packet_dir = tmp_path / "packets"
    review_dir = tmp_path / "reviews"
    packet = _write_packet(packet_dir)
    review_path = _write_review(review_dir, packet, verdict="uncertain")
    review = json.loads(review_path.read_text(encoding="utf-8"))
    review["evidence"] = [
        item for item in review["evidence"] if item["kind"] == "attack_chain"
    ]
    review["decision"]["next_focus"] = (
        "Resolve the exact repair and supported deployment from upstream evidence."
    )
    review_path.write_text(json.dumps(review), encoding="utf-8")

    result = subprocess.run(
        _command(tmp_path, packet_dir, review_dir), capture_output=True, text=True
    )

    assert result.returncode == 0, result.stdout + result.stderr


def test_semantic_validator_allows_early_application_exclusion(tmp_path):
    packet_dir = tmp_path / "packets"
    review_dir = tmp_path / "reviews"
    packet = _write_packet(packet_dir)
    review_path = _write_review(review_dir, packet, verdict="low_potential")
    review = json.loads(review_path.read_text(encoding="utf-8"))
    review["decision"]["operability"] = None
    review_path.write_text(json.dumps(review), encoding="utf-8")

    result = subprocess.run(
        _command(tmp_path, packet_dir, review_dir), capture_output=True, text=True
    )

    assert result.returncode == 0, result.stdout + result.stderr


def test_semantic_validator_rejects_legacy_schema_three(tmp_path):
    packet_dir = tmp_path / "packets"
    review_dir = tmp_path / "reviews"
    packet = _write_packet(packet_dir)
    review_dir.mkdir()
    (review_dir / packet.name).write_text(
        json.dumps({"schema_version": 3}), encoding="utf-8"
    )

    result = subprocess.run(
        _command(tmp_path, packet_dir, review_dir), capture_output=True, text=True
    )

    assert result.returncode == 1
    assert "schema-version 5" in result.stdout


def test_semantic_validator_rejects_unregistered_scope_and_missing_candidate(tmp_path):
    packet_dir = tmp_path / "packets"
    review_dir = tmp_path / "reviews"
    packet = _write_packet(packet_dir)
    review_path = _write_review(review_dir, packet)
    review = json.loads(review_path.read_text(encoding="utf-8"))
    review["decision"]["candidate_scope_ids"] = ["host.unknown"]
    review["decision"]["candidate_id"] = "CVE-2026-9999@" + "f" * 40
    review_path.write_text(json.dumps(review), encoding="utf-8")

    result = subprocess.run(
        _command(tmp_path, packet_dir, review_dir), capture_output=True, text=True
    )

    assert result.returncode == 1
    assert "decision uses unregistered scope host.unknown" in result.stdout
    assert "decision.candidate_id is outside the source packet" in result.stdout


def test_semantic_validator_rejects_candidate_identity_drift(tmp_path):
    packet_dir = tmp_path / "packets"
    review_dir = tmp_path / "reviews"
    packet = _write_packet(packet_dir)
    review_path = _write_review(review_dir, packet)
    review = json.loads(review_path.read_text(encoding="utf-8"))
    review["decision"]["repair_commit"] = "c" * 40
    review["decision"]["selected_component_ids"] = ["CVE-2026-9999"]
    review_path.write_text(json.dumps(review), encoding="utf-8")

    result = subprocess.run(
        _command(tmp_path, packet_dir, review_dir), capture_output=True, text=True
    )

    assert result.returncode == 1
    assert "decision.repair_commit does not match the selected candidate" in result.stdout
    assert "decision selects a component outside the source packet" in result.stdout


def test_semantic_validator_rejects_unretained_or_untyped_evidence(tmp_path):
    packet_dir = tmp_path / "packets"
    review_dir = tmp_path / "reviews"
    packet = _write_packet(packet_dir)
    review_path = _write_review(review_dir, packet)
    review = json.loads(review_path.read_text(encoding="utf-8"))
    review["evidence"][0]["kind"] = "context"
    review["evidence"][1]["sha256"] = "0" * 64
    review_path.write_text(json.dumps(review), encoding="utf-8")

    result = subprocess.run(
        _command(tmp_path, packet_dir, review_dir), capture_output=True, text=True
    )

    assert result.returncode == 1
    assert "requires attack_chain evidence" in result.stdout
    assert "sha256 does not match" in result.stdout


def test_semantic_validator_accepts_complete_custom_scope(tmp_path):
    packet_dir = tmp_path / "packets"
    review_dir = tmp_path / "reviews"
    packet = _write_packet(packet_dir)
    review_path = _write_review(review_dir, packet)
    review = json.loads(review_path.read_text(encoding="utf-8"))
    scope_id = "custom.example.protected_report.read"
    review["decision"]["candidate_scope_ids"] = [scope_id]
    review["custom_scopes"] = [{
        "id": scope_id,
        "technical_impact": "read_data",
        "title": "Unauthorized protected-report read",
        "target": "protected_report",
        "boundary": "report_authorization",
        "capability": "Read a protected report unavailable to the attacker.",
        "proof_requirement": "Recover a challenge-generated report value.",
    }]
    review_path.write_text(json.dumps(review), encoding="utf-8")

    result = subprocess.run(
        _command(tmp_path, packet_dir, review_dir), capture_output=True, text=True
    )

    assert result.returncode == 0, result.stdout + result.stderr


def test_semantic_validator_rejects_unanchored_custom_scope(tmp_path):
    packet_dir = tmp_path / "packets"
    review_dir = tmp_path / "reviews"
    packet = _write_packet(packet_dir)
    review_path = _write_review(review_dir, packet)
    review = json.loads(review_path.read_text(encoding="utf-8"))
    scope_id = "custom.example.protected_report.read"
    review["decision"]["candidate_scope_ids"] = [scope_id]
    review["custom_scopes"] = [{
        "id": scope_id,
        "technical_impact": "invented_impact",
        "title": "Unauthorized protected-report read",
        "target": "protected_report",
        "boundary": "report_authorization",
        "capability": "Read a protected report unavailable to the attacker.",
        "proof_requirement": "Recover a challenge-generated report value.",
    }]
    review_path.write_text(json.dumps(review), encoding="utf-8")

    result = subprocess.run(
        _command(tmp_path, packet_dir, review_dir), capture_output=True, text=True
    )

    assert result.returncode == 1
    assert "technical_impact is not registered" in result.stdout
