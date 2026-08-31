import hashlib
import json
import subprocess
import sys
from pathlib import Path


VALIDATOR = Path(__file__).resolve().parents[1] / "scripts/validate_stage3_study.py"
COMMIT = "a" * 40
REPAIR = "b" * 40
COMPONENT = "CVE-2026-1001"
CANDIDATE = f"{COMPONENT}@{REPAIR}"
RANGE_CLAIM = "RANGE-1"


def _packet(tmp_path: Path) -> Path:
    path = tmp_path / "EXAMPLE__APP.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": 3,
                "repository": "example/app",
                "components": [{"component_id": COMPONENT}],
                "revision_candidates": [
                    {
                        "candidate_id": CANDIDATE,
                        "component_id": COMPONENT,
                        "repair_commit": REPAIR,
                        "primary_commit": COMMIT,
                        "fallback_range_claim_ids": [RANGE_CLAIM],
                    }
                ],
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return path


def _review(tmp_path: Path, packet: Path, *, verdict="promising") -> Path:
    path = tmp_path / "semantic-review.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": 5,
                "repository": "example/app",
                "source_packet": packet.name,
                "source_packet_sha256": hashlib.sha256(
                    packet.read_bytes()
                ).hexdigest(),
                "decision": {
                    "verdict": verdict,
                    "candidate_id": CANDIDATE,
                    "repair_commit": REPAIR,
                    "primary_commit": COMMIT,
                    "fallback_range_claim_id": RANGE_CLAIM,
                    "selected_component_ids": [COMPONENT],
                },
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return path


def _study(tmp_path: Path, packet: Path, *, outcome="ready_for_authoring") -> Path:
    study = tmp_path / "study"
    (study / "evidence").mkdir(parents=True)
    (study / "STAGE3_STUDY.md").write_text(
        f"# Study\n\nVulnerable: `{COMMIT}`\n\nRepair: `{REPAIR}`\n\n"
        f"Range: `{RANGE_CLAIM}`\n\nComponent: `{COMPONENT}`\n",
        encoding="utf-8",
    )
    (study / "compose.yaml").write_text("services: {}\n", encoding="utf-8")
    (study / "reproduce.py").write_text("# reproduction\n", encoding="utf-8")
    (study / "evidence/vulnerable.txt").write_text("observed\n", encoding="utf-8")
    (study / "evidence/fixed.txt").write_text("blocked\n", encoding="utf-8")
    result = {
        "schema_version": 4,
        "repository": "example/app",
        "source_packet": packet.name,
        "source_packet_sha256": hashlib.sha256(packet.read_bytes()).hexdigest(),
        "candidate_id": CANDIDATE,
        "repair_commit": REPAIR,
        "primary_commit": COMMIT,
        "fallback_range_claim_id": RANGE_CLAIM,
        "reproduced_commit": COMMIT,
        "fallback_search_used": False,
        "selected_component_ids": [COMPONENT],
        "outcome": outcome,
        "artifacts": {
            "study": "STAGE3_STUDY.md",
            "environment": ["compose.yaml"],
            "reproduction": "reproduce.py",
            "evidence": ["evidence/vulnerable.txt", "evidence/fixed.txt"],
        },
    }
    (study / "result.json").write_text(
        json.dumps(result, indent=2) + "\n", encoding="utf-8"
    )
    return study


def _run(packet: Path, review: Path, study: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(VALIDATOR),
            "--packet",
            str(packet),
            "--review",
            str(review),
            "--study-dir",
            str(study),
        ],
        capture_output=True,
        text=True,
    )


def test_ready_study_passes_with_linked_runtime_artifacts(tmp_path):
    packet = _packet(tmp_path)
    review = _review(tmp_path, packet)
    study = _study(tmp_path, packet)

    result = _run(packet, review, study)

    assert result.returncode == 0, result.stdout + result.stderr


def test_ready_study_rejects_unreported_fallback_commit(tmp_path):
    packet = _packet(tmp_path)
    review = _review(tmp_path, packet)
    study = _study(tmp_path, packet)
    result_path = study / "result.json"
    payload = json.loads(result_path.read_text(encoding="utf-8"))
    payload["reproduced_commit"] = "c" * 40
    result_path.write_text(json.dumps(payload), encoding="utf-8")

    result = _run(packet, review, study)

    assert result.returncode == 1
    assert "must equal primary_commit" in result.stdout


def test_ready_study_requires_vulnerable_and_fixed_evidence(tmp_path):
    packet = _packet(tmp_path)
    review = _review(tmp_path, packet)
    study = _study(tmp_path, packet)
    result_path = study / "result.json"
    payload = json.loads(result_path.read_text(encoding="utf-8"))
    payload["artifacts"]["evidence"] = ["evidence/vulnerable.txt"]
    result_path.write_text(json.dumps(payload), encoding="utf-8")

    result = _run(packet, review, study)

    assert result.returncode == 1
    assert "requires vulnerable and fixed evidence" in result.stdout


def test_artifacts_cannot_escape_study_directory(tmp_path):
    packet = _packet(tmp_path)
    review = _review(tmp_path, packet)
    study = _study(tmp_path, packet, outcome="needs_study")
    result_path = study / "result.json"
    payload = json.loads(result_path.read_text(encoding="utf-8"))
    payload["artifacts"]["study"] = "../outside.md"
    result_path.write_text(json.dumps(payload), encoding="utf-8")

    result = _run(packet, review, study)

    assert result.returncode == 1
    assert "must stay inside" in result.stdout


def test_ready_study_rejects_environment_pointer(tmp_path):
    packet = _packet(tmp_path)
    review = _review(tmp_path, packet)
    study = _study(tmp_path, packet)
    (study / "environment.txt").write_text("See ../shared\n", encoding="utf-8")
    result_path = study / "result.json"
    payload = json.loads(result_path.read_text(encoding="utf-8"))
    payload["artifacts"]["environment"] = ["environment.txt"]
    result_path.write_text(json.dumps(payload), encoding="utf-8")

    result = _run(packet, review, study)

    assert result.returncode == 1
    assert "must include a Dockerfile or Compose YAML" in result.stdout


def test_uncertain_semantic_review_cannot_advance(tmp_path):
    packet = _packet(tmp_path)
    review = _review(tmp_path, packet, verdict="uncertain")
    study = _study(tmp_path, packet)

    result = _run(packet, review, study)

    assert result.returncode == 1
    assert "semantic review is not eligible for Stage 3" in result.stdout


def test_rejected_study_may_record_no_reproduced_commit(tmp_path):
    packet = _packet(tmp_path)
    review = _review(tmp_path, packet)
    study = _study(tmp_path, packet, outcome="rejected")
    result_path = study / "result.json"
    payload = json.loads(result_path.read_text(encoding="utf-8"))
    payload["reproduced_commit"] = None
    payload["artifacts"] = {"study": "STAGE3_STUDY.md"}
    result_path.write_text(json.dumps(payload), encoding="utf-8")

    result = _run(packet, review, study)

    assert result.returncode == 0, result.stdout + result.stderr
