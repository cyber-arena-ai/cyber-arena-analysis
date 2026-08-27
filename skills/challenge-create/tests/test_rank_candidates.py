import hashlib
import json
import sys
from pathlib import Path


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

from rank_candidates import InputError, generate  # noqa: E402


def _row(identifier, disposition="unresolved", **enabled):
    assets = {
        "application_repository": True,
        "exploit_evidence": False,
        "exact_git_repair": False,
        "fixed_release": False,
        "usable_application_git_range": False,
        "repository_metadata": False,
    }
    assets.update(enabled)
    return {
        "component_id": identifier,
        "disposition": disposition,
        "repository": "example/app" if assets["application_repository"] else None,
        "reason": "test_gap",
        "assets": assets,
    }


def _write_candidates(path, rows):
    path.write_text(
        json.dumps(
            {"schema_version": 4, "evidence_matrix": {"rows": rows}},
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def test_ranking_follows_downstream_usefulness_and_repository_gate(tmp_path):
    candidates_path = tmp_path / "candidates.json"
    _write_candidates(
        candidates_path,
        [
            _row("POC", exploit_evidence=True),
            _row("REPAIR", exact_git_repair=True),
            _row("FIXED", fixed_release=True),
            _row("RANGE", usable_application_git_range=True),
            _row("METADATA", repository_metadata=True),
            _row(
                "NO-REPOSITORY",
                application_repository=False,
                exploit_evidence=True,
                exact_git_repair=True,
                fixed_release=True,
                usable_application_git_range=True,
                repository_metadata=True,
            ),
            _row("REPAIR-AND-RELEASE", exact_git_repair=True, fixed_release=True),
        ],
    )

    result = generate(candidates_path=candidates_path)

    assert [item["component_id"] for item in result["ranked_candidates"]] == [
        "POC",
        "REPAIR",
        "REPAIR-AND-RELEASE",
        "FIXED",
        "RANGE",
        "METADATA",
        "NO-REPOSITORY",
    ]
    assert [item["score"] for item in result["ranked_candidates"]] == [
        71,
        65,
        65,
        58,
        56,
        54,
        0,
    ]
    release = result["ranked_candidates"][2]
    assert release["score_contributions"]["fixed_release_without_exact_git_repair"] == 0
    assert result["candidate_source"]["sha256"] == hashlib.sha256(
        candidates_path.read_bytes()
    ).hexdigest()


def test_ranking_uses_hash_linked_candidate_view(tmp_path):
    candidates_path = tmp_path / "candidates.json"
    _write_candidates(
        candidates_path,
        [
            _row("READY", disposition="resolved"),
            _row("SELECTED", exact_git_repair=True),
            _row("OMITTED", exploit_evidence=True),
        ],
    )
    view_path = tmp_path / "view.json"
    view_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "candidate_source": {
                    "sha256": hashlib.sha256(candidates_path.read_bytes()).hexdigest()
                },
                "buckets": {
                    "after": {
                        "projects": [
                            {
                                "repository": "example/app",
                                "component_ids": ["READY"],
                            }
                        ],
                        "unresolved_component_ids": ["SELECTED"],
                    }
                },
            }
        ),
        encoding="utf-8",
    )

    result = generate(
        candidates_path=candidates_path,
        view_path=view_path,
        bucket_name="after",
    )

    assert [item["component_id"] for item in result["ranked_candidates"]] == [
        "READY",
        "SELECTED",
    ]
    assert [item["disposition"] for item in result["ranked_candidates"]] == [
        "resolved",
        "unresolved",
    ]
    assert result["summary"]["disposition_counts"] == {
        "resolved": 1,
        "unresolved": 1,
    }
    assert result["selection"]["candidate_view"]["bucket"] == "after"
    assert result["selection"]["candidate_view"]["sha256"] == hashlib.sha256(
        view_path.read_bytes()
    ).hexdigest()


def test_ranking_rejects_candidate_view_for_another_report(tmp_path):
    candidates_path = tmp_path / "candidates.json"
    _write_candidates(candidates_path, [_row("SELECTED")])
    view_path = tmp_path / "view.json"
    view_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "candidate_source": {"sha256": "0" * 64},
                "buckets": {
                    "after": {
                        "projects": [],
                        "unresolved_component_ids": ["SELECTED"],
                    }
                },
            }
        ),
        encoding="utf-8",
    )

    try:
        generate(
            candidates_path=candidates_path,
            view_path=view_path,
            bucket_name="after",
        )
    except InputError as error:
        assert "source hash" in str(error)
    else:
        raise AssertionError("ranking accepted a view for another candidate report")
