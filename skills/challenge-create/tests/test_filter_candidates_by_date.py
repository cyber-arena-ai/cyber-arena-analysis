import hashlib
import json
import sys
from pathlib import Path


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

from filter_candidates_by_date import InputError, generate  # noqa: E402


def _component(identifier, publication):
    return {
        "component_id": identifier,
        "earliest_manifested_publication": publication,
    }


def _matrix_row(identifier, publication, disposition, repository=None):
    return {
        **_component(identifier, publication),
        "disposition": disposition,
        "repository": repository,
    }


def test_date_view_preserves_three_buckets_and_hash_links_source(tmp_path):
    candidates = {
        "schema_version": 5,
        "evidence_matrix": {
            "rows": [
                _matrix_row(
                    "CVE-2025-0001",
                    "2025-12-01T00:00:00+00:00",
                    "resolved",
                    "example/app",
                ),
                _matrix_row(
                    "CVE-2026-0001",
                    "2026-03-01T00:00:00+00:00",
                    "resolved",
                    "example/app",
                ),
                _matrix_row("CVE-2026-0002", None, "resolved", "example/app"),
                _matrix_row(
                    "CVE-2025-0002",
                    "2025-12-02T00:00:00+00:00",
                    "unresolved",
                ),
                _matrix_row(
                    "CVE-2026-0003",
                    "2026-03-02T00:00:00+00:00",
                    "unresolved",
                ),
                _matrix_row(
                    "CVE-2025-0003",
                    "2025-12-03T00:00:00+00:00",
                    "unresolved",
                ),
                _matrix_row(
                    "CVE-2026-0004",
                    "2026-03-03T00:00:00+00:00",
                    "unresolved",
                ),
                _matrix_row("CVE-2026-0005", None, "unresolved"),
                _matrix_row(
                    "CVE-2026-REJECTED",
                    "2026-03-04T00:00:00+00:00",
                    "rejected",
                ),
            ]
        },
    }
    candidates_path = tmp_path / "candidates.json"
    candidates_path.write_text(
        json.dumps(candidates, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    view = generate(
        candidates_path=candidates_path,
        cutoff_value="2026-02-16T23:59:59Z",
    )

    assert view["candidate_source"] == {
        "path": str(candidates_path),
        "sha256": hashlib.sha256(candidates_path.read_bytes()).hexdigest(),
        "schema_version": 5,
    }
    assert view["summary"] == {
        "retained_components": 8,
        "bucket_component_counts": {
            "after": 3,
            "at_or_before": 3,
            "unknown": 2,
        },
    }
    assert view["buckets"]["after"]["projects"] == [
        {"repository": "example/app", "component_ids": ["CVE-2026-0001"]}
    ]
    assert view["buckets"]["after"]["unresolved_component_ids"] == [
        "CVE-2026-0003",
        "CVE-2026-0004",
    ]
    assert view["buckets"]["at_or_before"]["projects"] == [
        {"repository": "example/app", "component_ids": ["CVE-2025-0001"]}
    ]
    assert view["buckets"]["unknown"]["projects"] == [
        {"repository": "example/app", "component_ids": ["CVE-2026-0002"]}
    ]
    assert view["buckets"]["unknown"]["unresolved_component_ids"] == [
        "CVE-2026-0005"
    ]


def test_date_view_rejects_an_already_filtered_source(tmp_path):
    candidates_path = tmp_path / "candidates.json"
    candidates_path.write_text(
        json.dumps(
            {
                "schema_version": 5,
                "date_cutoff": {"enabled": True},
                "evidence_matrix": {"rows": []},
            }
        ),
        encoding="utf-8",
    )

    try:
        generate(
            candidates_path=candidates_path,
            cutoff_value="2026-02-16T23:59:59Z",
        )
    except InputError as error:
        assert "unfiltered candidate index" in str(error)
    else:
        raise AssertionError("already filtered candidate index was accepted")


def test_date_view_rejects_legacy_candidate_schema(tmp_path):
    candidates_path = tmp_path / "candidates.json"
    candidates_path.write_text(
        json.dumps({"schema_version": 4, "evidence_matrix": {"rows": []}}),
        encoding="utf-8",
    )

    try:
        generate(
            candidates_path=candidates_path,
            cutoff_value="2026-02-16T23:59:59Z",
        )
    except InputError as error:
        assert "candidate schema version 5" in str(error)
    else:
        raise AssertionError("date view accepted a legacy candidate schema")
