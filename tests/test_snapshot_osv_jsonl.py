import json

from scripts.challenge_research.snapshot_osv import _existing_file, write_advisory_jsonl


def test_write_advisory_jsonl_is_lossless_and_deterministic(tmp_path):
    records = [
        {"repository": "example/zeta", "aliases": ["CVE-2026-1234"]},
        {"summary": "Unicode: café", "repository": "example/alpha"},
    ]
    output = tmp_path / "advisories.jsonl"

    write_advisory_jsonl(output, records)

    lines = output.read_text(encoding="utf-8").splitlines()
    assert [json.loads(line) for line in lines] == records
    assert lines[0] == (
        '{"aliases":["CVE-2026-1234"],"repository":"example/zeta"}'
    )
    assert output.read_bytes().endswith(b"\n")


def test_reused_snapshot_preserves_matching_http_provenance(tmp_path):
    archive = tmp_path / "GIT.zip"
    archive.write_bytes(b"snapshot")
    previous = {
        "sha256": "not-the-current-hash",
        "fetched_at": "2026-01-01T00:00:00Z",
        "etag": "old",
    }

    without_match = _existing_file("https://example.test/GIT.zip", archive, previous)
    assert without_match["fetched_at"] is None

    previous["sha256"] = without_match["sha256"]
    with_match = _existing_file("https://example.test/GIT.zip", archive, previous)
    assert with_match["fetched_at"] == "2026-01-01T00:00:00Z"
    assert with_match["etag"] == "old"
