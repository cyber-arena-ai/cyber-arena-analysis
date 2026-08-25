import sys
import hashlib
import json
from pathlib import Path


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

from snapshot_osv import _existing_file, snapshot  # noqa: E402


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


def test_snapshot_preserves_manifested_complementary_archives(tmp_path):
    raw_dir = tmp_path / "raw"
    raw_dir.mkdir()
    osv = raw_dir / "GIT.zip"
    old_osv = raw_dir / "Go.zip"
    complement = raw_dir / "vendor.zip"
    osv.write_bytes(b"osv")
    old_osv.write_bytes(b"old-osv")
    complement.write_bytes(b"vendor")
    manifest = {
        "schema_version": 1,
        "sources": [
            {
                "path": "Go.zip",
                "bytes": old_osv.stat().st_size,
                "sha256": hashlib.sha256(old_osv.read_bytes()).hexdigest(),
                "ecosystem": "Go",
                "url": "https://storage.googleapis.com/osv-vulnerabilities/Go/all.zip",
            },
            {
                "path": "vendor.zip",
                "bytes": complement.stat().st_size,
                "sha256": hashlib.sha256(complement.read_bytes()).hexdigest(),
                "source": "vendor advisories",
            }
        ],
    }
    (tmp_path / "osv_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    payload = snapshot(output_dir=tmp_path, ecosystems=["GIT"], refresh=False)

    sources = {item["path"]: item for item in payload["sources"]}
    assert set(sources) == {"GIT.zip", "vendor.zip"}
    assert sources["vendor.zip"]["source"] == "vendor advisories"
