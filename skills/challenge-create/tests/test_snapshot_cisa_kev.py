import hashlib
import json
import sys
import zipfile
from pathlib import Path


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

from snapshot_cisa_kev import snapshot  # noqa: E402


def test_snapshot_normalizes_and_manifests_cisa_kev_fast_lane(tmp_path):
    raw_dir = tmp_path / "raw"
    raw_dir.mkdir()
    base = raw_dir / "GIT.zip"
    with zipfile.ZipFile(base, "w") as archive:
        archive.writestr("base.json", json.dumps({"id": "CVE-2026-0001"}))
    manifest_path = tmp_path / "osv_manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "sources": [
                    {
                        "path": base.name,
                        "bytes": base.stat().st_size,
                        "sha256": hashlib.sha256(base.read_bytes()).hexdigest(),
                        "ecosystem": "GIT",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    source = tmp_path / "known_exploited_vulnerabilities.json"
    source.write_text(
        json.dumps(
            {
                "catalogVersion": "2026.08.25",
                "dateReleased": "2026-08-25T17:43:58Z",
                "vulnerabilities": [
                    {
                        "cveID": "CVE-2026-60004",
                        "vendorProject": "Gitea",
                        "product": "Gitea",
                        "vulnerabilityName": "Gitea Code Injection",
                        "dateAdded": "2026-08-25",
                        "shortDescription": "Repository write leads to command execution.",
                        "requiredAction": "Apply vendor mitigations.",
                        "knownRansomwareCampaignUse": "Unknown",
                        "notes": (
                            "https://github.com/go-gitea/gitea/security/advisories/"
                            "GHSA-rcr6-4jqh-j84m ; "
                            "https://nvd.nist.gov/vuln/detail/CVE-2026-60004"
                        ),
                        "cwes": ["CWE-94"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    result = snapshot(input_path=source, output_dir=tmp_path)

    assert result["record_count"] == 1
    archive_path = raw_dir / "CISA_KEV.zip"
    with zipfile.ZipFile(archive_path) as archive:
        record = json.loads(archive.read("CVE-2026-60004.json"))
    assert record["id"] == "CVE-2026-60004"
    assert record["published"] == "2026-08-25T00:00:00Z"
    assert record["summary"] == "Gitea Code Injection"
    assert record["database_specific"]["cwe_ids"] == ["CWE-94"]
    assert record["references"] == [
        {
            "type": "ADVISORY",
            "url": (
                "https://github.com/go-gitea/gitea/security/advisories/"
                "GHSA-rcr6-4jqh-j84m"
            ),
        },
        {
            "type": "WEB",
            "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-60004",
        },
    ]
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    fast_lane = next(
        item for item in manifest["sources"] if item["path"] == archive_path.name
    )
    assert fast_lane["role"] == "fast_lane"
    assert fast_lane["lane"] == "known_exploited"
    assert fast_lane["priority"] == 1
    assert fast_lane["source"] == "CISA Known Exploited Vulnerabilities"
    assert fast_lane["record_count"] == 1
    assert fast_lane["source_sha256"] == hashlib.sha256(source.read_bytes()).hexdigest()
