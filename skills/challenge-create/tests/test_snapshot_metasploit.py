import hashlib
import json
import subprocess
import sys
import zipfile
from pathlib import Path


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

from snapshot_metasploit import snapshot  # noqa: E402


def test_snapshot_normalizes_metasploit_cves_as_executable_exploit_lane(tmp_path):
    raw_dir = tmp_path / "sources" / "raw"
    raw_dir.mkdir(parents=True)
    base = raw_dir / "GIT.zip"
    with zipfile.ZipFile(base, "w") as archive:
        archive.writestr("base.json", json.dumps({"id": "CVE-2026-0001"}))
    output_dir = raw_dir.parent
    manifest_path = output_dir / "osv_manifest.json"
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
    repository = tmp_path / "metasploit-framework"
    module = repository / "modules" / "exploits" / "linux" / "http" / "example.rb"
    module.parent.mkdir(parents=True)
    module.write_text(
        """
        'Name' => 'Example Service Command Injection',
        'References' => [
          ['CVE', '2026-12345'],
          ['CVE', '2026-12346']
        ]
        """,
        encoding="utf-8",
    )
    subprocess.run(["git", "init", "-q", str(repository)], check=True)
    subprocess.run(
        ["git", "-C", str(repository), "config", "user.email", "test@example.com"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(repository), "config", "user.name", "Test"], check=True
    )
    subprocess.run(["git", "-C", str(repository), "add", "."], check=True)
    subprocess.run(
        ["git", "-C", str(repository), "commit", "-qm", "fixture"], check=True
    )
    commit = subprocess.run(
        ["git", "-C", str(repository), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()

    result = snapshot(repository=repository, output_dir=output_dir)

    assert result["record_count"] == 2
    archive_path = raw_dir / "METASPLOIT.zip"
    with zipfile.ZipFile(archive_path) as archive:
        names = sorted(archive.namelist())
        record = json.loads(archive.read(names[0]))
    assert names == [
        "MSF-modules-exploits-linux-http-example-CVE-2026-12345.json",
        "MSF-modules-exploits-linux-http-example-CVE-2026-12346.json",
    ]
    assert record["aliases"] == ["CVE-2026-12345"]
    assert record["summary"] == (
        "Metasploit exploit module: Example Service Command Injection"
    )
    assert record["references"] == [
        {
            "type": "EVIDENCE",
            "url": (
                "https://github.com/rapid7/metasploit-framework/blob/"
                f"{commit}/modules/exploits/linux/http/example.rb"
            ),
        }
    ]
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    fast_lane = next(
        item for item in manifest["sources"] if item["path"] == archive_path.name
    )
    assert fast_lane["role"] == "fast_lane"
    assert fast_lane["lane"] == "executable_exploit"
    assert fast_lane["priority"] == 2
    assert fast_lane["repository_commit"] == commit
    assert fast_lane["record_count"] == 2
