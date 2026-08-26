#!/usr/bin/env python3
"""Normalize Metasploit exploit-module CVEs into a manifested fast-lane archive."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import zipfile
from datetime import datetime, timezone
from pathlib import Path


ARCHIVE_NAME = "METASPLOIT.zip"
SOURCE_NAME = "Rapid7 Metasploit exploit modules"
SOURCE_URL = "https://github.com/rapid7/metasploit-framework"
CVE_REFERENCE = re.compile(
    r"[\[(]\s*['\"]CVE['\"]\s*,\s*['\"](\d{4}-\d{4,})['\"]"
)
MODULE_NAME = re.compile(r"['\"]Name['\"]\s*=>\s*['\"]([^'\"]+)['\"]")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _git(repository: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repository), *args],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _records(repository: Path, commit: str) -> tuple[list[dict], int]:
    records = []
    module_count = 0
    modules_root = repository / "modules" / "exploits"
    if not modules_root.is_dir():
        raise ValueError(f"Metasploit exploit modules not found: {modules_root}")
    for path in sorted(modules_root.rglob("*.rb")):
        relative = path.relative_to(repository).as_posix()
        text = path.read_text(encoding="utf-8", errors="replace")
        cves = sorted({f"CVE-{value}" for value in CVE_REFERENCE.findall(text)})
        if not cves:
            continue
        module_count += 1
        match = MODULE_NAME.search(text)
        name = match.group(1) if match else path.stem.replace("_", " ")
        slug = "-".join(path.with_suffix("").relative_to(repository).parts).replace(
            "_", "-"
        )
        url = f"{SOURCE_URL}/blob/{commit}/{relative}"
        for cve in cves:
            records.append(
                {
                    "id": f"MSF-{slug}-{cve}",
                    "aliases": [cve],
                    "summary": f"Metasploit exploit module: {name}",
                    "affected": [],
                    "references": [{"type": "EVIDENCE", "url": url}],
                    "database_specific": {
                        "module": relative,
                        "module_name": name,
                        "repository_commit": commit,
                    },
                }
            )
    return records, module_count


def _write_archive(path: Path, records: list[dict]) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for record in records:
            member = zipfile.ZipInfo(f"{record['id']}.json")
            member.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(
                member,
                json.dumps(record, indent=2, sort_keys=True).encode() + b"\n",
            )
    temporary.replace(path)


def snapshot(*, repository: Path, output_dir: Path) -> dict:
    manifest_path = output_dir / "osv_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    commit = _git(repository, "rev-parse", "HEAD")
    records, module_count = _records(repository, commit)

    raw_dir = output_dir / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    archive_path = raw_dir / ARCHIVE_NAME
    _write_archive(archive_path, records)
    source = {
        "path": ARCHIVE_NAME,
        "bytes": archive_path.stat().st_size,
        "sha256": _sha256(archive_path),
        "url": SOURCE_URL,
        "source": SOURCE_NAME,
        "role": "fast_lane",
        "lane": "executable_exploit",
        "priority": 2,
        "record_count": len(records),
        "module_count": module_count,
        "repository_commit": commit,
        "repository_commit_time": _git(repository, "show", "-s", "--format=%cI", commit),
        "fetched_at": datetime.now(timezone.utc).isoformat(),
    }
    sources = [
        {**item, "role": item.get("role") or "base"}
        for item in manifest.get("sources", [])
        if item.get("path") != ARCHIVE_NAME
    ]
    sources.append(source)
    manifest.update(
        {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "sources": sources,
        }
    )
    temporary = manifest_path.with_name(f".{manifest_path.name}.tmp")
    temporary.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    temporary.replace(manifest_path)
    return {
        "record_count": len(records),
        "module_count": module_count,
        "archive": str(archive_path),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = snapshot(repository=args.repository, output_dir=args.output_dir)
    except (
        OSError,
        ValueError,
        subprocess.CalledProcessError,
        json.JSONDecodeError,
    ) as error:
        parser.error(str(error))
    print(
        f"wrote {result['record_count']} CVE records from "
        f"{result['module_count']} Metasploit modules to {result['archive']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
