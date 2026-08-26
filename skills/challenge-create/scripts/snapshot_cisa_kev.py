#!/usr/bin/env python3
"""Normalize CISA KEV JSON into a manifested OSV-shaped fast-lane archive."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import zipfile
from datetime import date, datetime, timezone
from pathlib import Path


ARCHIVE_NAME = "CISA_KEV.zip"
SOURCE_NAME = "CISA Known Exploited Vulnerabilities"
SOURCE_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
CVE = re.compile(r"CVE-\d{4}-\d{4,}")
URL = re.compile(r"https?://[^\s;]+")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _references(notes: str) -> list[dict]:
    references = []
    seen = set()
    for raw_url in URL.findall(notes):
        url = raw_url.rstrip(".,)")
        if url in seen:
            continue
        seen.add(url)
        reference_type = (
            "ADVISORY"
            if re.search(r"github\.com/[^/]+/[^/]+/security/advisories/", url)
            else "WEB"
        )
        references.append({"type": reference_type, "url": url})
    return references


def _record(item: dict) -> dict:
    identifier = str(item.get("cveID", ""))
    if not CVE.fullmatch(identifier):
        raise ValueError(f"invalid CISA KEV cveID: {identifier!r}")
    added = str(item.get("dateAdded", ""))
    try:
        published = f"{date.fromisoformat(added).isoformat()}T00:00:00Z"
    except ValueError as error:
        raise ValueError(f"invalid CISA KEV dateAdded for {identifier}: {added!r}") from error
    return {
        "id": identifier,
        "published": published,
        "summary": str(item.get("vulnerabilityName") or identifier),
        "details": str(item.get("shortDescription") or ""),
        "affected": [],
        "references": _references(str(item.get("notes") or "")),
        "database_specific": {
            "vendor_project": item.get("vendorProject"),
            "product": item.get("product"),
            "date_added": added,
            "due_date": item.get("dueDate"),
            "known_ransomware_campaign_use": item.get("knownRansomwareCampaignUse"),
            "required_action": item.get("requiredAction"),
            "cwe_ids": item.get("cwes") or [],
        },
    }


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


def snapshot(*, input_path: Path, output_dir: Path) -> dict:
    manifest_path = output_dir / "osv_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    payload = json.loads(input_path.read_text(encoding="utf-8"))
    items = payload.get("vulnerabilities")
    if not isinstance(items, list):
        raise ValueError("CISA KEV vulnerabilities must be an array")
    records = sorted((_record(item) for item in items), key=lambda item: item["id"])
    if len({record["id"] for record in records}) != len(records):
        raise ValueError("CISA KEV contains duplicate cveID values")

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
        "lane": "known_exploited",
        "priority": 1,
        "record_count": len(records),
        "source_sha256": _sha256(input_path),
        "catalog_version": payload.get("catalogVersion"),
        "fetched_at": payload.get("dateReleased"),
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
    return {"record_count": len(records), "archive": str(archive_path)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = snapshot(input_path=args.input, output_dir=args.output_dir)
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as error:
        parser.error(str(error))
    print(f"wrote {result['record_count']} CISA KEV records to {result['archive']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
