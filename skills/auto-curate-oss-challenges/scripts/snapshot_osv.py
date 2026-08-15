#!/usr/bin/env python3
"""Download selected OSV ecosystem snapshots and extract repository-linked evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path

try:
    from ._lib import extract_osv_record
except ImportError:  # direct execution from this skill's scripts directory
    from _lib import extract_osv_record


DEFAULT_ECOSYSTEMS = (
    "GIT",
    "Go",
    "Maven",
    "Packagist",
    "PyPI",
    "RubyGems",
    "crates.io",
    "npm",
)
BASE_URL = "https://storage.googleapis.com/osv-vulnerabilities"


def write_advisory_jsonl(path: Path, records: list[dict]) -> None:
    """Write normalized advisory evidence as deterministic one-object-per-line JSON."""
    with path.open("w", encoding="utf-8") as stream:
        for record in records:
            stream.write(
                json.dumps(
                    record,
                    ensure_ascii=False,
                    separators=(",", ":"),
                    sort_keys=True,
                )
                + "\n"
            )


def _download(url: str, destination: Path) -> dict:
    request = urllib.request.Request(
        url, headers={"User-Agent": "cyber-arena-challenge-research"}
    )
    digest = hashlib.sha256()
    size = 0
    temporary = destination.with_suffix(destination.suffix + ".part")
    with urllib.request.urlopen(request, timeout=120) as response, temporary.open("wb") as out:
        while chunk := response.read(1024 * 1024):
            out.write(chunk)
            digest.update(chunk)
            size += len(chunk)
        headers = dict(response.headers.items())
    temporary.replace(destination)
    return {
        "url": url,
        "path": destination.name,
        "sha256": digest.hexdigest(),
        "bytes": size,
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "last_modified": headers.get("Last-Modified"),
        "etag": headers.get("ETag"),
    }


def _existing_file(url: str, path: Path, previous: dict | None = None) -> dict:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    source = {
        "url": url,
        "path": path.name,
        "sha256": digest.hexdigest(),
        "bytes": path.stat().st_size,
        "fetched_at": None,
        "last_modified": None,
        "etag": None,
        "reused": True,
    }
    if previous and previous.get("sha256") == source["sha256"]:
        for key in ("fetched_at", "last_modified", "etag"):
            source[key] = previous.get(key)
    return source


def _extract(path: Path, ecosystem: str) -> tuple[list[dict], dict]:
    evidence: list[dict] = []
    stats = {
        "record_count": 0,
        "withdrawn_count": 0,
        "repository_linked_record_count": 0,
        "evidence_count": 0,
    }
    with zipfile.ZipFile(path) as archive:
        for member in archive.infolist():
            if member.is_dir() or not member.filename.endswith(".json"):
                continue
            stats["record_count"] += 1
            with archive.open(member) as stream:
                record = json.load(stream)
            if record.get("withdrawn"):
                stats["withdrawn_count"] += 1
                continue
            extracted = extract_osv_record(record, source_ecosystem=ecosystem)
            if extracted:
                stats["repository_linked_record_count"] += 1
                evidence.extend(extracted)
    stats["evidence_count"] = len(evidence)
    return evidence, stats


def snapshot(*, output_dir: Path, ecosystems: list[str], refresh: bool) -> dict:
    raw_dir = output_dir / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    previous_manifest_path = output_dir / "osv_manifest.json"
    previous_sources = {}
    if previous_manifest_path.is_file():
        with previous_manifest_path.open(encoding="utf-8") as stream:
            previous_manifest = json.load(stream)
        previous_sources = {
            source.get("path"): source
            for source in previous_manifest.get("sources", [])
            if source.get("path")
        }
    sources = []
    all_evidence = []
    stats = {}
    for ecosystem in ecosystems:
        url = f"{BASE_URL}/{ecosystem}/all.zip"
        filename = ecosystem.replace(".", "_").replace("/", "_") + ".zip"
        path = raw_dir / filename
        source = (
            _download(url, path)
            if refresh or not path.exists()
            else _existing_file(url, path, previous_sources.get(path.name))
        )
        source["ecosystem"] = ecosystem
        sources.append(source)
        evidence, ecosystem_stats = _extract(path, ecosystem)
        all_evidence.extend(evidence)
        stats[ecosystem] = ecosystem_stats

    payload = {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": "OSV ecosystem bulk snapshots",
        "sources": sources,
        "coverage_note": f"Selected OSV ecosystems: {', '.join(ecosystems)}.",
        "stats": stats,
        "evidence_count": len(all_evidence),
        "advisories": sorted(
            all_evidence,
            key=lambda item: (item["repository"], item["advisory_id"]),
        ),
    }
    (output_dir / "osv_advisories.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n"
    )
    write_advisory_jsonl(
        output_dir / "osv_advisories.jsonl",
        payload["advisories"],
    )
    (output_dir / "osv_manifest.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "generated_at": payload["generated_at"],
                "sources": sources,
                "stats": stats,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )
    return payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--ecosystem", action="append", dest="ecosystems")
    parser.add_argument("--refresh", action="store_true")
    args = parser.parse_args(argv)
    payload = snapshot(
        output_dir=args.output_dir,
        ecosystems=args.ecosystems or list(DEFAULT_ECOSYSTEMS),
        refresh=args.refresh,
    )
    print(
        f"wrote {payload['evidence_count']} repository-linked advisory records "
        f"to {args.output_dir / 'osv_advisories.json'} and "
        f"{args.output_dir / 'osv_advisories.jsonl'}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
