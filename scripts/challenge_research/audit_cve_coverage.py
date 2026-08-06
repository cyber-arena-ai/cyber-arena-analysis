#!/usr/bin/env python3
"""Audit retained repository-linked CVE evidence against the positive test pool."""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path

try:
    from ._lib import canonical_github_repo
except ImportError:  # direct execution
    from _lib import canonical_github_repo


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_POOL = ROOT / "docs/jt/oss_discovery_test_pool.json"
DEFAULT_ADVISORIES = ROOT / "docs/jt/oss_shortlist_prototype/osv_advisories.json"
DEFAULT_JSON = ROOT / "docs/jt/oss_discovery_test_pool_cve_audit.json"
DEFAULT_MARKDOWN = ROOT / "docs/jt/OSS_DISCOVERY_TEST_POOL_CVE_AUDIT.md"

LANGUAGE_ECOSYSTEMS = {
    "Python": ("PyPI",),
    "Go": ("Go",),
    "Java": ("Maven",),
    "PHP": ("Packagist", "GIT"),
    "JavaScript": ("npm", "GIT"),
    "TypeScript": ("npm", "GIT"),
    "TypeScript and Go": ("npm", "Go", "GIT"),
    "C": ("GIT",),
}


def collection_context(language: str, collected: set[str]) -> str:
    relevant = LANGUAGE_ECOSYSTEMS.get(language, ())
    present = [ecosystem for ecosystem in relevant if ecosystem in collected]
    missing = [ecosystem for ecosystem in relevant if ecosystem not in collected]
    parts = []
    if present:
        parts.append(f"{', '.join(present)} collected")
    if missing:
        parts.append(f"{', '.join(missing)} not collected")
    return "; ".join(parts) or "no direct ecosystem mapping recorded"


def load_json(path: Path) -> dict:
    with path.open(encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected an object")
    return value


def record_cves(record: dict) -> set[str]:
    identifiers = [record.get("advisory_id", ""), *record.get("aliases", [])]
    return {str(item) for item in identifiers if str(item).startswith("CVE-")}


def audit(pool: dict, snapshot: dict) -> dict:
    collected_ecosystems = {
        str(source["ecosystem"])
        for source in snapshot.get("sources", [])
        if source.get("ecosystem")
    }
    by_repository: dict[str, list[dict]] = defaultdict(list)
    for record in snapshot.get("advisories", []):
        repository = str(record.get("repository", "")).lower()
        if repository:
            by_repository[repository].append(record)

    results = []
    for project in pool.get("projects", []):
        repository = canonical_github_repo(project.get("source_url"))
        if not repository:
            raise ValueError(f"{project.get('id')}: source URL is not a GitHub repository")
        evidence = by_repository.get(repository, [])
        cves = sorted({cve for record in evidence for cve in record_cves(record)})
        cve_records = [record for record in evidence if record_cves(record)]
        if cves:
            status = "cve-found"
        elif evidence:
            status = "repository-evidence-without-cve"
        else:
            status = "no-repository-evidence"
        results.append(
            {
                "id": project["id"],
                "name": project["name"],
                "source_url": project["source_url"],
                "repository": repository,
                "primary_language": project["primary_language"],
                "status": status,
                "repository_evidence_records": len(evidence),
                "cve_bearing_evidence_records": len(cve_records),
                "unique_cve_count": len(cves),
                "cves": cves,
                "example_cves": cves[:5],
                "source_ecosystems": sorted(
                    {record.get("source_ecosystem", "") for record in evidence}
                    - {""}
                ),
                "collection_context": collection_context(
                    project["primary_language"], collected_ecosystems
                ),
            }
        )

    statuses = (
        "cve-found",
        "repository-evidence-without-cve",
        "no-repository-evidence",
    )
    status_counts = {
        status: sum(item["status"] == status for item in results)
        for status in statuses
    }
    return {
        "schema_version": 1,
        "pool_defined_at": pool.get("defined_at"),
        "advisory_snapshot_generated_at": snapshot.get("generated_at"),
        "advisory_snapshot_source": snapshot.get("source"),
        "match_method": "Exact lowercase GitHub owner/repository against retained repository-linked OSV evidence; CVE IDs only.",
        "limitations": [
            "An exact repository miss does not prove that the project has no CVEs.",
            "Collected OSV ecosystems: " + ", ".join(sorted(collected_ecosystems)) + ".",
            "CVE records linked only to a package, mirror, security tracker, or different upstream repository may be missed.",
        ],
        "summary": {
            "projects": len(results),
            "projects_with_cves": status_counts["cve-found"],
            "projects_without_cves": len(results) - status_counts["cve-found"],
            "unique_cves_across_pool": len(
                {cve for item in results for cve in item["cves"]}
            ),
            "status_counts": status_counts,
        },
        "projects": results,
    }


def render_markdown(payload: dict) -> str:
    summary = payload["summary"]
    lines = [
        "# OSS Discovery Test Pool — Existing CVE Coverage",
        "",
        f"> Advisory snapshot: `{payload['advisory_snapshot_generated_at']}`. Match: exact repository; CVE identifiers only.",
        "",
        "This audits the retained discovery evidence without fetching new sources. A miss means the current pipeline found no repository-linked CVE evidence; it does not mean the project has no CVEs.",
        "",
        f"- Test-pool projects: **{summary['projects']}**",
        f"- Projects with at least one CVE: **{summary['projects_with_cves']}**",
        f"- Projects without a CVE hit: **{summary['projects_without_cves']}**",
        f"- Unique CVEs found across the pool: **{summary['unique_cves_across_pool']}**",
        "",
        "| # | Project | Result | Unique CVEs | Evidence rows | Source ecosystems | Example CVEs | Collection context |",
        "| ---: | --- | --- | ---: | ---: | --- | --- | --- |",
    ]
    for index, item in enumerate(payload["projects"], 1):
        examples = ", ".join(item["example_cves"]) or "—"
        ecosystems = ", ".join(item["source_ecosystems"]) or "—"
        lines.append(
            f"| {index} | [{item['name']}]({item['source_url']}) | "
            f"`{item['status']}` | {item['unique_cve_count']} | "
            f"{item['repository_evidence_records']} | {ecosystems} | {examples} | "
            f"{item['collection_context']} |"
        )
    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            "- `cve-found` proves only that the retained OSV-derived evidence linked at least one CVE identifier to the exact repository.",
            "- `repository-evidence-without-cve` means another advisory namespace linked the repository but no CVE identifier was present.",
            "- `no-repository-evidence` is a coverage gap, not a security-history conclusion.",
            "- Feed presence does not guarantee that OSV maps a product to the exact source repository used by this test pool.",
            "- Package-to-repository aliases and non-GitHub canonical sources require a later identity-resolution step.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pool", type=Path, default=DEFAULT_POOL)
    parser.add_argument("--advisories", type=Path, default=DEFAULT_ADVISORIES)
    parser.add_argument("--output-json", type=Path, default=DEFAULT_JSON)
    parser.add_argument("--output-markdown", type=Path, default=DEFAULT_MARKDOWN)
    parser.add_argument(
        "--check",
        action="store_true",
        help="validate inputs and require generated outputs to be current",
    )
    args = parser.parse_args()

    payload = audit(load_json(args.pool), load_json(args.advisories))
    outputs = {
        args.output_json: json.dumps(payload, indent=2, sort_keys=True) + "\n",
        args.output_markdown: render_markdown(payload),
    }
    if args.check:
        stale = [
            str(path)
            for path, content in outputs.items()
            if not path.exists() or path.read_text(encoding="utf-8") != content
        ]
        if stale:
            raise SystemExit("stale or missing audit outputs:\n- " + "\n- ".join(stale))
        print(
            f"validated {payload['summary']['projects']} projects; "
            f"{payload['summary']['projects_with_cves']} have CVE hits"
        )
        return
    for path, content in outputs.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        print(path.relative_to(ROOT))


if __name__ == "__main__":
    main()
