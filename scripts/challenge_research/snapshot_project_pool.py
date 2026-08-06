#!/usr/bin/env python3
"""Snapshot GitHub metadata for every repository in a curated project pool."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

try:
    from ._lib import canonical_github_repo
    from .discover_projects import API_VERSION, _normalize, _request_json
except ImportError:  # direct execution
    from _lib import canonical_github_repo
    from discover_projects import API_VERSION, _normalize, _request_json


def snapshot(pool: dict) -> dict:
    projects = []
    requests = []
    rate_limit = {}
    for item in pool.get("projects", []):
        repository = canonical_github_repo(item.get("source_url"))
        if not repository:
            raise ValueError(f"{item.get('id')}: expected a GitHub source repository")
        url = f"https://api.github.com/repos/{quote(repository, safe='/')}"
        raw, headers = _request_json(url)
        projects.append(
            _normalize(
                raw,
                query=f"curated-pool:{item['id']}",
                category=str(item.get("category", "curated-pool")),
            )
        )
        requests.append({"id": item["id"], "repository": repository, "url": url})
        rate_limit = {
            key.lower(): value
            for key, value in headers.items()
            if key.lower().startswith("x-ratelimit-")
        }
    return {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": "GitHub repository API for a curated project pool",
        "api_version": API_VERSION,
        "pool_defined_at": pool.get("defined_at"),
        "requests": requests,
        "rate_limit_after_last_request": rate_limit,
        "project_count": len(projects),
        "projects": sorted(
            projects,
            key=lambda project: (-project["stars"], project["repository"]),
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pool", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    with args.pool.open(encoding="utf-8") as handle:
        pool = json.load(handle)
    payload = snapshot(pool)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    print(f"wrote {payload['project_count']} projects to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
