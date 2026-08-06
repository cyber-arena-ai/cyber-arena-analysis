#!/usr/bin/env python3
"""Discover popular OSS candidates through config-driven GitHub searches."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


DEFAULT_QUERY_CONFIG = Path(__file__).with_name("discovery_queries.json")
API_VERSION = "2022-11-28"


def _request_json(url: str) -> tuple[dict, dict[str, str]]:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "cyber-arena-challenge-research",
        "X-GitHub-Api-Version": API_VERSION,
    }
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers)
    for attempt in range(2):
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return json.load(response), dict(response.headers.items())
        except urllib.error.HTTPError as exc:
            response_headers = {key.lower(): value for key, value in exc.headers.items()}
            remaining = response_headers.get("x-ratelimit-remaining")
            reset = response_headers.get("x-ratelimit-reset")
            if attempt == 0 and exc.code in {403, 429} and remaining == "0" and reset:
                delay = max(1, int(reset) - int(time.time()) + 1)
                if delay <= 65:
                    time.sleep(delay)
                    continue
            detail = exc.read().decode("utf-8", errors="replace")[-500:]
            raise RuntimeError(
                f"GitHub API request failed: HTTP {exc.code}: {detail}"
            ) from exc
    raise AssertionError("unreachable")


def load_queries(path: Path) -> list[dict]:
    with path.open(encoding="utf-8") as handle:
        payload = json.load(handle)
    if payload.get("schema_version") != 1 or not isinstance(payload.get("queries"), list):
        raise ValueError(f"{path}: expected discovery query schema version 1")
    queries = []
    seen_ids = set()
    for index, raw in enumerate(payload["queries"], 1):
        if not isinstance(raw, dict):
            raise ValueError(f"{path}: query {index} must be an object")
        query = {
            key: str(raw.get(key, "")).strip()
            for key in ("id", "lane", "category", "query")
        }
        if not all(query.values()):
            raise ValueError(f"{path}: query {index} is missing a required field")
        if query["id"] in seen_ids:
            raise ValueError(f"{path}: duplicate query id {query['id']}")
        seen_ids.add(query["id"])
        queries.append(query)
    return queries


def _normalize(
    item: dict,
    *,
    query: str,
    category: str,
    query_id: str | None = None,
    lane: str = "curated",
) -> dict:
    license_info = item.get("license") or {}
    return {
        "repository": item["full_name"].lower(),
        "name": item["name"],
        "url": item["html_url"],
        "description": item.get("description") or "",
        "stars": item.get("stargazers_count", 0),
        "forks": item.get("forks_count", 0),
        "language": item.get("language") or "Unknown",
        "license": license_info.get("spdx_id"),
        "topics": sorted(item.get("topics", [])),
        "archived": bool(item.get("archived")),
        "pushed_at": item.get("pushed_at"),
        "created_at": item.get("created_at"),
        "discovery_queries": [query],
        "discovery_query_ids": [query_id or query],
        "discovery_lanes": [lane],
        "discovery_categories": [category],
    }


def discover(*, queries: list[dict], per_query: int, min_stars: int) -> dict:
    projects: dict[str, dict] = {}
    requests = []
    rate_limit = {}
    for query_spec in queries:
        category = query_spec["category"]
        query_prefix = query_spec["query"]
        query = f"{query_prefix} stars:>={min_stars} archived:false fork:false"
        params = urllib.parse.urlencode(
            {
                "q": query,
                "sort": "stars",
                "order": "desc",
                "per_page": per_query,
                "page": 1,
            }
        )
        url = f"https://api.github.com/search/repositories?{params}"
        payload, headers = _request_json(url)
        rate_limit = {
            key.lower(): value
            for key, value in headers.items()
            if key.lower().startswith("x-ratelimit-")
        }
        unique_before = len(projects)
        items = payload.get("items", [])
        for raw in items:
            item = _normalize(
                raw,
                query=query,
                query_id=query_spec["id"],
                lane=query_spec["lane"],
                category=category,
            )
            existing = projects.get(item["repository"])
            if existing:
                existing["discovery_queries"] = sorted(
                    set(existing["discovery_queries"] + item["discovery_queries"])
                )
                existing["discovery_categories"] = sorted(
                    set(existing["discovery_categories"] + item["discovery_categories"])
                )
                existing["discovery_query_ids"] = sorted(
                    set(existing["discovery_query_ids"] + item["discovery_query_ids"])
                )
                existing["discovery_lanes"] = sorted(
                    set(existing["discovery_lanes"] + item["discovery_lanes"])
                )
            else:
                projects[item["repository"]] = item
        unique_additions = len(projects) - unique_before
        requests.append(
            {
                "id": query_spec["id"],
                "lane": query_spec["lane"],
                "category": category,
                "query": query,
                "url": url,
                "total_count": payload.get("total_count"),
                "incomplete_results": bool(payload.get("incomplete_results")),
                "returned_count": len(items),
                "unique_additions": unique_additions,
                "overlap_count": len(items) - unique_additions,
            }
        )

    return {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": "GitHub repository search API",
        "api_version": API_VERSION,
        "authenticated": bool(os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")),
        "query_count": len(queries),
        "requests": requests,
        "rate_limit_after_last_request": rate_limit,
        "project_count": len(projects),
        "projects": sorted(
            projects.values(), key=lambda item: (-item["stars"], item["repository"])
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--query-config", type=Path, default=DEFAULT_QUERY_CONFIG)
    parser.add_argument(
        "--language",
        action="append",
        dest="languages",
        help="override portfolio queries with self-hosted searches for these languages",
    )
    parser.add_argument("--per-query", type=int, default=100)
    parser.add_argument("--min-stars", type=int, default=1_000)
    args = parser.parse_args(argv)
    if not 1 <= args.per_query <= 100:
        parser.error("--per-query must be between 1 and 100")
    if args.min_stars < 0:
        parser.error("--min-stars must be non-negative")

    queries = (
        [
            {
                "id": f"self-hosted-{language.lower()}",
                "lane": "language-override",
                "category": f"self-hosted-{language.lower()}",
                "query": f'topic:self-hosted language:"{language}"',
            }
            for language in args.languages
        ]
        if args.languages
        else load_queries(args.query_config)
    )
    payload = discover(
        queries=queries,
        per_query=args.per_query,
        min_stars=args.min_stars,
    )
    if not args.languages:
        raw_config = args.query_config.read_bytes()
        payload["query_config"] = {
            "path": str(args.query_config),
            "sha256": hashlib.sha256(raw_config).hexdigest(),
        }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    print(f"wrote {payload['project_count']} projects to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
