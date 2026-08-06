#!/usr/bin/env python3
"""Rank discovered OSS projects and apply a configurable popularity gate."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

try:
    from ._lib import merge_and_rank
except ImportError:  # direct execution: python scripts/challenge_research/rank_shortlist.py
    from _lib import merge_and_rank


POPULARITY_AXES = [
    {
        "key": "star_reach",
        "max_points": 55,
        "rationale": "Log-scaled GitHub stars as a broad public-reach signal.",
    },
    {
        "key": "community_breadth",
        "max_points": 25,
        "rationale": "Log-scaled forks as a participation and reuse signal.",
    },
    {
        "key": "maintenance_activity",
        "max_points": 10,
        "rationale": "Recency of the latest repository push.",
    },
    {
        "key": "longevity",
        "max_points": 10,
        "rationale": "Repository age as a sustained-public-history signal.",
    },
]


def _load(path: Path, key: str) -> tuple[list[dict], dict]:
    raw = path.read_bytes()
    payload = json.loads(raw)
    return payload[key], {
        "path": str(path),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "generated_at": payload.get("generated_at"),
        "source": payload.get("source"),
        "ecosystems": [
            source["ecosystem"]
            for source in payload.get("sources", [])
            if source.get("ecosystem")
        ],
    }


def _markdown(payload: dict) -> str:
    gate = payload["popularity_gate"]
    lines = [
        "# OSS Popularity Ranking and Admission Gate",
        "",
        f"Generated: `{payload['generated_at']}`",
        f"Ranking snapshot cutoff: `{payload['ranking_as_of']}`",
        "",
        "Status: **popularity admission only; challenge suitability is evaluated later.**",
        "",
        "## Method",
        "",
        "Every project in the discovery snapshot is ranked using GitHub popularity proxies.",
        "CVE volume, CWE diversity, application fit, license metadata, and portfolio diversity",
        "do not affect this gate. They remain annotations or later review stages.",
        "",
        f"- Minimum popularity score: **{gate['min_score']} / 100**",
        "- Maximum admitted projects: **"
        + (str(gate["limit"]) if gate["limit"] is not None else "unlimited")
        + "**",
        f"- GitHub projects discovered: **{payload['input_counts']['projects']}**",
        f"- Projects admitted: **{payload['input_counts']['admitted']}**",
        f"- Projects rejected: **{payload['input_counts']['rejected']}**",
        f"- Repository-linked OSV evidence records: **{payload['input_counts']['advisories']}**",
        f"- Projects with advisory evidence: **{payload['input_counts']['both']}**",
        "- OSV feeds in this snapshot: "
        + ", ".join(payload["sources"]["advisories"].get("ecosystems", [])),
        "",
        "## Ranking axes",
        "",
        "| Axis | Maximum | Method |",
        "| --- | ---: | --- |",
    ]
    for axis in gate["axes"]:
        lines.append(
            f"| `{axis['key']}` | {axis['max_points']} | {axis['rationale']} |"
        )
    lines.extend(
        [
        "",
        "Stars and forks are log-scaled so a tenfold increase matters without allowing the",
        "largest repositories to dominate the entire score. Activity receives 10/7/3/0",
        "points for a latest push within 90/365/730/more days. Longevity receives",
        "10/7/4/2 points for at least 5/2/1/less years of public history.",
        "",
        "## All discovered projects",
        "",
        "| Rank | Project | Stars | Forks | Reach | Community | Activity | Longevity | Score | Gate | Advisories |",
        "| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | ---: |",
        ]
    )
    for item in payload["ranked_projects"]:
        components = item["popularity_score_components"]
        gate_result = item["popularity_gate"]
        status = "admit" if gate_result["admitted"] else "reject: " + "; ".join(gate_result["reasons"])
        lines.append(
            "| {rank} | [{repo}]({url}) | {stars:,} | {forks:,} | {reach} | "
            "{community} | {activity} | {longevity} | {score} | {status} | {advisories} |".format(
                rank=item["popularity_rank"],
                repo=item["repository"],
                url=item["url"],
                stars=item["stars"],
                forks=item["forks"],
                reach=components["star_reach"],
                community=components["community_breadth"],
                activity=components["maintenance_activity"],
                longevity=components["longevity"],
                score=item["popularity_score"],
                status=status,
                advisories=item["advisory_count"],
            )
        )

    lines.extend(
        [
            "",
            "## Known limitations",
            "",
            "- This is a GitHub popularity proxy, not a direct measurement of deployments,",
            "  package downloads, downstream dependents, or organizational usage.",
            "- Discovery recall is separate: a project cannot be ranked if no discovery lane",
            "  adds it to the project snapshot.",
            "- Repository links are accepted only from OSV affected GIT ranges or strong",
            "  PACKAGE/FIX/ADVISORY references. Records without such links are absent.",
            "- OSV aliases are deduplicated by CVE, then GHSA, then source identifier.",
            "- Feed presence does not guarantee that OSV maps every product to its source repository.",
            "",
            "## Next gate",
            "",
            "Apply application-shape, license, advisory-history, exploit-depth, defense-depth,",
            "arena-feasibility, and portfolio-diversity review to the admitted projects.",
            "",
        ]
    )
    return "\n".join(lines)


def _apply_popularity_gate(
    ranked: list[dict], *, min_score: int, limit: int | None
) -> list[dict]:
    admitted_count = 0
    results = []
    for rank, item in enumerate(ranked, 1):
        reasons = []
        if item.get("archived"):
            reasons.append("archived")
        if item["popularity_score"] < min_score:
            reasons.append(f"score {item['popularity_score']} below {min_score}")
        if not reasons and limit is not None and admitted_count >= limit:
            reasons.append(f"outside top {limit}")
        admitted = not reasons
        if admitted:
            admitted_count += 1
        results.append(
            {
                **item,
                "popularity_rank": rank,
                "popularity_gate": {
                    "admitted": admitted,
                    "reasons": reasons,
                },
            }
        )
    return results


def generate(
    *,
    projects_path: Path,
    advisories_path: Path,
    output_json: Path,
    output_markdown: Path,
    min_popularity_score: int,
    limit: int | None,
) -> dict:
    projects, project_source = _load(projects_path, "projects")
    advisories, advisory_source = _load(advisories_path, "advisories")
    generated_at = datetime.now(timezone.utc).isoformat()
    ranking_as_of = max(
        source["generated_at"]
        for source in (project_source, advisory_source)
        if source["generated_at"]
    )
    all_evidence = merge_and_rank(projects, advisories, as_of=ranking_as_of)
    discovered = [
        item
        for item in all_evidence
        if item["discovery_lane"] in {"both", "project"}
    ]
    ranked_projects = _apply_popularity_gate(
        discovered,
        min_score=min_popularity_score,
        limit=limit,
    )
    admitted = [item for item in ranked_projects if item["popularity_gate"]["admitted"]]
    payload = {
        "schema_version": 2,
        "generated_at": generated_at,
        "ranking_as_of": ranking_as_of,
        "sources": {"projects": project_source, "advisories": advisory_source},
        "popularity_gate": {
            "min_score": min_popularity_score,
            "limit": limit,
            "axes": POPULARITY_AXES,
        },
        "input_counts": {
            "projects": len(projects),
            "advisories": len(advisories),
            "both": sum(item["discovery_lane"] == "both" for item in discovered),
            "project_only": sum(item["discovery_lane"] == "project" for item in discovered),
            "advisory_only": sum(item["discovery_lane"] == "advisory" for item in all_evidence),
            "admitted": len(admitted),
            "rejected": len(ranked_projects) - len(admitted),
        },
        "portfolio": {
            "languages": dict(Counter(item.get("language") or "Unknown" for item in admitted)),
            "categories": dict(Counter(item["primary_category"] for item in admitted)),
        },
        "ranked_projects": ranked_projects,
        "shortlist": admitted,
    }
    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_markdown.parent.mkdir(parents=True, exist_ok=True)
    output_json.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    output_markdown.write_text(_markdown(payload))
    return payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--projects", type=Path, required=True)
    parser.add_argument("--advisories", type=Path, required=True)
    parser.add_argument("--output-json", type=Path, required=True)
    parser.add_argument("--output-markdown", type=Path, required=True)
    parser.add_argument("--min-popularity-score", type=int, default=75)
    parser.add_argument("--limit", type=int)
    args = parser.parse_args(argv)
    if not 0 <= args.min_popularity_score <= 100:
        parser.error("--min-popularity-score must be between 0 and 100")
    if args.limit is not None and args.limit < 1:
        parser.error("--limit must be positive")
    payload = generate(
        projects_path=args.projects,
        advisories_path=args.advisories,
        output_json=args.output_json,
        output_markdown=args.output_markdown,
        min_popularity_score=args.min_popularity_score,
        limit=args.limit,
    )
    print(
        f"ranked {len(payload['ranked_projects'])} projects; "
        f"admitted {len(payload['shortlist'])} to {args.output_markdown}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
