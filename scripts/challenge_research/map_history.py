#!/usr/bin/env python3
"""Validate curated OSS revision mappings and render inspectable reports."""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SCOPES = ROOT / "docs/jt/attack_scopes.json"
DEFAULT_HISTORY = ROOT / "docs/jt/oss_candidate_history.json"
DEFAULT_REGISTRY_REPORT = ROOT / "docs/jt/ATTACK_SCOPE_REGISTRY.md"
DEFAULT_HISTORY_REPORT = ROOT / "docs/jt/OSS_CANDIDATE_HISTORY.md"
DEFAULT_EXAMPLE_REPORT = ROOT / "docs/jt/GITEA_CANDIDATE_EXAMPLE.md"

SHA_RE = re.compile(r"[0-9a-f]{40}")
SCOPE_RE = re.compile(r"[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+")

CWE_CATEGORIES = {
    "authorization-access-control": {"CWE-269", "CWE-276", "CWE-284", "CWE-285", "CWE-639", "CWE-732", "CWE-862", "CWE-863"},
    "authentication-session": {"CWE-287", "CWE-294", "CWE-295", "CWE-303", "CWE-305", "CWE-306", "CWE-345", "CWE-346", "CWE-347", "CWE-384", "CWE-522", "CWE-613", "CWE-614", "CWE-640"},
    "injection-execution": {"CWE-74", "CWE-77", "CWE-78", "CWE-88", "CWE-89", "CWE-90", "CWE-94", "CWE-95", "CWE-502", "CWE-611"},
    "path-file-handling": {"CWE-22", "CWE-23", "CWE-24", "CWE-27", "CWE-59", "CWE-61", "CWE-73", "CWE-98", "CWE-434", "CWE-552"},
    "xss-client-content": {"CWE-79", "CWE-80", "CWE-83", "CWE-184"},
    "ssrf-network-boundary": {"CWE-441", "CWE-918"},
    "information-disclosure": {"CWE-200", "CWE-201", "CWE-203", "CWE-204", "CWE-208", "CWE-312", "CWE-359", "CWE-497", "CWE-532"},
    "resource-availability": {"CWE-248", "CWE-362", "CWE-400", "CWE-404", "CWE-406", "CWE-407", "CWE-409", "CWE-476", "CWE-672", "CWE-754", "CWE-770", "CWE-772", "CWE-789", "CWE-799", "CWE-820", "CWE-835"},
    "memory-safety": {"CWE-119", "CWE-120", "CWE-121", "CWE-122", "CWE-125", "CWE-190", "CWE-416", "CWE-787"},
}

KEYWORD_CATEGORIES = {
    "authorization-access-control": ("access control", "authorization", "permission", "private resource"),
    "authentication-session": ("authentication", "credential", "login", "session"),
    "injection-execution": ("command injection", "code execution", "sql injection", "shell"),
    "path-file-handling": ("arbitrary file", "directory traversal", "file read", "path traversal"),
    "xss-client-content": ("cross-site scripting", "stored xss", " xss"),
    "ssrf-network-boundary": ("server-side request forgery", "ssrf"),
    "information-disclosure": ("disclosure", "exposes", "information leak"),
    "resource-availability": ("denial of service", "resource exhaustion"),
}


def load_json(path: Path) -> dict:
    with path.open(encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"{path}: root must be an object")
    return value


def validate(scopes: dict, history: dict) -> None:
    errors: list[str] = []
    scope_ids: set[str] = set()
    for scope in scopes.get("scopes", []):
        scope_id = scope.get("id", "")
        if scope_id in scope_ids:
            errors.append(f"duplicate scope: {scope_id}")
        scope_ids.add(scope_id)
        if not SCOPE_RE.fullmatch(scope_id):
            errors.append(f"invalid scope id: {scope_id}")
        if scope.get("tier") not in {1, 2, 3}:
            errors.append(f"invalid tier for {scope_id}")
        for key in ("title", "capability", "proof_requirement"):
            if not scope.get(key):
                errors.append(f"{scope_id} lacks {key}")

    project_ids: set[str] = set()
    candidate_ids: set[str] = set()
    cves: set[str] = set()
    for project in history.get("projects", []):
        project_id = project.get("id", "")
        if project_id in project_ids:
            errors.append(f"duplicate project: {project_id}")
        project_ids.add(project_id)
        repository = project.get("repository", "")
        source_url = f"https://github.com/{repository}"
        if project.get("source_url") != source_url:
            errors.append(f"{project_id}: source_url does not match repository")
        revisions = [("current", project.get("current_revision", {}))]
        for candidate in project.get("candidates", []):
            candidate_id = candidate.get("id", "")
            if candidate_id in candidate_ids:
                errors.append(f"duplicate candidate: {candidate_id}")
            candidate_ids.add(candidate_id)
            cve = candidate.get("cve", "")
            if cve in cves:
                errors.append(f"duplicate CVE mapping: {cve}")
            cves.add(cve)
            if not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve):
                errors.append(f"{candidate_id}: invalid CVE")
            if not re.fullmatch(r"GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}", candidate.get("ghsa", "")):
                errors.append(f"{candidate_id}: invalid GHSA")
            for scope_id in candidate.get("attack_scopes", []):
                if scope_id not in scope_ids:
                    errors.append(f"{candidate_id}: unknown attack scope {scope_id}")
            for key in ("description", "affected_versions", "vulnerability_categories"):
                if not candidate.get(key):
                    errors.append(f"{candidate_id}: lacks {key}")
            revisions.extend(
                (f"{candidate_id}:{key}", candidate[key])
                for key in ("vulnerable_revision", "fix_revision", "introduction_revision")
                if key in candidate
            )
        for label, revision in revisions:
            commit = revision.get("commit", "")
            expected_url = f"{source_url}/commit/{commit}"
            if not SHA_RE.fullmatch(commit):
                errors.append(f"{project_id}:{label}: invalid commit")
            if revision.get("source_url") != expected_url:
                errors.append(f"{project_id}:{label}: commit URL mismatch")

    if errors:
        raise ValueError("mapping validation failed:\n- " + "\n- ".join(errors))


def advisory_components(records: list[dict], repository: str) -> list[dict]:
    """Deduplicate GHSA/GO/CVE aliases into advisory components."""
    selected = [record for record in records if record.get("repository") == repository]
    parent: dict[str, str] = {}

    def find(item: str) -> str:
        parent.setdefault(item, item)
        if parent[item] != item:
            parent[item] = find(parent[item])
        return parent[item]

    def union(left: str, right: str) -> None:
        left_root, right_root = find(left), find(right)
        if left_root != right_root:
            parent[right_root] = left_root

    for record in selected:
        ids = [record.get("advisory_id", ""), *record.get("aliases", [])]
        ids = [item for item in ids if item]
        for item in ids[1:]:
            union(ids[0], item)

    grouped: dict[str, list[dict]] = defaultdict(list)
    for record in selected:
        ids = [record.get("advisory_id", ""), *record.get("aliases", [])]
        key = find(next(item for item in ids if item))
        grouped[key].append(record)

    components = []
    for group in grouped.values():
        ids = sorted({item for record in group for item in [record.get("advisory_id", ""), *record.get("aliases", [])] if item})
        cwes = sorted({item for record in group for item in record.get("cwes", [])})
        summaries = sorted({record.get("summary", "") for record in group if record.get("summary")})
        components.append({"ids": ids, "cwes": cwes, "summaries": summaries})
    return components


def history_profile(records: list[dict], repository: str) -> tuple[int, list[tuple[str, int]]]:
    components = advisory_components(records, repository)
    counts: Counter[str] = Counter()
    for component in components:
        categories = {
            category
            for category, cwes in CWE_CATEGORIES.items()
            if set(component["cwes"]) & cwes
        }
        summary = " ".join(component["summaries"]).lower()
        categories.update(
            category
            for category, terms in KEYWORD_CATEGORIES.items()
            if any(term in summary for term in terms)
        )
        for category in categories or {"unclassified"}:
            counts[category] += 1
    return len(components), sorted(counts.items(), key=lambda item: (-item[1], item[0]))


def render_registry(scopes: dict) -> str:
    lines = [
        "# Global Attack Scope Registry",
        "",
        "> Generated from `docs/jt/attack_scopes.json`. Edit the JSON source, then rerun the generator.",
        "",
        "Flags prove capabilities, not CVEs. A challenge selects applicable scopes from this registry and records its concrete flag store and proof mechanism in its dossier. Challenge-specific scopes use `custom.<challenge_id>.*` and must define the same fields.",
        "",
        "| Tier | Scope | Capability | Proof requirement |",
        "| --- | --- | --- | --- |",
    ]
    for scope in sorted(scopes["scopes"], key=lambda item: (item["tier"], item["id"])):
        lines.append(f"| {scope['tier']} | `{scope['id']}` — {scope['title']} | {scope['capability']} | {scope['proof_requirement']} |")
    lines.extend([
        "",
        "## Per-challenge mapping rule",
        "",
        "For every planted flag, record: scope ID, local tier ordering, store, authorized baseline identity, proof returned to the scorer, and legitimate workflow that must remain functional. Planting must not add the selected vulnerable path or encode a CVE-specific hint.",
        "",
    ])
    return "\n".join(lines)


def candidate_lines(candidate: dict) -> list[str]:
    vulnerable = candidate["vulnerable_revision"]
    fixed = candidate["fix_revision"]
    scopes = ", ".join(f"`{item}`" for item in candidate["attack_scopes"])
    lines = [
        f"### {candidate['cve']}: {candidate['id']}",
        "",
        candidate["description"],
        "",
        f"- Records: [{candidate['cve']}]({candidate['cve_url']}), [{candidate['ghsa']}]({candidate['advisory_url']}), [OSV]({candidate['osv_url']})",
        f"- Affected versions: {candidate['affected_versions']}",
        f"- Vulnerable baseline: [`{vulnerable['commit']}`]({vulnerable['source_url']}) ({vulnerable['relationship']})",
    ]
    if "introduction_revision" in candidate:
        introduced = candidate["introduction_revision"]
        lines.append(f"- Introduction evidence: [`{introduced['commit']}`]({introduced['source_url']}) — {introduced['message']}")
    lines.extend([
        f"- Upstream fix: [`{fixed['commit']}`]({fixed['source_url']}) — {fixed['message']}",
        f"- Categories: {', '.join(f'`{item}`' for item in candidate['vulnerability_categories'])}",
        f"- Candidate scopes: {scopes}",
        f"- Challenge fit: **{candidate['challenge_fit']['status']}** — {candidate['challenge_fit']['rationale']}",
        "",
    ])
    return lines


def render_history(history: dict, records: list[dict], only_project: str | None = None) -> str:
    title = "Gitea Candidate Mapping — Small Example" if only_project else "OSS Candidate History Pilot"
    lines = [
        f"# {title}",
        "",
        f"> Research cutoff: {history['research_cutoff']}. Status: `{history['status']}`.",
        "",
        "These are source-history mappings, not admitted challenges. Counts below are deduplicated advisory components from the retained OSV snapshot; categories overlap and describe historical pressure, not exploitability or challenge quality.",
        "",
    ]
    projects = [project for project in history["projects"] if not only_project or project["id"] == only_project]
    for project in projects:
        count, categories = history_profile(records, project["repository"])
        current = project["current_revision"]
        lines.extend([
            f"## {project['name']}",
            "",
            f"- Source: [{project['repository']}]({project['source_url']})",
            f"- Current discovery pin: [`{current['commit']}`]({current['source_url']}) on `{current['branch']}`",
            f"- Current-pin advisory status: `{current['advisory_status']}` — {current['note']}",
            f"- Historical snapshot: {count} deduplicated advisory components",
            "- Recurring categories: " + ", ".join(f"`{name}` ({value})" for name, value in categories[:6]),
            "",
        ])
        for candidate in project["candidates"]:
            lines.extend(candidate_lines(candidate))
    if only_project:
        lines.extend([
            "## What to inspect",
            "",
            "The first mapping reaches the common read/write/execute host scopes but still needs a defense-depth review. The second confirms that file-boundary errors recur in this project, yet is explicitly retained only as a history signal. This distinction prevents a famous CVE from being mistaken for an automatically worthy challenge.",
            "",
            "The global definitions and per-challenge proof requirements are in [`ATTACK_SCOPE_REGISTRY.md`](ATTACK_SCOPE_REGISTRY.md).",
            "",
        ])
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scopes", type=Path, default=DEFAULT_SCOPES)
    parser.add_argument("--history", type=Path, default=DEFAULT_HISTORY)
    parser.add_argument("--registry-report", type=Path, default=DEFAULT_REGISTRY_REPORT)
    parser.add_argument("--history-report", type=Path, default=DEFAULT_HISTORY_REPORT)
    parser.add_argument("--example-report", type=Path, default=DEFAULT_EXAMPLE_REPORT)
    parser.add_argument("--check", action="store_true", help="validate inputs and require generated reports to be current")
    args = parser.parse_args()

    scopes = load_json(args.scopes)
    history = load_json(args.history)
    validate(scopes, history)
    snapshot = load_json(ROOT / history["advisory_snapshot"])
    reports = {
        args.registry_report: render_registry(scopes),
        args.history_report: render_history(history, snapshot["advisories"]),
        args.example_report: render_history(history, snapshot["advisories"], "gitea"),
    }
    if args.check:
        stale = [str(path) for path, content in reports.items() if not path.exists() or path.read_text(encoding="utf-8") != content]
        if stale:
            raise SystemExit("stale or missing generated reports:\n- " + "\n- ".join(stale))
        print(f"validated {len(scopes['scopes'])} scopes, {len(history['projects'])} projects, and {sum(len(item['candidates']) for item in history['projects'])} candidate mappings")
        return
    for path, content in reports.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        print(path.relative_to(ROOT))


if __name__ == "__main__":
    main()
