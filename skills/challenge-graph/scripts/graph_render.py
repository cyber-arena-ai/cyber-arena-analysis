#!/usr/bin/env python3
"""Render a challenge graph as a Mermaid diagram with summary tables."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from _graph import Graph, analyze, discriminator_warnings, load

SHAPES = {
    "entry": '{id}(["{label}"]):::entry',
    "objective": '{id}{{{{"{label}"}}}}:::obj',
    "function": '{id}["{label}"]:::fn',
}
CLASSDEFS = [
    "classDef entry fill:#eef,stroke:#446",
    "classDef obj fill:#fee,stroke:#a44,stroke-width:2px",
    "classDef fn fill:#fff,stroke:#888",
]


def _node(identifier: str, seen: dict[str, str]) -> str:
    """Mermaid-safe id that stays injective: N-m.1 and N-m-1 must not merge."""
    if identifier in seen:
        return seen[identifier]
    base = re.sub(r"\W", "_", identifier)
    name = base
    suffix = 2
    while name in seen.values():
        name = f"{base}__{suffix}"
        suffix += 1
    seen[identifier] = name
    return name


def _label(text: str) -> str:
    return re.sub(r"\s+", " ", str(text)).replace('"', "'").replace("|", "/")


def _node_label(node: dict) -> str:
    if node.get("role") == "objective":
        return f"{node.get('store')} · {node.get('scope')}"
    return node.get("title") or node["id"]


def diagram(graph: Graph, analysis: dict) -> str:
    seen: dict[str, str] = {}
    # Top-down: authored node titles run long, and a left-to-right chain of them
    # is many screens wide.
    lines = ["```mermaid", "flowchart TD", *(f"  {c}" for c in CLASSDEFS), ""]
    for node_id, node in graph.nodes.items():
        shape = SHAPES[node["role"]]
        lines.append(
            "  " + shape.format(id=_node(node_id, seen), label=_label(_node_label(node)))
        )
    lines.append("")

    implicated = {n for cut in analysis["observed_cuts"] for n in cut["implicated_nodes"]}
    marked: list[int] = []
    index = 0
    for node_id, node in graph.nodes.items():
        for required in node.get("requires", []) or []:
            lines.append(f"  {_node(required, seen)} --> {_node(node_id, seen)}")
            if node_id in implicated:
                marked.append(index)
            index += 1
    for edge in marked:
        lines.append(f"  linkStyle {edge} stroke:#a44,stroke-dasharray:4")
    lines.append("```")
    return "\n".join(lines)


def _table(header: list[str], rows: list[list[str]]) -> str:
    if not rows:
        return "_none_\n"
    out = ["| " + " | ".join(header) + " |", "|" + "---|" * len(header)]
    out += ["| " + " | ".join(_label(c) for c in r) + " |" for r in rows]
    return "\n".join(out) + "\n"


def report(graph: Graph, analysis: dict, warnings: list[dict]) -> str:
    target = graph.document["target"]
    parts = [
        f"# Challenge graph: {target['id']}",
        "",
        f"`{target['repository']}` at `{target['revision']}`. "
        f"Geometry **{', '.join(analysis['geometry']) or 'none'}**, "
        f"`mincut_all` **{analysis['mincut_all']}**, "
        f"{len(graph.paths)} recorded path(s), {len(graph.by_role('objective'))} objective(s).",
        "",
        "Cuts are computed over the *recorded* routes and exclude the terminals, "
        "so a larger min-cut is sound while a small one may only mean no further "
        "route was recorded yet. **This graph does not say which cuts are "
        "allowed** — that needs the functionality checker and belongs to challenge "
        "authoring. The entry set is an unchecked author claim: a node declared "
        "`entry` leaves every cut, so check that it really is the identity the "
        "challenge grants the attacker.",
        "",
        diagram(graph, analysis),
        "",
        "Dashed red edges enter a node an observed cut implicated.",
        "",
        "## Nodes",
        "",
        _table(
            ["node", "role", "symbol", "requires"],
            [
                [
                    node_id,
                    str(node.get("role")),
                    str(node.get("symbol") or "—"),
                    (" **and** " if node.get("requires_all") else " *or* ").join(
                        node.get("requires") or []
                    )
                    or "—",
                ]
                for node_id, node in graph.nodes.items()
            ],
        ),
        "## Routes",
        "",
        _table(
            ["path", "objective", "nodes", "interior", "chain", "advisories", "witnesses"],
            [
                [
                    path_id,
                    str(path.get("objective")),
                    str(len(path.get("nodes", []))),
                    str(len(graph.interior(path_id))),
                    "yes" if analysis["nontrivial_paths"][path_id] else "**no**",
                    ", ".join(path.get("advisories") or []) or "—",
                    str(len(path.get("witnesses") or [])),
                ]
                for path_id, path in graph.paths.items()
            ],
        ),
        "## Candidate cuts (cheapest, admissibility not judged)",
        "",
        _table(
            ["size", "nodes"],
            [[str(len(c)), ", ".join(c)] for c in analysis["minimum_cuts_all"]],
        ),
        "## Objective coverage",
        "",
        _table(
            ["objective", "scope", "routes", "mincut"],
            [
                [objective, str(detail["scope"]), str(len(detail["paths"])), str(detail["mincut"])]
                for objective, detail in analysis["objective_coverage"].items()
            ],
        ),
        "## Observed cuts",
        "",
        _table(
            ["cut", "reference", "blocked", "survived", "reading"],
            [
                [
                    cut["id"],
                    str(cut["reference"]),
                    ", ".join(cut["blocked"]) or "—",
                    ", ".join(cut["survived"]) or "—",
                    cut["reading"],
                ]
                for cut in analysis["observed_cuts"]
            ],
        ),
        "## Frontier",
        "",
        _table(
            ["kind", "target"],
            [[item["kind"], item["target"]] for item in analysis["frontier"]],
        ),
        f"Citations resting on the study document: "
        f"**{analysis['citation_sources']['study_document']}**; "
        f"citing retained output: "
        f"**{analysis['citation_sources']['retained_evidence']}**.",
        "",
        "## Citation warnings",
        "",
        _table(
            ["where", "detail"],
            [[w["where"], w["detail"]] for w in warnings],
        ),
    ]
    return "\n".join(parts)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("graph", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument(
        "--study-dir",
        type=Path,
        required=True,
        help="Stage 3 study directory; the graph is fully validated before use",
    )
    parser.add_argument(
        "--scope-registry",
        type=Path,
        help="attack-scopes.json; when given, objective scopes are checked against it",
    )
    args = parser.parse_args()

    document, errors = load(args.graph, args.study_dir, args.scope_registry)
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    args.out.parent.mkdir(parents=True, exist_ok=True)

    graph = Graph(document)
    warnings = discriminator_warnings(graph, args.study_dir)
    args.out.write_text(report(graph, analyze(graph), warnings), encoding="utf-8")
    print(f"{args.out}: rendered")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
