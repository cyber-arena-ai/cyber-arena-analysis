#!/usr/bin/env python3
"""Render a challenge graph as a Mermaid diagram with summary tables.

Imported by `graph_finalize.py`, which writes `graph.md` as part of checking the
deliverable. There is no CLI: a derived artifact the root produces by hand is one
the last step has to verify, and deriving it there instead removes both.
"""

from __future__ import annotations

import re
from pathlib import Path

from _graph import Graph, analyze, load

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


def diagram(graph: Graph) -> str:
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

    for node_id, node in graph.nodes.items():
        for required in node.get("predecessors", []) or []:
            lines.append(f"  {_node(required, seen)} --> {_node(node_id, seen)}")
    lines.append("```")
    return "\n".join(lines)


def _table(header: list[str], rows: list[list[str]]) -> str:
    if not rows:
        return "_none_\n"
    out = ["| " + " | ".join(header) + " |", "|" + "---|" * len(header)]
    out += ["| " + " | ".join(_label(c) for c in r) + " |" for r in rows]
    return "\n".join(out) + "\n"


def report(graph: Graph, analysis: dict) -> str:
    target = graph.document["target"]
    parts = [
        f"# Challenge graph: {target['id']}",
        "",
        f"`{target['repository']}` at `{target['revision']}`. "
        f"Geometry **{', '.join(analysis['geometry']) or 'none'}**, "
        f"`mincut_all` **{analysis['mincut_all']}**, "
        f"{len(graph.paths)} recorded path(s), {len(graph.by_role('objective'))} objective(s).",
        "",
        "The min-cut is computed over the *recorded* routes and excludes the "
        "terminals, so a larger size is sound while a small one may only mean no "
        "further route was recorded yet. It says how many nodes a defender would "
        "have to touch, never which ones are allowed to be touched — that needs "
        "the functionality checker and belongs to challenge authoring. The entry "
        "set is an unchecked author claim: a node declared `entry` leaves every "
        "cut, so check that it really is the identity the challenge grants the "
        "attacker.",
        "",
        diagram(graph),
        "",
        "## Nodes",
        "",
        _table(
            ["node", "role", "symbol", "predecessors"],
            [
                [
                    node_id,
                    str(node.get("role")),
                    str(node.get("symbol") or "—"),
                    (" **and** " if node.get("conjunctive") else " *or* ").join(
                        node.get("predecessors") or []
                    )
                    or "—",
                ]
                for node_id, node in graph.nodes.items()
            ],
        ),
        "## Routes",
        "",
        _table(
            ["route", "objective", "walk", "advisories", "witnesses"],
            [
                [
                    path_id,
                    str(path.get("objective")),
                    " → ".join(path.get("nodes", [])),
                    ", ".join(path.get("advisories") or []) or "—",
                    str(len(path.get("witnesses") or [])),
                ]
                for path_id, path in graph.paths.items()
            ],
        ),
        "## The cut the advisory accepted",
        "",
        _table(
            ["", "value"],
            [
                ["advisory", str(cut.get("advisory") or "—")],
                ["nodes it guarded", ", ".join(cut.get("nodes") or []) or "—"],
                ["routes that refused every request tried",
                 ", ".join(e["path"] for e in cut.get("refused") or []) or "—"],
                ["routes it left open",
                 ", ".join(e["path"] for e in cut.get("survived") or []) or "—"],
            ] if (cut := graph.advisory_cut) else [],
        ),
        "This is the one cut here whose admissibility is known: upstream shipped "
        "it and the project kept working. Every cut *size* above is a candidate "
        "nobody has judged. A route under **left open** reached the objective "
        "with this repair applied.",
        "",
        "## Objective coverage",
        "",
        _table(
            ["objective", "scope", "routes", "mincut"],
            [
                [objective, str(detail["scope"]), str(detail["routes"]), str(detail["mincut"])]
                for objective, detail in analysis["objective_coverage"].items()
            ],
        ),
        "",
    ]
    return "\n".join(parts)
