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
    cut = graph.advisory_cut
    cut_rows = [
        ["advisory", str(cut.get("advisory") or "—")],
        ["nodes it guarded", ", ".join(cut.get("nodes") or []) or "—"],
        ["routes that refused every request tried",
         ", ".join(e["path"] for e in cut.get("refused") or []) or "—"],
        ["routes it left open",
         ", ".join(e["path"] for e in cut.get("survived") or []) or "—"],
    ] if cut else []
    cut_note = (
        "This records the supplied upstream fix and its observed result against "
        "each route. A route under **left open** reached the objective with this "
        "repair applied."
        if cut
        else "No repaired comparison was supplied."
    )
    parts = [
        f"# Challenge graph: {target['id']}",
        "",
        f"`{target['repository']}` at `{target['revision']}`. "
        f"Geometry **{', '.join(analysis['geometry']) or 'none'}**, "
        f"{len(graph.paths)} recorded path(s), {len(graph.by_role('objective'))} objective(s).",
        "",
        "Geometry describes the recorded routes only; it does not claim that no "
        "additional route exists. The entry set must match the identity and "
        "access the challenge grants the attacker.",
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
            ["route", "objective", "required nodes", "advisories", "witnesses"],
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
        "## Repaired comparison",
        "",
        _table(
            ["", "value"],
            cut_rows,
        ),
        cut_note,
        "",
        "## Objective coverage",
        "",
        _table(
            ["objective", "scope", "routes"],
            [
                [objective, str(detail["scope"]), str(detail["routes"])]
                for objective, detail in analysis["objective_coverage"].items()
            ],
        ),
        "",
    ]
    return "\n".join(parts)
