#!/usr/bin/env python3
"""Render a challenge graph as a Mermaid diagram with summary tables."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from _graph import Graph, analyze, read_graph, validate

SHAPES = {
    "entry": '{id}(["{label}"]):::entry',
    "objective": '{id}{{{{"{label}"}}}}:::obj',
    "intermediate": '{id}("{label}")',
}
CLASSDEFS = [
    "classDef entry fill:#eef,stroke:#446",
    "classDef obj fill:#fee,stroke:#a44,stroke-width:2px",
    "classDef op fill:#fff,stroke:#888",
]


def _node(identifier: str, seen: dict[str, str]) -> str:
    """Mermaid-safe id that stays injective: ST-m.1 and ST-m-1 must not merge."""
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


def _state_label(state: dict) -> str:
    if state.get("role") == "objective":
        return f"{state.get('store')} · {state.get('scope')}"
    return state.get("title") or state["id"]


def diagram(graph: Graph, analysis: dict) -> str:
    seen: dict[str, str] = {}
    lines = ["```mermaid", "flowchart LR", *(f"  {c}" for c in CLASSDEFS), ""]
    for state_id, state in graph.states.items():
        shape = SHAPES.get(state.get("role"), SHAPES["intermediate"])
        lines.append("  " + shape.format(id=_node(state_id, seen), label=_label(_state_label(state))))
    for op_id, operation in graph.operations.items():
        label = _label(operation.get("title") or op_id)
        lines.append(f'  {_node(op_id, seen)}["{label}"]:::op')
    lines.append("")

    implicated = {
        op
        for cut in analysis["observed_cuts"]
        for op in cut["implicated_operations"]
    }
    marked: list[int] = []
    index = 0
    for op_id, operation in graph.operations.items():
        for state_id in operation.get("requires", []):
            lines.append(f"  {_node(state_id, seen)} --> {_node(op_id, seen)}")
            if op_id in implicated:
                marked.append(index)
            index += 1
        for state_id in operation.get("produces", []):
            lines.append(f"  {_node(op_id, seen)} --> {_node(state_id, seen)}")
            if op_id in implicated:
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
    out += ["| " + " | ".join(r) + " |" for r in rows]
    return "\n".join(out) + "\n"


def report(graph: Graph, analysis: dict) -> str:
    target = graph.document["target"]
    tested = {
        path: cut["id"]
        for cut in analysis["observed_cuts"]
        for path in cut["blocked"] + cut["survived"]
    }
    parts = [
        f"# Challenge graph: {target['id']}",
        "",
        f"`{target['repository']}` at `{target['revision']}`. "
        f"Geometry **{', '.join(analysis['geometry']) or 'none'}**, "
        f"`mincut_all` **{analysis['mincut_all']}**, "
        f"{len(graph.paths)} recorded path(s), {len(graph.by_role('objective'))} objective(s).",
        "",
        "Cuts and geometry are computed over the *recorded* subgraph. A larger "
        "min-cut is sound; a small one may only mean no further path was recorded yet.",
        "",
        diagram(graph, analysis),
        "",
        "Dashed red edges are operations an observed cut implicated.",
        "",
        "## Paths",
        "",
        _table(
            ["path", "objective", "operations", "nontrivial", "advisory", "observed in"],
            [
                [
                    path_id,
                    str(path.get("objective")),
                    str(len(path.get("operations", []))),
                    "yes" if analysis["nontrivial_paths"][path_id] else "**no**",
                    "yes" if path.get("advisory_backed") else "no",
                    tested.get(path_id, "—"),
                ]
                for path_id, path in graph.paths.items()
            ],
        ),
        "## Minimum-cost cuts protecting every objective",
        "",
        _table(
            ["size", "operations"],
            [[str(len(c)), ", ".join(c)] for c in analysis["minimum_cuts_all"]],
        ),
        "## Objective coverage",
        "",
        _table(
            ["objective", "scope", "paths", "mincut"],
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

    document, errors = read_graph(args.graph)
    if document is not None:
        errors = validate(document, args.study_dir, args.scope_registry)
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    args.out.parent.mkdir(parents=True, exist_ok=True)

    graph = Graph(document)
    args.out.write_text(report(graph, analyze(graph)), encoding="utf-8")
    print(f"{args.out}: rendered")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
