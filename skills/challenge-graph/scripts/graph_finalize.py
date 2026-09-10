#!/usr/bin/env python3
"""Check a finished deliverable and render its findings.

The last step of a run has no downstream consumer, so nothing else would
reject a partial or malformed tree — it would simply be read as finished. This
checks what the root wrote, against the graph it wrote it about, and renders
`findings.md` from `provenance.json` so the two cannot drift.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from _graph import Graph, analyze, load, _text
from graph_render import report

ARTIFACTS = ("graph.json", "analysis.json", "provenance.json")


def provenance_errors(record: object) -> list[str]:
    """The fields only the root can supply, checked for being there at all."""
    if not isinstance(record, dict):
        return ["provenance.json must be a JSON object"]
    errors: list[str] = []
    # The one sentence naming what was wrong with the application. Unchecked, a
    # deliverable shipped clean with "_not stated_" where its whole point goes.
    fault = record.get("fault")
    if not isinstance(fault, dict) or not _text(fault.get("statement")):
        errors.append("provenance.fault.statement must name the fault in one sentence")

    raw = record.get("unsettled")
    if raw is not None and not isinstance(raw, list):
        errors.append("provenance.unsettled must be a list")
    else:
        for index, item in enumerate(raw or []):
            if not isinstance(item, dict):
                errors.append(f"unsettled {index} must be an object, not a bare string")
                continue
            for field in ("claim", "reaches_fault_by", "check", "blocked_by"):
                if not _text(item.get(field)):
                    errors.append(f"unsettled {index} must carry {field}")
    notes = record.get("notes")
    if notes is not None and (not isinstance(notes, list) or not all(_text(n) for n in notes)):
        # A string here renders one bullet per character.
        errors.append("provenance.notes must be a list of strings")
    return errors


def merge_errors(merged: object, graph: Graph) -> list[str]:
    """The merge's own record of the union it performed.

    Attribution is a fact the merge established. Reading it here rather than
    from `provenance.json` means the root cannot mistype it, and a
    route whose author is missing is a merge that did not happen.
    """
    if not isinstance(merged, dict):
        return ["merge.json must be a JSON object"]
    routes = merged.get("routes")
    if not isinstance(routes, dict):
        return ["merge.json has no routes map; it was not written by graph_merge.py"]
    errors = [f"merge.json does not say which role found {p}"
              for p in sorted(set(graph.paths) - set(routes))]
    errors += [f"merge.json names {p}, which is not a route in the graph"
               for p in sorted(set(routes) - set(graph.paths))]
    return errors


def derived_errors(out: Path, graph: Graph) -> list[str]:
    """`analysis.json` is computed from `graph.json`, so it can be recomputed.
    (`graph.md` is too, but it is rewritten here unconditionally, so it cannot
    drift and is not compared.) Being present said nothing: a graph repaired during
    Adjudicate and shipped without re-running Derive carries an analysis of the older
    graph."""
    analysis = analyze(graph)

    errors = []
    try:
        # Compared parsed, not as text: this checks that the analysis is of *this*
        # graph, not that it was serialised the way graph_analyze.py serialises.
        if json.loads((out / "analysis.json").read_text(encoding="utf-8")) != analysis:
            errors.append("analysis.json was not derived from this graph.json; re-run Derive")
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        errors.append("analysis.json is not the JSON graph_analyze.py writes")
    return errors


def findings(record: dict, merged: dict, graph: Graph) -> str:
    fault = record["fault"]
    parts = [
        f"# Findings: {graph.document['target']['id']}",
        "",
        f"`{graph.document['target']['repository']}` at "
        f"`{graph.document['target']['revision']}`.",
        "",
        "## Fault",
        "",
        str(fault["statement"]),
        "",
    ]
    parts += ["## Unsettled", ""]
    parts += [
        f"- {item['claim']}\n  - reaches the fault by: {item['reaches_fault_by']}"
        f"\n  - check: {item['check']}\n  - blocked by: {item['blocked_by']}"
        for item in record.get("unsettled") or []
    ] or ["_none_"]
    parts += ["", "## Notes", ""]
    notes = record.get("notes") or []
    parts += [f"- {note}" for note in notes] or ["_none — the analysis and the study agreed_"]
    parts += ["", "## Attribution", ""]
    parts += [f"- `{path}` — {role}" for path, role in sorted(merged["routes"].items())]
    return "\n".join(parts) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("out", type=Path, help="the deliverable directory")
    parser.add_argument(
        "--merge-record", type=Path, required=True,
        help="<run>/merge.json: which role found each route",
    )
    parser.add_argument("--scope-registry", type=Path, required=True)
    args = parser.parse_args()

    missing = [name for name in ARTIFACTS if not (args.out / name).is_file()]
    if missing:
        for name in missing:
            print(f"deliverable is missing {name}", file=sys.stderr)
        return 1

    document, errors = load(args.out / "graph.json", args.scope_registry)
    if errors:
        for error in errors:
            print(f"graph.json: {error}", file=sys.stderr)
        return 1
    graph = Graph(document)
    # `paths` may be empty in a fragment; a finished deliverable with no route
    # records nothing, and this is the step that owns finished trees.
    if not graph.paths:
        print("graph.json records no route", file=sys.stderr)
        return 1

    payload = {}
    for label, path in (("provenance.json", args.out / "provenance.json"),
                        ("merge.json", args.merge_record)):
        try:
            payload[label] = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            print(f"{label} could not be read: {exc}", file=sys.stderr)
            return 1
    record, merged = payload["provenance.json"], payload["merge.json"]

    errors = (provenance_errors(record) + derived_errors(args.out, graph)
              + merge_errors(merged, graph))
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1

    (args.out / "graph.md").write_text(report(graph, analyze(graph)), encoding="utf-8")
    (args.out / "findings.md").write_text(findings(record, merged, graph), encoding="utf-8")
    print(f"{args.out}: complete, findings.md rendered")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
