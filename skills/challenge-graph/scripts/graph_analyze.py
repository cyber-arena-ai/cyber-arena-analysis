#!/usr/bin/env python3
"""Compute cuts, geometry, coverage, and the open frontier for a challenge graph."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from _graph import Graph, analyze, read_graph, validate


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

    analysis = analyze(Graph(document))
    args.out.write_text(json.dumps(analysis, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"{args.out}: geometry={','.join(analysis['geometry']) or 'none'} "
          f"mincut_all={analysis['mincut_all']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
