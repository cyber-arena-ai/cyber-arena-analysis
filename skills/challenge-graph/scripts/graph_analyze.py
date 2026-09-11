#!/usr/bin/env python3
"""Compute geometry and objective coverage for a challenge graph."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from _graph import Graph, analyze, load


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("graph", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument(
        "--scope-registry",
        type=Path,
        required=True,
        help="attack-scopes.json; objective scopes are checked against it",
    )
    args = parser.parse_args()

    document, errors = load(args.graph, args.scope_registry)
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    args.out.parent.mkdir(parents=True, exist_ok=True)

    graph = Graph(document)
    analysis = analyze(graph)
    args.out.write_text(json.dumps(analysis, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"{args.out}: geometry={','.join(analysis['geometry']) or 'none'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
