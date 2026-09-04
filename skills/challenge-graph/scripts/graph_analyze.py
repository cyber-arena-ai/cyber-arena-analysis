#!/usr/bin/env python3
"""Compute cuts, geometry, coverage, and the open frontier for a challenge graph."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from _graph import Graph, analyze, load, structural_errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("graph", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    document = load(args.graph)
    errors = structural_errors(document)
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1

    analysis = analyze(Graph(document))
    args.out.write_text(json.dumps(analysis, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"{args.out}: geometry={','.join(analysis['geometry']) or 'none'} "
          f"mincut_all={analysis['mincut_all']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
