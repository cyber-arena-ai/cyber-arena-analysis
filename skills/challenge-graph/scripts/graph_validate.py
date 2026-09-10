#!/usr/bin/env python3
"""Validate a challenge graph. Nothing outside the graph is read."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from _graph import load


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("graph", type=Path)
    parser.add_argument(
        "--scope-registry",
        type=Path,
        required=True,
        help="attack-scopes.json; objective scopes are checked against it",
    )
    args = parser.parse_args()

    document, errors = load(args.graph, args.scope_registry)
    for error in errors:
        print(error, file=sys.stderr)
    if errors:
        return 1
    print(f"{args.graph}: valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
