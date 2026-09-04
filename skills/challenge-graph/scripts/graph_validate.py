#!/usr/bin/env python3
"""Validate a challenge graph and resolve every evidence locator."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from _graph import read_graph, validate


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("graph", type=Path)
    parser.add_argument(
        "--study-dir",
        type=Path,
        required=True,
        help="Stage 3 study directory that evidence locators resolve against",
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
    for error in errors:
        print(error, file=sys.stderr)
    if errors:
        return 1
    print(f"{args.graph}: valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
