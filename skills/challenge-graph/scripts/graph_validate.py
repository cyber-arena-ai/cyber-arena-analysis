#!/usr/bin/env python3
"""Validate a challenge graph and resolve every evidence locator."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from _graph import LOCATOR, Graph, load, structural_errors


def _evidence_entries(graph: Graph) -> list[tuple[str, dict]]:
    entries: list[tuple[str, dict]] = []
    for op_id, operation in graph.operations.items():
        entries.append((f"operation {op_id}", operation.get("evidence", {})))
    for path_id, path in graph.paths.items():
        entries.append((f"path {path_id}", path.get("evidence", {})))
    for cut in graph.observed_cuts:
        for key in ("blocked", "survived"):
            for entry in cut.get(key, []):
                if isinstance(entry, dict):
                    entries.append((f"cut {cut['id']} {key} {entry.get('path')}", entry))
    return entries


def evidence_errors(graph: Graph, study_dir: Path) -> list[str]:
    """Resolve each locator to a real line holding the observed string."""
    errors: list[str] = []
    root = Path(str(graph.document.get("evidence_root", "")))
    for where, evidence in _evidence_entries(graph):
        match = LOCATOR.match(str(evidence.get("locator", "")))
        if not match:
            continue
        relative = Path(match.group("path"))
        if relative.is_absolute() or ".." in relative.parts:
            errors.append(f"{where} locator must stay inside the study directory")
            continue
        if root.parts and relative.parts[: len(root.parts)] != root.parts:
            errors.append(f"{where} locator must stay inside {root}")
            continue
        resolved = study_dir / relative
        if not resolved.is_file():
            errors.append(f"{where} locator does not exist: {relative}")
            continue
        lines = resolved.read_text(encoding="utf-8", errors="replace").splitlines()
        number = int(match.group("line"))
        if number > len(lines):
            errors.append(f"{where} locator points past the end of {relative}")
            continue
        if str(evidence.get("observed", "")) not in lines[number - 1]:
            errors.append(
                f"{where} observed string is not on {relative} line {number}"
            )
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("graph", type=Path)
    parser.add_argument(
        "--study-dir",
        type=Path,
        required=True,
        help="Stage 3 study directory that evidence locators resolve against",
    )
    args = parser.parse_args()

    document = load(args.graph)
    errors = structural_errors(document)
    if not errors:
        errors = evidence_errors(Graph(document), args.study_dir)
    for error in errors:
        print(error, file=sys.stderr)
    if errors:
        return 1
    print(f"{args.graph}: valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
