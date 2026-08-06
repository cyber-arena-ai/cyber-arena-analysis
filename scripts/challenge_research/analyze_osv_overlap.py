#!/usr/bin/env python3
"""Build a lossless project OSV history and find explicit-version overlap."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

try:
    from .osv_history import analyze_overlap, build_components, select_project_records
except ImportError:  # direct execution
    from osv_history import analyze_overlap, build_components, select_project_records


def _checkpoint(value: str) -> tuple[str, str]:
    label, separator, version = value.partition("=")
    if not label:
        raise argparse.ArgumentTypeError("checkpoint label cannot be empty")
    return (label, version) if separator else (label, label)


def generate(
    *,
    raw_dir: Path,
    repository: str,
    packages: set[str],
    checkpoints: list[tuple[str, str]] | None,
) -> dict:
    records, resolved_packages, selection = select_project_records(
        raw_dir, repository, packages
    )
    components = build_components(records)
    return {
        "schema_version": 1,
        "repository": repository.lower(),
        "packages": sorted(resolved_packages),
        "source": {
            "raw_dir": str(raw_dir),
            **selection,
        },
        "component_count": len(components),
        "components": components,
        "overlap": analyze_overlap(components, resolved_packages, checkpoints),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw-dir", type=Path, required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--package", action="append", default=[])
    parser.add_argument(
        "--checkpoint",
        action="append",
        type=_checkpoint,
        help="ordered LABEL=VERSION checkpoint; repeat to compare releases",
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)

    if not args.raw_dir.is_dir():
        parser.error(f"raw OSV directory does not exist: {args.raw_dir}")
    payload = generate(
        raw_dir=args.raw_dir,
        repository=args.repository,
        packages=set(args.package),
        checkpoints=args.checkpoint,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    selection = payload["overlap"]["selection"]
    print(
        f"wrote {payload['component_count']} alias-connected components; "
        f"maximum explicit overlap {selection['maximum_count']} at "
        f"{', '.join(selection['maximal_checkpoints']) or 'no checkpoint'}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
