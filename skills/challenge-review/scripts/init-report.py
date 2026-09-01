#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from _contracts import ACTIVE_STAGES, CHECKS, CONTEXT_KEYS, SCHEMA_VERSION, STAGE_ORDER


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Initialize a compact challenge-review draft.")
    parser.add_argument("--context", type=Path, required=True)
    parser.add_argument("--scope", choices=sorted(ACTIVE_STAGES), required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)

    try:
        raw_context = json.loads(args.context.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    missing = [key for key in CONTEXT_KEYS if key not in raw_context]
    if missing:
        print(f"error: context missing {missing}", file=sys.stderr)
        return 1
    if args.output.exists():
        print(f"error: refusing to overwrite {args.output}", file=sys.stderr)
        return 1

    active = ACTIVE_STAGES[args.scope]
    report = {
        "schema_version": SCHEMA_VERSION,
        "scope": args.scope,
        "context": {key: raw_context[key] for key in CONTEXT_KEYS},
        "objectives": [],
        "stages": [
            {
                "stage": stage,
                "status": "NOT_RUN",
                "summary": "DRAFT: complete this stage." if stage in active else "Outside selected scope.",
            }
            for stage in STAGE_ORDER
        ],
        "checks": [
            {
                "check_id": check_id,
                "stage": stage,
                "status": "NOT_RUN",
                "summary": "DRAFT: record a concise conclusion.",
                "evidence": [],
                "next_check": None,
            }
            for check_id, stage in CHECKS if stage in active
        ],
        "findings": [],
        "unresolved": [],
        "wip_observations": [],
        "verdict": {"value": "DRAFT", "summary": "DRAFT: adjudicate after review."},
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
