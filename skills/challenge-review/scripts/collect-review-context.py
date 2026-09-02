#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import secrets
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import NoReturn

from _contracts import ORCHESTRATOR_COMMIT
from _warehouse import WAREHOUSE_ENV, selected_warehouse


def fail(message: str) -> NoReturn:
    print(f"error: {message}", file=sys.stderr)
    raise SystemExit(1)


def git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args], text=True, capture_output=True, check=False,
    )
    if result.returncode != 0:
        fail(result.stderr.strip() or f"git {' '.join(args)} failed")
    return result.stdout.strip()


def registry_package(repo: Path, challenge_id: str) -> str:
    sys.path.insert(0, str(repo))
    try:
        from challenges.registry import build_challenge, known_challenge_names

        known = known_challenge_names()
        if challenge_id not in known:
            fail(f"unknown challenge {challenge_id!r}; known: {known}")
        challenge = build_challenge(challenge_id)
    except SystemExit:
        raise
    except Exception as exc:
        fail(
            f"registry resolution failed for {challenge_id!r}: "
            f"{type(exc).__name__}: {exc}"
        )
    return type(challenge).__module__.split(".")[1]


def resolve_challenge_dir(warehouse: Path, package: str) -> Path:
    candidates = sorted(
        path for path in warehouse.glob(f"*/{package}")
        if path.is_dir() and (path / "challenge.py").is_file()
    )
    if len(candidates) != 1:
        fail(f"expected one warehouse directory for package {package!r}, found {candidates}")
    return candidates[0]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Initialize deterministic review context.")
    parser.add_argument("challenge_id")
    parser.add_argument("--warehouse", type=Path, required=True)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--review-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)

    if not args.repo_root.is_absolute():
        parser.error("--repo-root must be absolute")
    if not args.challenge_id or any(char.isspace() for char in args.challenge_id):
        fail("provide exactly one challenge id without whitespace")
    try:
        warehouse = selected_warehouse(args.warehouse)
    except ValueError as exc:
        fail(str(exc))
    os.environ[WAREHOUSE_ENV] = str(warehouse)
    repo = args.repo_root.resolve()
    if not (repo / ".git").exists():
        fail(f"not a repository root: {repo}")
    if args.output.exists():
        fail(f"refusing to overwrite {args.output}")

    package = registry_package(repo, args.challenge_id)
    challenge_dir = resolve_challenge_dir(warehouse, package)

    orchestrator_commit = git(repo, "rev-parse", f"{ORCHESTRATOR_COMMIT}^{{commit}}")
    git(repo, "cat-file", "-e", f"{orchestrator_commit}:challenges/check/__main__.py")
    now = datetime.now(timezone.utc).replace(microsecond=0)
    timestamp = now.isoformat().replace("+00:00", "Z")
    run_id = f"{now.strftime('%Y%m%dT%H%M%SZ')}-{secrets.token_hex(4)}"
    payload = {
        "challenge_id": args.challenge_id,
        "challenge_dir": challenge_dir.relative_to(warehouse).as_posix(),
        "timestamp": timestamp,
        "run_id": run_id,
        "orchestrator_commit": orchestrator_commit,
        "warehouse_path": str(warehouse),
        "image_hash": None,
        "challenge_package": package,
        "recommended_output_dir": str(
            args.review_root.resolve() / args.challenge_id / run_id
        ),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8",
    )
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
