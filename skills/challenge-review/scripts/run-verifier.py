#!/usr/bin/env python3
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

from _contracts import ORCHESTRATOR_COMMIT
from _warehouse import WAREHOUSE_ENV, selected_warehouse


IMAGE_HASH = re.compile(r"^sha256:[0-9a-f]{64}$")


def command_result(command: list[str], cwd: Path, timeout: float) -> dict:
    started = time.monotonic()
    try:
        result = subprocess.run(
            command, cwd=cwd, text=True, capture_output=True,
            timeout=timeout, check=False,
        )
        parsed = None
        try:
            parsed = json.loads(result.stdout)
        except json.JSONDecodeError:
            pass
        return {
            "command": command,
            "cwd": str(cwd),
            "timeout_seconds": timeout,
            "status": "PASS" if result.returncode == 0 else "FAIL",
            "exit_code": result.returncode,
            "duration_seconds": round(time.monotonic() - started, 3),
            "stdout": result.stdout,
            "stderr": result.stderr,
            "parsed_json": parsed,
        }
    except subprocess.TimeoutExpired as exc:
        stdout = (
            exc.stdout.decode(errors="replace")
            if isinstance(exc.stdout, bytes) else exc.stdout or ""
        )
        stderr = (
            exc.stderr.decode(errors="replace")
            if isinstance(exc.stderr, bytes) else exc.stderr or ""
        )
        return {
            "command": command,
            "cwd": str(cwd),
            "timeout_seconds": timeout,
            "status": "FAIL",
            "exit_code": None,
            "duration_seconds": round(time.monotonic() - started, 3),
            "stdout": stdout,
            "stderr": stderr + f"\ncommand timed out after {timeout:g}s",
            "parsed_json": None,
        }
    except OSError as exc:
        return {
            "command": command,
            "cwd": str(cwd),
            "timeout_seconds": timeout,
            "status": "FAIL",
            "exit_code": None,
            "duration_seconds": round(time.monotonic() - started, 3),
            "stdout": "",
            "stderr": f"{type(exc).__name__}: {exc}",
            "parsed_json": None,
        }


def checker_result(command: list[str], cwd: Path, timeout: float) -> dict:
    result = command_result(command, cwd, timeout)
    if result["status"] != "PASS":
        return result
    parsed = result["parsed_json"]
    valid = (
        isinstance(parsed, dict)
        and isinstance(parsed.get("challenge"), str)
        and bool(parsed["challenge"])
        and parsed.get("ok") is True
        and isinstance(parsed.get("checks"), list)
        and bool(parsed["checks"])
    )
    if not valid:
        result["status"] = "FAIL"
        result["stderr"] = (
            f"{result['stderr']}\nchecker did not return successful JSON"
        ).lstrip()
    return result


def git(repo: Path, *args: str, timeout: float = 180.0) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(repo), *args], text=True, capture_output=True,
        timeout=timeout, check=False,
    )


def fail(message: str) -> int:
    print(f"error: {message}", file=sys.stderr)
    return 1


def write_output(path: Path, payload: dict) -> int:
    if path.exists():
        return fail(f"refusing to overwrite {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(path)
    return 0


def built_image_reference(tier_result: dict) -> str | None:
    """Return the canonical build tier's successful image reference."""
    parsed = tier_result.get("parsed_json")
    if not isinstance(parsed, dict):
        return None
    checks = parsed.get("checks")
    if not isinstance(checks, list):
        return None
    matches = [
        check.get("detail")
        for check in checks
        if isinstance(check, dict)
        and check.get("group") == "build"
        and check.get("name") == "image build"
        and check.get("status") == "pass"
        and isinstance(check.get("detail"), str)
        and check["detail"].strip()
    ]
    return matches[0].strip() if len(matches) == 1 else None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the frozen canonical challenge verifier.")
    parser.add_argument("challenge_id")
    parser.add_argument("--warehouse", type=Path, required=True)
    parser.add_argument("--context", type=Path, required=True)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--output", type=Path, required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--dry-run", action="store_true")
    mode.add_argument("--execute", action="store_true")
    parser.add_argument("--tier-timeout", type=float, default=1200.0)
    parser.add_argument("--lock-timeout", type=float, default=30.0)
    args = parser.parse_args(argv)
    if args.tier_timeout <= 0 or args.lock_timeout <= 0:
        parser.error("timeouts must be positive")

    try:
        warehouse = selected_warehouse(args.warehouse)
    except ValueError as exc:
        return fail(str(exc))
    os.environ[WAREHOUSE_ENV] = str(warehouse)
    repo = args.repo_root.resolve()
    try:
        context = json.loads(args.context.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return fail(str(exc))
    if context.get("challenge_id") != args.challenge_id:
        return fail("challenge id does not match review context")
    required = ["orchestrator_commit", "warehouse_path", "run_id"]
    if any(not context.get(key) for key in required):
        return fail(f"context missing one of {required}")
    if context["orchestrator_commit"] != ORCHESTRATOR_COMMIT:
        return fail(f"context must use pinned orchestrator commit {ORCHESTRATOR_COMMIT}")
    if context["warehouse_path"] != str(warehouse):
        return fail("selected warehouse does not match review context")
    worktree = Path("/tmp") / f"cyberarena-verifier-{context['run_id']}"
    tier_args = [[], ["--build", "--ready-timeout", "150"], ["--game", "--ready-timeout", "150"]]
    tiers = []
    for name, extra in zip(["static", "build", "game"], tier_args, strict=True):
        command = [
            sys.executable, "-m", "challenges.check", args.challenge_id,
            *extra, "--json",
        ]
        tiers.append({
            "name": name,
            "command": command,
            "cwd": str(worktree),
            "timeout_seconds": args.tier_timeout,
            "status": "NOT_RUN",
            "exit_code": None,
            "duration_seconds": None,
            "stdout": "",
            "stderr": "",
            "parsed_json": None,
        })
    payload = {
        "mode": "dry-run" if args.dry_run else "execute",
        "challenge_id": args.challenge_id,
        "orchestrator_commit": context["orchestrator_commit"],
        "warehouse_path": context["warehouse_path"],
        "image_reference": None,
        "image_hash": None,
        "status": "NOT_RUN",
        "worktree": str(worktree),
        "tiers": tiers,
        "setup": [],
        "cleanup": [],
        "error": None,
    }
    if args.dry_run:
        return write_output(args.output, payload)

    key = hashlib.sha256(str(repo).encode()).hexdigest()[:16]
    lock_path = Path("/tmp") / f"cyberarena-challenge-review-{key}.lock"
    deadline = time.monotonic() + args.lock_timeout
    with lock_path.open("a+", encoding="utf-8") as lock:
        while True:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    payload["status"] = "BLOCKED"
                    payload["error"] = f"dynamic review lock busy: {lock_path}"
                    wrote = write_output(args.output, payload)
                    return wrote if wrote != 0 else 1
                time.sleep(0.1)
        created_worktree = False
        try:
            if worktree.exists():
                payload["error"] = f"worktree path already exists: {worktree}"
                payload["status"] = "BLOCKED"
            if payload["error"] is None:
                command = ["worktree", "add", "--detach", str(worktree), context["orchestrator_commit"]]
                result = git(repo, *command)
                payload["setup"].append({
                    "command": ["git", "-C", str(repo), *command],
                    "exit_code": result.returncode,
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                })
                if result.returncode == 0:
                    created_worktree = True
                else:
                    payload["error"] = "git worktree add failed"
                    payload["status"] = "BLOCKED"

            if payload["error"] is None:
                orchestrator_head = git(worktree, "rev-parse", "HEAD")
                if orchestrator_head.stdout.strip() != context["orchestrator_commit"]:
                    payload["error"] = "orchestrator worktree commit mismatch"
                    payload["status"] = "BLOCKED"

            if payload["error"] is None:
                executed: list[dict] = []
                for tier in tiers:
                    if tier["name"] == "build":
                        docker = command_result(
                            [
                                "docker", "info", "--format",
                                "{{json .ServerVersion}}",
                            ],
                            repo,
                            min(args.tier_timeout, 60.0),
                        )
                        payload["setup"].append(docker)
                        if docker["status"] != "PASS":
                            result = dict(tier)
                            result.update(
                                status="BLOCKED",
                                exit_code=docker["exit_code"],
                                duration_seconds=docker["duration_seconds"],
                                stdout=docker["stdout"],
                                stderr=docker["stderr"],
                            )
                            executed.append(result)
                            payload["status"] = "BLOCKED"
                            break

                    result = checker_result(
                        tier["command"], worktree, args.tier_timeout,
                    )
                    result["name"] = tier["name"]
                    executed.append(result)
                    if result["status"] != "PASS":
                        break
                    if tier["name"] == "build":
                        image_reference = built_image_reference(result)
                        payload["image_reference"] = image_reference
                        if image_reference is None:
                            payload["error"] = "canonical build did not report exactly one image reference"
                            break
                        inspection = command_result(
                            [
                                "docker", "image", "inspect", "--format",
                                "{{.Id}}", image_reference,
                            ],
                            repo,
                            min(args.tier_timeout, 60.0),
                        )
                        image_hash = inspection["stdout"].strip()
                        if inspection["status"] != "PASS" or not IMAGE_HASH.fullmatch(image_hash):
                            payload["error"] = "could not pin canonical built image hash"
                            break
                        payload["image_hash"] = image_hash
                payload["tiers"] = executed + tiers[len(executed):]
        except (OSError, subprocess.TimeoutExpired) as exc:
            payload["error"] = f"{type(exc).__name__}: {exc}"
            payload["status"] = "BLOCKED"
        finally:
            if created_worktree:
                cleanup = git(repo, "worktree", "remove", "--force", str(worktree), timeout=180)
                payload["cleanup"].append({
                    "command": ["git", "worktree", "remove", "--force", str(worktree)],
                    "exit_code": cleanup.returncode,
                    "stdout": cleanup.stdout,
                    "stderr": cleanup.stderr,
                })
            prune = git(repo, "worktree", "prune")
            payload["cleanup"].append({
                "command": ["git", "worktree", "prune"],
                "exit_code": prune.returncode,
                "stdout": prune.stdout,
                "stderr": prune.stderr,
            })

    if payload["status"] != "BLOCKED":
        payload["status"] = (
            "PASS"
            if payload["error"] is None
            and all(tier["status"] == "PASS" for tier in payload["tiers"])
            else "FAIL"
        )
    wrote = write_output(args.output, payload)
    if wrote != 0:
        return wrote
    return 0 if payload["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
