#!/usr/bin/env python3
"""Stand up a study's own bundle in a scratch copy, and tear it down again.

Provisioning is the same sequence for every study — copy the bundle out of the study,
run its reproducer there, find out what came up, write it down. What is *not* the
same for every study is the reproducer's command and how it names things, so
those are supplied and discovered rather than guessed: the script diffs Docker's
own state across the run and reports what appeared, instead of parsing prose.

It never writes inside the study. It hashes the study before and after and says
so, because "read-only" is otherwise a claim nothing checks.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

PORT = re.compile(r"(?:([\d.]+):)?(\d+)->(\d+)/tcp")
FIELDS = ('{{.ID}}\t{{.Names}}\t{{.Label "com.docker.compose.project"}}'
          '\t{{.Label "com.docker.compose.project.working_dir"}}\t{{.Ports}}')


def _docker(*args: str) -> str:
    result = subprocess.run(["docker", *args], capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or f"docker {' '.join(args)} failed")
    return result.stdout


def environment(identifier: str) -> set[str]:
    """The *names* of any facility credentials in the container's environment.

    Names only. The root reads the values itself when it provisions the entry
    principal; holding them here would put secrets in a variable this file exists
    to keep them out of, one stray print away from a transcript.
    """
    raw = _docker("inspect", identifier, "--format", "{{range .Config.Env}}{{println .}}{{end}}")
    return {
        line.partition("=")[0]
        for line in raw.splitlines()
        if "=" in line and any(word in line.partition("=")[0].upper()
                               for word in ("ADMIN", "USER", "PASSWORD", "TOKEN", "SECRET", "KEY"))
    }


def containers() -> dict[str, dict]:
    rows = {}
    for line in _docker("ps", "--all", "--no-trunc", "--format", FIELDS).splitlines():
        if not line.strip():
            continue
        identifier, name, project, workdir, ports = (line.split("\t") + [""] * 5)[:5]
        rows[identifier] = {"name": name, "project": project,
                            "working_dir": workdir, "ports": ports}
    return rows


def digest(root: Path) -> dict[str, str]:
    return {
        str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(root.rglob("*")) if path.is_file()
    }


def published(ports: str) -> list[int]:
    """Every host-published port. A container that publishes an application and
    a database publishes two, and picking either would be a guess."""
    seen = []
    for host, outside, _inside in PORT.findall(ports):
        if host in ("", "127.0.0.1", "0.0.0.0") and int(outside) not in seen:
            seen.append(int(outside))
    return seen


def discover(appeared: dict[str, dict]) -> tuple[dict[str, dict], dict[str, set[str]]]:
    """One entry per compose project, and no guess about which service is the app.

    A project routinely publishes more than one port — an application and its
    database — and picking one by iteration order would hand the roles a base URL
    that answers nothing they can read. When it is ambiguous the candidates are
    written down and `base_url` stays null for a human to settle.
    """
    candidates: dict[str, list[dict]] = {}
    owned: dict[str, list[str]] = {}
    facility: dict[str, set[str]] = {}
    for identifier, container in appeared.items():
        if not container["project"]:
            continue
        owned.setdefault(container["project"], []).append(container["name"])
        try:
            facility.setdefault(container["project"], set()).update(environment(identifier))
        except (RuntimeError, OSError):
            # A sidecar can be gone between the listing and the inspect. Losing a
            # credential hint is survivable; failing here would strand the stack,
            # because target.json — the only teardown key — is written below.
            facility.setdefault(container["project"], set())
        for port in published(container["ports"]):
            candidates.setdefault(container["project"], []).append(
                {"container": container["name"], "base_url": f"http://127.0.0.1:{port}"}
            )
    builds: dict[str, dict] = {}
    for project in sorted(owned):
        found = candidates.get(project, [])
        name = project.rsplit("-", 1)[-1]
        if name in builds:
            # Two projects ending in the same segment. Overwriting would drop a
            # build out of target.json with nothing said about it.
            name = project
        entry = {"base_url": found[0]["base_url"] if len(found) == 1 else None}
        if len(found) > 1:
            entry["candidates"] = found
        elif not found:
            entry["containers"] = sorted(owned[project])
        builds[name] = entry
    # facility comes back beside the builds and is printed to the root only:
    # target.json is handed to the roles, and they get the entry principal and
    # nothing more.
    return builds, facility


def up(study: Path, run: Path, reproducer: str) -> int:
    env = run / "env"
    if env.exists():
        print(f"{env} already exists; provision writes a fresh copy", file=sys.stderr)
        return 1
    before_hashes = digest(study)
    shutil.copytree(study, env)
    before = containers()

    log = run / "reproduce.log"
    print(f"running: {reproducer}\n  in {env}")
    result = subprocess.run(reproducer, shell=True, cwd=env, capture_output=True, text=True)
    log.write_text(result.stdout + result.stderr, encoding="utf-8")
    print(f"{log}: {len(result.stdout.splitlines())} lines, exit {result.returncode}")

    # Ownership is the reproducer's own directory, not "appeared while we ran":
    # another session starting a stack in this window would otherwise be recorded
    # as ours and destroyed by --down.
    mine = str(env.resolve())
    appeared = {
        k: v for k, v in containers().items()
        if k not in before and v["working_dir"] and v["working_dir"].startswith(mine)
    }
    projects = sorted({c["project"] for c in appeared.values() if c["project"]})
    builds, facility_found = discover(appeared)

    # Written before anything can fail below. Whatever came up is now decidably
    # ours, and a run that stops here can still be torn down with --down; the
    # alternative leaves live containers no tool path can reach.
    target = run / "target.json"
    target.write_text(json.dumps({
        "reproducer": {"compose_projects": projects},
        "builds": builds,
    }, indent=2) + "\n", encoding="utf-8")
    print(f"{target}: {len(builds)} build(s) — {', '.join(sorted(builds)) or 'none discovered'}")
    print(f"  projects: {', '.join(projects) or 'none'}")
    unresolved = sorted(n for n, b in builds.items() if not b["base_url"])
    if unresolved:
        print(f"  ambiguous or internal-only, base_url left null: {', '.join(unresolved)}")
    print("  still yours to resolve: auth_header per build (null for anonymous), "
          "and what the facility seeded.")
    for project, found in facility_found.items():
        # Printed here and nowhere else: target.json is handed to the roles, and
        # they get the entry principal and nothing more.
        print(f"  facility credentials in {project}: {', '.join(sorted(found)) or 'none found'}")
    print("  for credentialed entry, read their values with `docker inspect` and")
    print("  provision the entry principal; they are yours, not the roles'.")

    errors = []
    if result.returncode != 0:
        errors.append(f"the reproducer exited {result.returncode}; see {log}")
    if digest(study) != before_hashes:
        errors.append("the study directory changed during provisioning")
    if not builds:
        # Exit status is the one signal the caller is told to trust, and a target
        # nothing came up in is not a provisioning that succeeded.
        errors.append("no build was discovered; there is nothing for a role to probe")
    for error in errors:
        print(error, file=sys.stderr)
    return 1 if errors else 0


def down(run: Path) -> int:
    target = run / "target.json"
    try:
        record = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        print(f"target.json could not be read: {exc}", file=sys.stderr)
        return 1
    projects = record.get("reproducer", {}).get("compose_projects") or []
    if not projects:
        # Nothing recorded means nothing came up, which is not a teardown that
        # failed. Saying so on stdout keeps a clean run from reading as an error.
        print("target.json names no compose project; there is nothing to tear down")
        return 0
    failed = []
    for project in projects:
        # One project failing must not strand the rest: teardown is the last
        # thing standing between a failed run and a host full of containers.
        try:
            _docker("compose", "-p", project, "down", "-v", "--remove-orphans", "--rmi", "local")
        except (RuntimeError, OSError) as exc:
            failed.append(project)
            print(f"{project}: {exc}", file=sys.stderr)
        else:
            print(f"{project}: down, volumes removed; `--rmi local` may leave a "
                  f"tagged image standing, so check before calling the host clean")
    return 1 if failed else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("study", type=Path, nargs="?",
                        help="the Stage 3 study directory, read-only; not used by --down")
    parser.add_argument("--run", type=Path, required=True, help="<run>")
    parser.add_argument("--reproducer", help="the command to run in the bundle copy")
    parser.add_argument("--down", action="store_true", help="tear down what this run started")
    args = parser.parse_args()

    if args.down:
        try:
            return down(args.run)
        except (RuntimeError, OSError) as exc:
            print(exc, file=sys.stderr)
            return 1
    if args.study is None:
        print("the study directory is required", file=sys.stderr)
        return 2
    if not args.reproducer:
        print("--reproducer is required; the command differs per study", file=sys.stderr)
        return 2
    if not (args.study / "STAGE3_STUDY.md").is_file():
        print(f"{args.study} has no STAGE3_STUDY.md", file=sys.stderr)
        return 1
    args.run.mkdir(parents=True, exist_ok=True)
    try:
        return up(args.study.resolve(), args.run, args.reproducer)
    except (RuntimeError, OSError) as exc:
        print(exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
