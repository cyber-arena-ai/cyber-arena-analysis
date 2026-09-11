#!/usr/bin/env python3
"""Run a root-derived stand-up command in a study copy, and report what persists.

Stage 3 supplies the build and reproduction materials, but its clean reproducer
may intentionally tear everything down. The root derives the command that leaves
the studied target available. This script copies the bundle, runs that command,
and diffs Docker state. Compose metadata supplies useful suggestions; every new
container is also reported so the root can map plain ``docker run`` deployments.

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


def container_candidates(appeared: dict[str, dict]) -> list[dict]:
    """Raw containers for the root to interpret, without guessing their role."""
    rows = []
    for identifier, container in sorted(appeared.items(), key=lambda item: item[1]["name"]):
        rows.append({
            "id": identifier,
            "name": container["name"],
            "compose_project": container["project"] or None,
            "published_ports": published(container["ports"]),
        })
    return rows


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


def up(study: Path, run: Path, stand_up: str) -> int:
    env = run / "env"
    if env.exists():
        print(f"{env} already exists; provision writes a fresh copy", file=sys.stderr)
        return 1
    before_hashes = digest(study)
    shutil.copytree(study, env)
    before = containers()

    log = run / "stand-up.log"
    print(f"running: {stand_up}\n  in {env}")
    result = subprocess.run(stand_up, shell=True, cwd=env, capture_output=True, text=True)
    log.write_text(result.stdout + result.stderr, encoding="utf-8")
    print(f"{log}: {len(result.stdout.splitlines())} lines, exit {result.returncode}")

    after = containers()
    appeared = {k: v for k, v in after.items() if k not in before}
    candidates = container_candidates(appeared)

    # Compose's working-directory label is strong enough to establish ownership.
    # Plain Docker has no corresponding label, so it stays a raw candidate until
    # the root selects it in target.json; --down never guesses from this list.
    mine = str(env.resolve())
    compose_owned = {
        k: v for k, v in appeared.items()
        if v["project"] and v["working_dir"] and v["working_dir"].startswith(mine)
    }
    projects = sorted({c["project"] for c in compose_owned.values()})
    builds, facility_found = discover(compose_owned)

    # Written before the post-checks so the root can inspect and resolve every
    # candidate even when the command or study-integrity check fails.
    target = run / "target.json"
    target.write_text(json.dumps({
        "provision": {
            "compose_projects": projects,
            "containers": [],
            "container_candidates": candidates,
        },
        "builds": builds,
    }, indent=2) + "\n", encoding="utf-8")
    print(f"{target}: {len(builds)} suggested build(s) — "
          f"{', '.join(sorted(builds)) or 'root must map the candidates'}")
    print(f"  projects: {', '.join(projects) or 'none'}")
    print(f"  container candidates: {len(candidates)}")
    unresolved = sorted(n for n, b in builds.items() if not b["base_url"])
    if unresolved:
        print(f"  ambiguous or internal-only, base_url left null: {', '.join(unresolved)}")
    print("  still yours to resolve: exact builds, protocol-native credentials "
          "(null for anonymous), and what the facility seeded.")
    for project, found in facility_found.items():
        # Printed here and nowhere else: target.json is handed to the roles, and
        # they get the entry principal and nothing more.
        print(f"  facility credentials in {project}: {', '.join(sorted(found)) or 'none found'}")
    print("  for credentialed entry, read their values with `docker inspect` and")
    print("  provision the entry principal; they are yours, not the roles'.")

    errors = []
    if result.returncode != 0:
        errors.append(f"the stand-up command exited {result.returncode}; see {log}")
    if digest(study) != before_hashes:
        errors.append("the study directory changed during provisioning")
    if not candidates:
        # Exit status is the one signal the caller is told to trust. A stand-up
        # command that leaves no container cannot supply the roles a live target.
        errors.append("no container was discovered; there is nothing for a role to probe")
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
    provision = record.get("provision") or {}
    projects = provision.get("compose_projects") or []
    selected = provision.get("containers") or []
    if not projects and not selected:
        # Nothing recorded means nothing came up, which is not a teardown that
        # failed. Saying so on stdout keeps a clean run from reading as an error.
        print("target.json names no provisioned resource; there is nothing to tear down")
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
    for identifier in selected:
        try:
            _docker("rm", "-f", "-v", identifier)
        except (RuntimeError, OSError) as exc:
            failed.append(identifier)
            print(f"{identifier}: {exc}", file=sys.stderr)
        else:
            print(f"{identifier}: container removed")
    return 1 if failed else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("study", type=Path, nargs="?",
                        help="the Stage 3 study directory, read-only; not used by --down")
    parser.add_argument("--run", type=Path, required=True, help="<run>")
    parser.add_argument(
        "--stand-up",
        help="root-derived command using the Stage 3 bundle that leaves the target running",
    )
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
    if not args.stand_up:
        print("--stand-up is required; derive it from the Stage 3 bundle", file=sys.stderr)
        return 2
    if not (args.study / "STAGE3_STUDY.md").is_file():
        print(f"{args.study} has no STAGE3_STUDY.md", file=sys.stderr)
        return 1
    args.run.mkdir(parents=True, exist_ok=True)
    try:
        return up(args.study.resolve(), args.run, args.stand_up)
    except (RuntimeError, OSError) as exc:
        print(exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
