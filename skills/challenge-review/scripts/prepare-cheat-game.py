#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import NoReturn

from _warehouse import WAREHOUSE_ENV, selected_warehouse


REVIEW_ROUND_SECONDS = 86_400
PARTICIPANT_ENV = "/var/lib/cyberarena/agent.env"
PARTICIPANT_MCP_CONFIG = "/var/lib/cyberarena/mcp.json"
NAMESPACE = re.compile(r"^[a-z0-9][a-z0-9-]{0,19}$")


def fail(message: str) -> NoReturn:
    print(f"error: {message}", file=sys.stderr)
    raise SystemExit(1)


def require_absolute(path: Path, option: str) -> Path:
    if not path.is_absolute():
        fail(f"{option} must be absolute")
    return path.resolve()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Prepare an isolated hard-mode CHEAT review game.",
    )
    parser.add_argument("challenge_id")
    parser.add_argument("--warehouse", type=Path, required=True)
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--namespace", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--runtime-output", type=Path, required=True)
    args = parser.parse_args(argv)

    if not NAMESPACE.fullmatch(args.namespace):
        fail("--namespace must be lowercase, start alphanumeric, and be at most 20 characters")

    repo = require_absolute(args.repo_root, "--repo-root")
    output = require_absolute(args.output, "--output")
    runtime_output = require_absolute(args.runtime_output, "--runtime-output")
    try:
        warehouse = selected_warehouse(args.warehouse)
    except ValueError as exc:
        fail(str(exc))
    if not (repo / "main.py").is_file() or not (
        repo / "challenges" / "check" / "game_phase.py"
    ).is_file():
        fail(f"not an orchestrator checkout: {repo}")
    if output.exists() or runtime_output.exists():
        fail("refusing to overwrite the game config or runtime record")

    os.environ[WAREHOUSE_ENV] = str(warehouse)
    sys.path.insert(0, str(repo))
    try:
        from challenges.check.docker_env import free_ports
        from challenges.check.game_phase import (
            _free_subnet_octet,
            build_game_config,
            yaml_dump,
        )
        from challenges.check.resolve import resolve_challenge
        from gamemgr.config import load
        from orchestrator.naming import qualify
    except Exception as exc:
        fail(f"cannot load orchestration game interfaces: {type(exc).__name__}: {exc}")

    name, challenge, error = resolve_challenge(args.challenge_id)
    if error or name is None or challenge is None:
        fail(error or f"cannot resolve challenge {args.challenge_id!r}")

    try:
        api_port, flag_port, health_port, mcp_port = free_ports(4)
        config = build_game_config(
            name,
            challenge,
            api_port=api_port,
            flag_port=flag_port,
            health_port=health_port,
            subnet_octet=_free_subnet_octet(args.namespace),
            mode="async",
        )
        for team in config["teams"]:
            team["agent"] = {
                "provider": "script",
                "cli": f"exec sleep {REVIEW_ROUND_SECONDS}",
            }
        config["nodes"].append({
            "id": "mcp-gateway",
            "image": "cyberarena/mcp-gateway",
            "networks": ["team1_net", "team2_net", "egress_net"],
            "ports": [f"127.0.0.1:{mcp_port}:8080"],
            "extra_hosts": {"host.docker.internal": "host-gateway"},
            "env": {
                "CYBERARENA_GM_BASE_URL": f"http://host.docker.internal:{api_port}",
                "CYBERARENA_FLAG_SERVICE_URL": "http://flag_service:8080",
                "CYBERARENA_MCP_ALLOWED_HOSTS": (
                    "mcp-gateway:*,127.0.0.1:*,localhost:*"
                ),
            },
        })
        config["mcp_gateway"] = {"agent_url": "http://mcp-gateway:8080"}
        config["challenges"][0]["level"] = "hard"
        config["round_config"] = {
            "mode": "async",
            "round_secs": REVIEW_ROUND_SECONDS,
            "total_rounds": 1,
        }
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(yaml_dump(config), encoding="utf-8")
        loaded = load(output, env_file=repo / ".env")
    except Exception as exc:
        fail(f"cannot prepare CHEAT game config: {type(exc).__name__}: {exc}")

    selected = [item for item in loaded.challenges if item.name == name]
    if len(selected) != 1:
        fail(f"rendered config did not preserve selected challenge {name!r}")
    if selected[0].level != "hard":
        fail(
            "orchestration did not preserve challenge level 'hard' while loading "
            f"the rendered config (loaded {selected[0].level!r})"
        )
    if len(loaded.topology.teams) != 2:
        fail("rendered config did not preserve the two-team topology")
    if loaded.mcp_gateway.agent_url != "http://mcp-gateway:8080":
        fail("rendered config did not preserve the participant MCP endpoint")

    start_command = [
        sys.executable, str(repo / "main.py"), "start",
        "--config", str(output),
        "--namespace", args.namespace,
        "--port", str(api_port),
    ]
    teardown_command = [
        sys.executable, str(repo / "main.py"), "teardown",
        "--config", str(output),
        "--namespace", args.namespace,
    ]
    participant_shells = {
        team_id: [
            "docker", "exec", "-it", qualify(f"{team_id}_dev", args.namespace),
            "bash", "-lc",
            f"set -a; . {PARTICIPANT_ENV}; set +a; cd /var/lib/cyberarena/workdir; exec bash",
        ]
        for team_id in ("team1", "team2")
    }
    tool_helper = Path(__file__).resolve().with_name("call-participant-tool.py")
    runtime = {
        "config_path": str(output),
        "namespace": args.namespace,
        "host_port": api_port,
        "start_command": start_command,
        "teardown_command": teardown_command,
        "participant_shells": participant_shells,
        "participant_mcp_config": PARTICIPANT_MCP_CONFIG,
        "participant_mcp_url": f"http://127.0.0.1:{mcp_port}/mcp/",
        "participant_tokens": {
            team["id"]: team["token"] for team in config["teams"]
        },
        "participant_tool_commands": {
            team_id: [
                sys.executable, str(tool_helper), "<tool>",
                "--runtime", str(runtime_output),
                "--team", team_id,
                "--arguments", "<json-object>",
            ]
            for team_id in ("team1", "team2")
        },
    }
    runtime_output.parent.mkdir(parents=True, exist_ok=True)
    runtime_output.write_text(
        json.dumps(runtime, indent=2, sort_keys=True) + "\n", encoding="utf-8",
    )
    print(runtime_output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
