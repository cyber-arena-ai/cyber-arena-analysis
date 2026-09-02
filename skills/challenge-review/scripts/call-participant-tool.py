#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import Any, NoReturn


TOOLS = frozenset({
    "claim_capability",
    "get_attack_targets",
    "get_health_checks",
    "restart_service",
    "submit_flag",
    "trigger_health_check",
})


def fail(message: str) -> NoReturn:
    print(f"error: {message}", file=sys.stderr)
    raise SystemExit(1)


async def call_tool(url: str, token: str, tool: str, arguments: dict[str, Any]) -> dict:
    try:
        import httpx
        from mcp import ClientSession
        from mcp.client.streamable_http import streamable_http_client
    except ImportError as exc:
        fail(f"the orchestration Python environment lacks its MCP client: {exc}")

    async with httpx.AsyncClient(headers={"X-Team-Token": token}) as http:
        async with streamable_http_client(url, http_client=http) as (
            read_stream, write_stream, _session_id,
        ):
            async with ClientSession(read_stream, write_stream) as session:
                await session.initialize()
                result = await session.call_tool(tool, arguments)
    return result.model_dump(mode="json")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Call a CHEAT game tool through one team's MCP gateway.",
    )
    parser.add_argument("tool", choices=sorted(TOOLS))
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--team", choices=("team1", "team2"), required=True)
    parser.add_argument("--arguments", default="{}")
    args = parser.parse_args(argv)

    if not args.runtime.is_absolute():
        fail("--runtime must be absolute")
    try:
        runtime = json.loads(args.runtime.read_text(encoding="utf-8"))
        arguments = json.loads(args.arguments)
        if not isinstance(arguments, dict):
            fail("--arguments must decode to a JSON object")
        url = runtime["participant_mcp_url"]
        token = runtime["participant_tokens"][args.team]
        if not isinstance(url, str) or not isinstance(token, str):
            raise TypeError("participant MCP URL and token must be strings")
    except (OSError, json.JSONDecodeError, KeyError, TypeError) as exc:
        fail(f"invalid runtime record or arguments: {exc}")

    try:
        result = asyncio.run(call_tool(url, token, args.tool, arguments))
    except SystemExit:
        raise
    except Exception as exc:
        fail(f"participant tool call failed: {type(exc).__name__}: {exc}")
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
