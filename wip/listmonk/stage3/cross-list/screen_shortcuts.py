#!/usr/bin/env python3
"""Bounded HTTP screen for ordinary alternatives to protected-list import."""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request


BASE = "http://listmonk:9000"
AUTH = "token ops-analyst:ops-analyst-token-a7f3e9c15b4d"
TARGET_ID = 4
TARGET_UUID = "c7be79b7-5805-4985-a1d4-d5115ba89510"


def probe(name: str, method: str, path: str, data: bytes | None = None,
          content_type: str | None = None, authenticated: bool = True) -> dict:
    headers = {"Accept": "application/json"}
    if authenticated:
        headers["Authorization"] = AUTH
    if content_type:
        headers["Content-Type"] = content_type
    request = urllib.request.Request(BASE + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            status, body = response.status, response.read()
    except urllib.error.HTTPError as error:
        status, body = error.code, error.read()
    return {"name": name, "http_status": status, "body": body.decode(errors="replace")[:500]}


checks = [
    probe("read protected list", "GET", f"/api/lists/{TARGET_ID}"),
    probe("query protected subscribers", "GET", f"/api/subscribers?list_id={TARGET_ID}"),
    probe(
        "direct subscriber creation",
        "POST",
        "/api/subscribers",
        json.dumps({
            "email": "cross_direct@stage3.invalid",
            "name": "cross_direct",
            "lists": [TARGET_ID],
        }).encode(),
        "application/json",
    ),
    probe(
        "bulk subscriber-list management",
        "PUT",
        "/api/subscribers/lists",
        json.dumps({"ids": [1], "action": "add", "target_list_ids": [TARGET_ID]}).encode(),
        "application/json",
    ),
    probe(
        "public subscription form against private list",
        "POST",
        "/subscription/form",
        urllib.parse.urlencode({
            "email": "cross_public@stage3.invalid",
            "name": "cross_public",
            "l": TARGET_UUID,
        }).encode(),
        "application/x-www-form-urlencoded",
        authenticated=False,
    ),
]

print(json.dumps(checks, indent=2, sort_keys=True))
