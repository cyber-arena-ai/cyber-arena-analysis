#!/usr/bin/env python3
"""Exercise listmonk's CSV subscriber import only through its HTTP API."""

from __future__ import annotations

import argparse
import json
import time
import urllib.error
import urllib.request
import uuid


USER = "ops-analyst"
TOKEN = "ops-analyst-token-a7f3e9c15b4d"


def request(base: str, method: str, path: str, body: bytes | None = None,
            content_type: str | None = None) -> tuple[int, bytes]:
    headers = {
        "Authorization": f"token {USER}:{TOKEN}",
        "Accept": "application/json",
    }
    if content_type:
        headers["Content-Type"] = content_type
    req = urllib.request.Request(base + path, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=20) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


def multipart(target_list: int, marker: str) -> tuple[bytes, str]:
    boundary = "----stage3-" + uuid.uuid4().hex
    params = json.dumps({
        "mode": "subscribe",
        "subscription_status": "confirmed",
        "delim": ",",
        "lists": [target_list],
        "overwrite": True,
    })
    csv_data = f"email,name\n{marker}@stage3.invalid,{marker}\n"
    fields = [
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"params\"\r\n\r\n{params}\r\n",
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"study.csv\"\r\nContent-Type: text/csv\r\n\r\n{csv_data}\r\n",
        f"--{boundary}--\r\n",
    ]
    return "".join(fields).encode(), f"multipart/form-data; boundary={boundary}"


def decode(payload: bytes):
    try:
        return json.loads(payload)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return payload.decode(errors="replace")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", default="http://listmonk:9000")
    parser.add_argument("--target-list", required=True, type=int)
    parser.add_argument("--marker", required=True)
    args = parser.parse_args()

    list_status, list_body = request(args.base, "GET", "/api/lists?per_page=all")
    body, content_type = multipart(args.target_list, args.marker)
    import_status, import_body = request(
        args.base, "POST", "/api/import/subscribers", body, content_type
    )

    final_stats = None
    if import_status == 200:
        for _ in range(50):
            status, payload = request(args.base, "GET", "/api/import/subscribers")
            final_stats = {"http_status": status, "body": decode(payload)}
            data = final_stats["body"].get("data", {}) if isinstance(final_stats["body"], dict) else {}
            if data.get("status") in {"finished", "failed"}:
                break
            time.sleep(0.1)
        request(args.base, "DELETE", "/api/import/subscribers")

    print(json.dumps({
        "visible_lists": {"http_status": list_status, "body": decode(list_body)},
        "import": {"http_status": import_status, "body": decode(import_body)},
        "final_stats": final_stats,
        "target_list": args.target_list,
        "marker": args.marker,
    }, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
