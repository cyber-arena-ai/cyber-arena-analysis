#!/usr/bin/env python3
"""Send one request to the running target as the entry principal, and record it.

Both roles wrote this themselves, the same way, and then assembled the four
evidence fields by hand — which is where a quoted string stops matching the
response it claims to come from. So the request and the evidence come out of one
place: `--observed` is checked against the body that actually came back, and a
claim the response does not support is refused rather than printed.

Every probe appends to `probes.log` beside the target file, so a run that ended
badly still says what was sent.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
from datetime import datetime, timezone
import urllib.parse
import urllib.request
from pathlib import Path

from _graph import MIN_OBSERVED

BODY_LIMIT = 4000
TIMEOUT = 60


def send(build: dict, method: str, path: str, params: list[str], data: str | None) -> dict:
    url = build["base_url"].rstrip("/") + path
    if params:
        pairs = [tuple(p.split("=", 1)) for p in params]
        if any(len(pair) != 2 for pair in pairs):
            raise ValueError("each --param must be NAME=VALUE")
        # urlencode takes a sequence of *tuples*; a list of lists raises TypeError,
        # so this failed for well-formed input too until a run found it.
        url += "?" + urllib.parse.urlencode(pairs)
    name, separator, value = build["auth_header"].partition(":")
    value = value.strip()
    if not separator or not name.strip() or not value:
        # Without this the header silently becomes empty and the request goes out
        # anonymous, recording a route the entry principal was never shown to walk.
        raise ValueError(
            f"auth_header must be '<header name>: <value>', got {build['auth_header']!r}"
        )
    headers = {name.strip(): value}
    payload = None
    if data is not None:
        payload = data.encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=payload, method=method, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
            status, received, body = response.status, dict(response.headers), response.read()
    except urllib.error.HTTPError as error:  # a 403 is a result, not a failure
        status, received, body = error.code, dict(error.headers), error.read()
    except (urllib.error.URLError, OSError) as error:
        # The target being down is the commonest bad case, and the record of
        # having tried is the whole reason this writes a log.
        return {"at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "method": method, "url": url, "sent": data, "status": None,
                "error": str(error), "content_type": None, "body": ""}
    return {
        "at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "method": method,
        "url": url,
        "sent": data,
        "status": status,
        "content_type": received.get("Content-Type"),
        "body": body.decode("utf-8", "replace"),
    }


def evidence(record: dict, build_name: str, observed: str) -> dict:
    """The graph's evidence shape, built from the response rather than retyped."""
    return {
        "source": (f"{build_name} build · {record['method']} {record['url']}"
                   + (f" · body {record['sent']}" if record.get("sent") is not None else "")
                   + f" · {record['status']}"),
        "excerpt": record["body"],
        "observed": observed,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", type=Path, required=True, help="<run>/target.json")
    parser.add_argument("--build", required=True, help="which build, as named in target.json")
    parser.add_argument("--method", default="GET")
    parser.add_argument("--path", required=True, help="request path, starting with /")
    parser.add_argument("--param", action="append", default=[], metavar="NAME=VALUE")
    parser.add_argument("--data", help="request body, sent as application/json")
    parser.add_argument("--note", default="", help="what this probe is for; kept in the log")
    parser.add_argument(
        "--observed",
        help="the string that carries the claim; printed as graph evidence when the "
             "response contains it, and refused when it does not",
    )
    args = parser.parse_args()

    try:
        target = json.loads(args.target.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        print(f"target.json could not be read: {exc}", file=sys.stderr)
        return 1
    if target.get("none"):
        print("this study has no runnable bundle; there is nothing to probe", file=sys.stderr)
        return 1
    builds = target.get("builds")
    if not isinstance(builds, dict) or args.build not in builds:
        print(f"target.json has no build {args.build!r}; it names "
              f"{sorted(builds) if isinstance(builds, dict) else 'none'}", file=sys.stderr)
        return 1
    build = builds[args.build]
    for field in ("base_url", "auth_header"):
        if not isinstance(build.get(field), str) or not build[field].strip():
            print(f"build {args.build} has no {field}", file=sys.stderr)
            return 1

    try:
        sent = send(build, args.method, args.path, args.param, args.data)
    except ValueError as exc:
        print(exc, file=sys.stderr)
        return 1
    record = {"build": args.build, "note": args.note, **sent}
    whole = record["body"]
    record["body"] = whole[:BODY_LIMIT]
    with (args.target.parent / "probes.log").open("a", encoding="utf-8") as log:
        log.write(json.dumps(record) + "\n")
    print(json.dumps(record, indent=2))
    if record["status"] is None:
        print(f"\nthe request did not reach {args.build}: {record['error']}", file=sys.stderr)
        return 1

    if args.observed is not None:
        if len(args.observed.strip()) < MIN_OBSERVED:
            print(f"\nobserved must carry at least {MIN_OBSERVED} characters of the "
                  "response; a shorter one is rejected at validation", file=sys.stderr)
            return 1
        if args.observed not in record["body"]:
            reason = (f"beyond the {BODY_LIMIT}-character excerpt this records"
                      if args.observed in whole else "not in the response at all")
            print(f"\n{args.observed!r} is {reason}; there is no evidence here to record",
                  file=sys.stderr)
            return 1
        print("\nevidence:")
        print(json.dumps(evidence(record, args.build, args.observed), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
