#!/usr/bin/env python3
"""Send one request to the running target as the entry principal, and record it.

This is the fast path, not a fence. Assembling the three evidence fields by hand
is where a quoted string stops matching the response it claims to come from, so
this builds them from the response and refuses a claim the response does not
carry. Use it wherever it reaches; where it cannot, use a client that does and
bring the exchange back with `--record`.

What the graph actually rests on is `probes.log`: every observation it cites has
to match a record here, and `source` says how that record was obtained — sent by
this script, or attested by the role that ran the exchange itself. The root
checks citations against this file, and an attested one is the kind to check
hardest.

One invocation is one request. Redirects are not followed, because a 302 and the
page it points at are two requests and one record cannot honestly be both.
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


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A 3xx is a result. Following it would put two requests in one record, and
    would let a cookie the first hop set walk the second under the first's name."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _pairs(items: list[str], flag: str) -> list[tuple[str, str]]:
    pairs = [tuple(item.split("=", 1)) for item in items]
    if any(len(pair) != 2 for pair in pairs):
        raise ValueError(f"each {flag} must be NAME=VALUE")
    # urlencode takes a sequence of *tuples*; a list of lists raises TypeError,
    # so this failed for well-formed input too until a run found it.
    return pairs


def _cookie_pairs(raw: str) -> dict:
    pairs = {}
    for part in raw.split(";"):
        name, separator, value = part.strip().partition("=")
        if separator and name:
            pairs[name] = value
    return pairs


def _headers(build: dict, extra: list[str]) -> tuple[dict, str, dict]:
    """The headers to send, the entry principal's header name, and what was added."""
    name, separator, value = build["auth_header"].partition(":")
    name, value = name.strip(), value.strip()
    if not separator or not name or not value:
        # Without this the header silently becomes empty and the request goes out
        # anonymous, recording a route the entry principal was never shown to walk.
        raise ValueError(
            f"auth_header must be '<header name>: <value>', got {build['auth_header']!r}"
        )
    headers, added = {name: value}, {}
    for raw in extra:
        other, separator, other_value = raw.partition(":")
        other, other_value = other.strip(), other_value.strip()
        if not separator or not other or not other_value:
            raise ValueError(f"each --header must be 'NAME: VALUE', got {raw!r}")
        if other.lower() == name.lower():
            if other.lower() != "cookie":
                # The entry principal is the identity the challenge granted. A
                # header that replaced it would record a route somebody else walked.
                raise ValueError(f"--header may not replace the entry principal's {name}")
            # A session alongside a cookie principal is ordinary; the granted
            # cookie still wins where both name the same one.
            merged = _cookie_pairs(other_value) | _cookie_pairs(headers[name])
            headers[name] = "; ".join(f"{key}={val}" for key, val in merged.items())
        else:
            headers[other] = other_value
        added[other] = other_value
    return headers, name, added


def _body(data: str | None, form: list[str],
          data_file: Path | None) -> tuple[bytes | None, str | None, str | None]:
    """The bytes to send, the Content-Type they imply, and what to log as `sent`."""
    if data is not None:
        return data.encode("utf-8"), "application/json", data
    if form:
        encoded = urllib.parse.urlencode(_pairs(form, "--form"))
        return encoded.encode("utf-8"), "application/x-www-form-urlencoded", encoded
    if data_file is not None:
        raw = data_file.read_bytes()
        # Logged by shape, not content: a packfile or an upload is not text, and
        # putting it in the log would make the log unreadable.
        return raw, "application/octet-stream", f"<{len(raw)} bytes from {data_file.name}>"
    return None, None, None


def send(build: dict, args: argparse.Namespace) -> dict:
    url = build["base_url"].rstrip("/") + args.path
    if args.param:
        url += "?" + urllib.parse.urlencode(_pairs(args.param, "--param"))
    headers, _principal, added = _headers(build, args.header)
    payload, content_type, sent = _body(args.data, args.form, args.data_file)
    if content_type and not any(key.lower() == "content-type" for key in headers):
        headers["Content-Type"] = content_type
    request = urllib.request.Request(url, data=payload, method=args.method, headers=headers)
    opener = urllib.request.build_opener(_NoRedirect)
    at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    base = {"at": at, "witness": "probe", "method": args.method, "url": url,
            "sent": sent, "added": added}
    try:
        with opener.open(request, timeout=TIMEOUT) as response:
            status, received, body = response.status, response.headers, response.read()
    except urllib.error.HTTPError as error:  # a 403, and a 302, are results
        status, received, body = error.code, error.headers, error.read()
    except (urllib.error.URLError, OSError) as error:
        # The target being down is the commonest bad case, and the record of
        # having tried is the whole reason this writes a log.
        return {**base, "status": None, "error": str(error), "content_type": None,
                "headers": [], "body": ""}
    return {
        **base,
        "status": status,
        "content_type": received.get("Content-Type"),
        # Pairs, not a mapping: Set-Cookie is the header a role most often needs
        # back, and it is the header that repeats.
        "headers": [[name, value] for name, value in received.items()],
        "body": body.decode("utf-8", "replace"),
    }


def attest(args: argparse.Namespace) -> dict:
    """An exchange the role performed with a client this script cannot be."""
    return {
        "at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "witness": "attested",
        "method": "",
        "url": args.request,
        "sent": None,
        "added": {},
        "status": args.status,
        "content_type": None,
        "headers": [],
        "body": args.response_file.read_text(encoding="utf-8", errors="replace"),
    }


def excerpt_for(whole: str, observed: str) -> str:
    """The window of the response that carries the claim.

    The log keeps the head of the body, which is what a reader wants. Evidence
    cannot: a disclosure can land deep inside a rendered page, and evidence whose
    `observed` is not inside its own `excerpt` is rejected at validation. So the
    excerpt follows the match instead of the start.
    """
    if observed in whole[:BODY_LIMIT]:
        return whole[:BODY_LIMIT]
    at = whole.index(observed)
    start = max(0, at - BODY_LIMIT // 4)
    return whole[start:max(start + BODY_LIMIT, at + len(observed))]


def header_text(record: dict) -> str:
    return "\n".join(f"{name}: {value}" for name, value in record["headers"])


def evidence(record: dict, build_name: str, observed: str, whole: str) -> dict:
    """The graph's evidence shape, built from the response rather than retyped."""
    beyond = [f"{name}: {value}" for name, value in record.get("added", {}).items()]
    if record["witness"] == "attested":
        source = f"{build_name} build · {record['url']} · attested · {record['status']}"
    else:
        source = (f"{build_name} build · {record['method']} {record['url']}"
                  + (f" · with {'; '.join(beyond)}" if beyond else "")
                  + (f" · body {record['sent']}" if record.get("sent") is not None else "")
                  + f" · {record['status']}")
    return {"source": source, "excerpt": excerpt_for(whole, observed), "observed": observed}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", type=Path, required=True, help="<run>/target.json")
    parser.add_argument("--build", required=True, help="which build, as named in target.json")
    parser.add_argument("--method", default="GET")
    parser.add_argument("--path", help="request path, starting with /")
    parser.add_argument("--param", action="append", default=[], metavar="NAME=VALUE")
    parser.add_argument("--header", action="append", default=[], metavar="NAME: VALUE",
                        help="an extra request header; may not replace the entry "
                             "principal's, though a cookie is merged into it")
    parser.add_argument("--data", help="request body, sent as application/json")
    parser.add_argument("--form", action="append", default=[], metavar="NAME=VALUE",
                        help="request body, sent as application/x-www-form-urlencoded")
    parser.add_argument("--data-file", type=Path,
                        help="request body read as bytes, for a payload that is not text")
    parser.add_argument("--record", action="store_true",
                        help="record an exchange you performed with another client, "
                             "for a request this script cannot send")
    parser.add_argument("--request", help="with --record: the request you sent, verbatim")
    parser.add_argument("--response-file", type=Path,
                        help="with --record: the response you received")
    parser.add_argument("--status", type=int, help="with --record: the status it returned")
    parser.add_argument("--note", default="", help="what this probe is for; kept in the log")
    parser.add_argument(
        "--observed",
        help="the string that carries the claim; printed as graph evidence when the "
             "response contains it, and refused when it does not",
    )
    args = parser.parse_args()

    if args.record:
        missing = [flag for flag, value in (("--request", args.request),
                                            ("--response-file", args.response_file),
                                            ("--status", args.status)) if value is None]
        if missing:
            print(f"--record needs {', '.join(missing)}", file=sys.stderr)
            return 1
    elif not args.path:
        print("--path is required unless you are recording with --record", file=sys.stderr)
        return 1
    given = [flag for flag, value in
             (("--data", args.data is not None), ("--form", bool(args.form)),
              ("--data-file", args.data_file is not None)) if value]
    if len(given) > 1:
        print(f"a request has one body: {', '.join(given)} were given", file=sys.stderr)
        return 1

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
        sent = attest(args) if args.record else send(build, args)
    except (ValueError, OSError) as exc:
        print(exc, file=sys.stderr)
        return 1

    record = {"build": args.build, "note": args.note, **sent}
    whole = record["body"]
    record["body"] = whole[:BODY_LIMIT]
    if record["status"] is None:
        with (args.target.parent / "probes.log").open("a", encoding="utf-8") as log:
            log.write(json.dumps(record) + "\n")
        print(json.dumps(record, indent=2))
        print(f"\nthe request did not reach {args.build}: {record['error']}", file=sys.stderr)
        return 1

    earned = None
    if args.observed is not None:
        if len(args.observed.strip()) < MIN_OBSERVED:
            print(f"\nobserved must carry at least {MIN_OBSERVED} characters of the "
                  "response; a shorter one is rejected at validation", file=sys.stderr)
            return 1
        # A claim can live in a header rather than the body: a study returned its
        # archive as ciphertext with the key that decrypts it in one.
        carrier = whole if args.observed in whole else header_text(record)
        if args.observed not in carrier:
            print(f"\n{args.observed!r} is in neither the response body nor its "
                  "headers; there is no evidence here to record", file=sys.stderr)
            return 1
        earned = evidence(record, args.build, args.observed, carrier)
        # Kept in the log as well as printed: the excerpt can follow a match past
        # the head this log keeps, and the root's citation check reads this file.
        record["evidence"] = earned

    with (args.target.parent / "probes.log").open("a", encoding="utf-8") as log:
        log.write(json.dumps(record) + "\n")
    print(json.dumps(record, indent=2))
    if earned is not None:
        print("\nevidence:")
        print(json.dumps(earned, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
