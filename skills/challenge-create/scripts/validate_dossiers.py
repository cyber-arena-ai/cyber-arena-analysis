#!/usr/bin/env python3
"""Validate research-stage potential-challenge dossiers."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path


REQUIRED_HEADERS = (
    "## Why it is a good candidate",
    "## Proposed scenario",
    "## Revision candidates",
    "## Historical vulnerability-to-scope probes",
    "## Provisional multiflag capability envelope",
)
SCENARIO_PHRASES = (
    "The attacker begins",
    "Defenders must preserve",
)
BANNED_PATTERNS = (
    (re.compile(r"shortlist evidence", re.IGNORECASE), "opaque shortlist evidence"),
    (re.compile(r"popularity(?: score)?", re.IGNORECASE), "popularity score"),
    (re.compile(r"\brank(?:ed|ing)?\b", re.IGNORECASE), "rank"),
)
SCOPE_RE = re.compile(
    r"`((?:app|host|network|secret|storage|custom)\.[a-z0-9_.-]+)`"
)
COMMIT_LINK_RE = re.compile(
    r"\[`([0-9a-f]{40})`\]\([^)]*/commit/([0-9a-f]{40})\)"
)


def load_scopes(path: Path) -> set[str]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    return {str(item["id"]) for item in payload.get("scopes", [])}


def collect_dossiers(inputs: list[Path]) -> list[Path]:
    dossiers: set[Path] = set()
    for path in inputs:
        if path.is_dir():
            dossiers.update(path.glob("*.md"))
        elif path.is_file():
            dossiers.add(path)
        else:
            raise ValueError(f"not a file or directory: {path}")
    return sorted(dossiers)


def validate(path: Path, registered_scopes: set[str]) -> list[str]:
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()
    errors: list[str] = []

    if not path.name.startswith("POTENTIAL_CHALLENGE_"):
        errors.append("filename must start with POTENTIAL_CHALLENGE_")
    if "Maintainer-only research dossier." not in text:
        errors.append("missing maintainer-only research banner")
    for header in REQUIRED_HEADERS:
        if text.count(header) != 1:
            errors.append(f"expected exactly one `{header}` header")
    for phrase in SCENARIO_PHRASES:
        if phrase not in text:
            errors.append(f"scenario is missing `{phrase}`")
    if "The target is" not in text and "The targets are" not in text:
        errors.append("scenario is missing its target")
    if "The task does not grant" not in text and "The task does not provide" not in text:
        errors.append("scenario is missing unavailable privileges or shortcuts")
    if not any(re.match(r"\| V\d+ \|", line) for line in lines):
        errors.append("historical probe table has no V0...Vn rows")
    if any(line.rstrip() != line for line in lines):
        errors.append("contains trailing whitespace")

    for pattern, label in BANNED_PATTERNS:
        if pattern.search(text):
            errors.append(f"contains disallowed {label}")

    for scope in sorted(set(SCOPE_RE.findall(text))):
        if scope not in registered_scopes and not scope.startswith("custom."):
            errors.append(f"unregistered scope `{scope}`")

    for label, target in COMMIT_LINK_RE.findall(text):
        if label != target:
            errors.append(f"commit label `{label}` does not match URL `{target}`")

    for line in lines:
        if re.match(r"\| V\d+ \|", line) and "rejected" in line.lower():
            if "| — |" not in line:
                errors.append("rejected probe must expose no candidate scope")

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scope-registry", required=True, type=Path)
    parser.add_argument("dossiers", nargs="+", type=Path)
    args = parser.parse_args()

    try:
        dossiers = collect_dossiers(args.dossiers)
        scopes = load_scopes(args.scope_registry)
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as error:
        parser.error(str(error))

    if not dossiers:
        parser.error("no Markdown dossiers found")

    failures = 0
    for dossier in dossiers:
        errors = validate(dossier, scopes)
        if errors:
            failures += 1
            for error in errors:
                print(f"FAIL {dossier}: {error}")
        else:
            print(f"PASS {dossier}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
