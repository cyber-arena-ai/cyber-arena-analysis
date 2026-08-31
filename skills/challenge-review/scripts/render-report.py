#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path


MARK = {
    "PASS": "[x]", "FAIL": "[!]", "UNKNOWN": "[~]",
    "NOT_APPLICABLE": "[-]", "NOT_RUN": "[-]", "BLOCKED": "[!]",
}


def render(report: dict, template: str) -> str:
    context = report["context"]
    context_text = "\n".join([
        f"- Challenge: `{context['challenge_id']}`",
        f"- Scope: `{report['scope']}`",
        f"- Orchestrator: `{context['orchestrator_commit']}`",
        f"- Warehouse: `{context['warehouse_commit']}`",
        f"- Run: `{context['run_id']}` at `{context['timestamp']}`",
    ])
    verdict = report["verdict"]
    verdict_label = verdict["value"].replace("_", " ")
    verdict_text = f"**{verdict_label}** — {verdict['summary']}"
    stages = "\n".join(
        f"- {MARK[item['status']]} **{item['stage']}** — {item['summary']}"
        for item in report["stages"]
    )

    check_lines: list[str] = []
    for item in report["checks"]:
        line = f"- {MARK[item['status']]} `{item['check_id']}` — {item['summary']}"
        if item["next_check"]:
            line += f" Next: {item['next_check']}"
        check_lines.append(line)
    checks = "\n".join(check_lines) or "No checks selected."

    finding_blocks: list[str] = []
    for item in report["findings"]:
        finding_blocks.append(
            f"### {item['finding_id']} [{item['severity']}] — {item['title']}\n\n"
            f"- Stage: `{item['stage']}`\n"
            f"- Pattern: `{item['antipattern_id']}`\n"
            f"- Evidence: {'; '.join(item['evidence'])}\n"
            f"- Impact: {item['impact']}\n"
            f"- Required action: {item['required_action']}"
        )
    findings = "\n\n".join(finding_blocks) or "None."

    unresolved = "\n".join(
        f"- [~] `{item['concern_id']}` (`{item['check_id']}`) — "
        f"{item['concern']} Evidence: {'; '.join(item['evidence'])}. "
        f"Resolve in `{item['owner_stage']}`: {item['resolving_check']}"
        for item in report["unresolved"]
    ) or "None."
    wip = "\n".join(
        f"- `{item['observation_id']}` — {item['note']} Evidence: {'; '.join(item['evidence'])}."
        for item in report["wip_observations"]
    ) or "None."

    return template.format(
        slug=context["challenge_id"], context=context_text, verdict=verdict_text,
        stages=stages, checks=checks, findings=findings, unresolved=unresolved,
        wip_observations=wip,
    ).rstrip() + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Render compact review JSON to Markdown.")
    parser.add_argument("report", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--template", type=Path,
        default=Path(__file__).resolve().parents[1] / "assets" / "report-template.md",
    )
    args = parser.parse_args(argv)
    checked = subprocess.run(
        [sys.executable, str(Path(__file__).with_name("validate-report.py")), str(args.report)],
        text=True, capture_output=True, check=False,
    )
    if checked.returncode != 0:
        sys.stderr.write(checked.stderr)
        return checked.returncode
    if args.output.exists():
        print(f"error: refusing to overwrite {args.output}", file=sys.stderr)
        return 1
    try:
        report = json.loads(args.report.read_text(encoding="utf-8"))
        template = args.template.read_text(encoding="utf-8")
        output = render(report, template)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(output, encoding="utf-8")
    except (OSError, json.JSONDecodeError, KeyError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
