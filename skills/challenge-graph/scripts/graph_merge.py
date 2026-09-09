#!/usr/bin/env python3
"""Merge a validated EXPAND fragment into the SEED graph.

The root owns the merged deliverable, so it must not be able to drop an
inconvenient EXPAND route by leaving it out. The union here is mechanical and
a refusal needs `--refute PATH=REASON`, which lands in the written record.
"""

from __future__ import annotations

import argparse
import copy
import json
import sys
from pathlib import Path

from _graph import Graph, load, validate

SHARED = ("schema_version", "target", "evidence_root")
ENTRIES = ("blocked", "survived")
# What makes two declarations of one node the same node. `title` and `evidence`
# are deliberately absent: EXPAND legitimately cites its own line for a node it
# reaches by another route, and SEED's declaration stands.
IDENTITY = ("role", "symbol", "store", "scope")


def _refutations(raw: list[str]) -> tuple[dict[str, str], list[str]]:
    parsed: dict[str, str] = {}
    errors: list[str] = []
    for item in raw:
        path_id, separator, reason = item.partition("=")
        if not separator or not path_id.strip() or not reason.strip():
            errors.append(f"--refute needs PATH-ID=REASON, got {item!r}")
            continue
        parsed[path_id.strip()] = reason.strip()
    return parsed, errors


def _header_errors(seed: dict, expand: dict) -> list[str]:
    return [
        f"fragments disagree on {key}: {seed.get(key)!r} vs {expand.get(key)!r}"
        for key in SHARED
        if seed.get(key) != expand.get(key)
    ]


def _terminal_errors(seed: Graph, expand: Graph) -> list[str]:
    """CH-4: objectives derive from the asset graph, never from the vulnerability."""
    return [
        f"EXPAND introduced {expand.role(node_id)} node {node_id}, which SEED does not "
        f"declare; a new objective is a lead, not a node"
        for node_id in expand.nodes
        if expand.role(node_id) in ("entry", "objective") and node_id not in seed.nodes
    ]


def _merge_node(seed_node: dict, expand_node: dict) -> tuple[dict, list[str]]:
    """One node both roles declare: `requires` unions, its identity must match."""
    node_id = seed_node["id"]
    seed_requires = seed_node.get("requires") or []
    expand_requires = expand_node.get("requires") or []
    added = [r for r in expand_requires if r not in seed_requires]

    differ = [k for k in IDENTITY if seed_node.get(k) != expand_node.get(k)]
    if bool(seed_node.get("requires_all")) != bool(expand_node.get("requires_all")):
        differ.append("requires_all")
    if differ:
        return seed_node, [f"fragments disagree on node {node_id}: {', '.join(differ)}"]
    if added and seed_node.get("requires_all"):
        # Widening a conjunction would silently demand the new predecessor too.
        return seed_node, [
            f"node {node_id} sets requires_all and the fragments list different "
            f"predecessors; adjudicate it rather than merging"
        ]
    if added:
        seed_node["requires"] = list(seed_requires) + added
    return seed_node, []


def _merge_cuts(seed: dict, expand: dict, kept: set[str]) -> tuple[list[dict], list[str]]:
    """Cuts union by id: EXPAND reports how the same fix treated its own routes.

    A refuted route takes its cut entries with it, and a cut left recording
    nothing is dropped rather than written out empty.
    """
    merged: dict[str, dict] = {}
    errors: list[str] = []
    for fragment in (seed, expand):
        for cut in fragment.get("observed_cuts") or []:
            existing = merged.get(cut["id"])
            if existing is None:
                merged[cut["id"]] = {**cut, **{k: _keep(cut, k, kept) for k in ENTRIES}}
            elif existing["reference"] != cut.get("reference"):
                errors.append(f"fragments disagree on the reference of cut {cut['id']}")
            else:
                for key in ENTRIES:
                    existing[key] += [e for e in _keep(cut, key, kept) if e not in existing[key]]
    return [c for c in merged.values() if c["blocked"] or c["survived"]], errors


def _keep(cut: dict, key: str, kept: set[str]) -> list[dict]:
    return [entry for entry in cut.get(key) or [] if entry["path"] in kept]


def merge(seed: dict, expand: dict, refuted: dict[str, str]) -> tuple[dict | None, dict, list[str]]:
    """Union two validated fragments. Every field of the record is SEED-relative."""
    seed_graph, expand_graph = Graph(seed), Graph(expand)
    errors = _header_errors(seed, expand) + _terminal_errors(seed_graph, expand_graph)
    unknown = sorted(set(refuted) - set(expand_graph.paths))
    errors += [f"--refute names {p}, which is not an EXPAND route" for p in unknown]
    if errors:
        return None, {}, errors

    nodes: dict[str, dict] = {i: copy.deepcopy(n) for i, n in seed_graph.nodes.items()}
    for node_id, node in expand_graph.nodes.items():
        if node_id not in nodes:
            nodes[node_id] = copy.deepcopy(node)
            continue
        nodes[node_id], node_errors = _merge_node(nodes[node_id], node)
        errors += node_errors

    paths = list(seed_graph.paths.values())
    for path_id, path in expand_graph.paths.items():
        if path_id in seed_graph.paths:
            errors.append(f"both fragments declare route {path_id}")
            continue
        if path_id in refuted:
            continue
        paths.append(path)

    cuts, cut_errors = _merge_cuts(seed, expand, {p["id"] for p in paths})
    errors += cut_errors
    if errors:
        return None, {}, errors

    dropped = _prune(nodes, paths, set(seed_graph.nodes))
    document = {**{k: seed[k] for k in SHARED if k in seed}}
    document["nodes"] = list(nodes.values())
    document["paths"] = paths
    document["observed_cuts"] = cuts
    record = {
        "nodes_added": [i for i in nodes if i not in seed_graph.nodes],
        "requires_widened": [
            i for i, n in nodes.items()
            if i in seed_graph.nodes
            and (n.get("requires") or []) != (seed_graph.nodes[i].get("requires") or [])
        ],
        "routes_added": [p["id"] for p in paths if p["id"] not in seed_graph.paths],
        "routes_refuted": [{"path": p, "reason": r} for p, r in sorted(refuted.items())],
        "nodes_dropped": dropped,
        "cuts_dropped": sorted(
            {c["id"] for f in (seed, expand) for c in f.get("observed_cuts") or []}
            - {c["id"] for c in cuts}
        ),
    }
    return document, record, []


def _prune(nodes: dict[str, dict], paths: list[dict], seed_ids: set[str]) -> list[str]:
    """Drop EXPAND-only nodes no surviving route reaches, and any `requires` naming them."""
    used = {n for path in paths for n in path["nodes"]}
    dropped = sorted(i for i in nodes if i not in seed_ids and i not in used)
    for node_id in dropped:
        del nodes[node_id]
    gone = set(dropped)
    for node in nodes.values():
        # An entry may carry `requires: null`, which validates as requiring
        # nothing; this is the same guard `_graph._requires` uses.
        if isinstance(node.get("requires"), list):
            node["requires"] = [r for r in node["requires"] if r not in gone]
    return dropped


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("seed", type=Path)
    parser.add_argument("expand", type=Path)
    parser.add_argument("--out", type=Path, required=True, help="merged graph.json")
    parser.add_argument(
        "--record", type=Path, required=True, help="merge.json: what merged, and what was refuted"
    )
    parser.add_argument(
        "--refute",
        action="append",
        default=[],
        metavar="PATH-ID=REASON",
        help="refuse one EXPAND route; the reason is written to the record",
    )
    parser.add_argument("--study-dir", type=Path, required=True)
    parser.add_argument("--scope-registry", type=Path)
    args = parser.parse_args()

    refuted, errors = _refutations(args.refute)
    seed, seed_errors = load(args.seed, args.study_dir, args.scope_registry)
    expand, expand_errors = load(args.expand, args.study_dir, args.scope_registry)
    errors += [f"SEED {e}" for e in seed_errors] + [f"EXPAND {e}" for e in expand_errors]
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1

    document, record, errors = merge(seed, expand, refuted)
    # Every record field is relative to whichever fragment was passed first, so
    # the record has to say which file that was.
    record = {"seed": str(args.seed), "expand": str(args.expand), **record}
    errors = errors or [f"merged: {e}" for e in validate(document, args.study_dir, args.scope_registry)]
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1

    for target, payload in ((args.out, document), (args.record, record)):
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(
        f"{args.out}: merged "
        f"+{len(record['nodes_added'])} node(s), "
        f"+{len(record['routes_added'])} route(s), "
        f"{len(record['routes_refuted'])} refuted, "
        f"{len(record['nodes_dropped'])} node(s) dropped"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
