#!/usr/bin/env python3
"""Merge a validated EXPAND fragment into the SEED graph.

The root owns the merged deliverable, so it must not be able to drop an
inconvenient EXPAND route by leaving it out. The union is mechanical: a route
leaves the graph only by the owning role being re-dispatched, never by the
root's choice here.
"""

from __future__ import annotations

import argparse
import copy
import json
import sys
from pathlib import Path

from _graph import CUT_SIDES, Graph, load, validate

SHARED = ("schema_version", "target")
# What makes two declarations of one node the same node. `title` and `evidence`
# are deliberately absent: EXPAND legitimately cites its own line for a node it
# reaches by another route, and SEED's declaration stands.
IDENTITY = ("role", "symbol", "store", "scope")


def _header_errors(seed: dict, expand: dict) -> list[str]:
    return [
        f"fragments disagree on {key}: {seed.get(key)!r} vs {expand.get(key)!r}"
        for key in SHARED
        if seed.get(key) != expand.get(key)
    ]


def _terminal_errors(seed: Graph, expand: Graph) -> list[str]:
    """Only the entry is SEED's alone.

    An entry is the identity the challenge grants, and a node declared `entry`
    leaves every cut, so a second one silently lowers the min-cut. An objective
    is different: at Stage 3 nothing declares it — both roles reconstruct it
    from what the target returned — and rejecting EXPAND's discarded a reachable
    asset the scope registry already had a name for.
    """
    return [
        f"EXPAND introduced entry node {node_id}, which SEED does not declare; "
        f"the entry is the identity the challenge grants, and SEED owns it"
        for node_id in expand.nodes
        if expand.role(node_id) == "entry" and node_id not in seed.nodes
    ]


def _merge_node(seed_node: dict, expand_node: dict) -> tuple[dict, list[str]]:
    """One node both roles declare: `predecessors` unions, its identity must match."""
    node_id = seed_node["id"]
    seed_before = seed_node.get("predecessors") or []
    expand_before = expand_node.get("predecessors") or []
    added = [r for r in expand_before if r not in seed_before]

    differ = [k for k in IDENTITY if seed_node.get(k) != expand_node.get(k)]
    if bool(seed_node.get("conjunctive")) != bool(expand_node.get("conjunctive")):
        differ.append("conjunctive")
    if differ:
        return seed_node, [f"fragments disagree on node {node_id}: {', '.join(differ)}"]
    if added and seed_node.get("conjunctive"):
        # Widening a conjunction would silently demand the new predecessor too.
        return seed_node, [
            f"node {node_id} sets conjunctive and the fragments list different "
            f"predecessors; adjudicate it rather than merging"
        ]
    if added:
        seed_node["predecessors"] = list(seed_before) + added
    return seed_node, []


def merge(seed: dict, expand: dict) -> tuple[dict | None, dict, list[str]]:
    """Union two validated fragments. Every field of the record is SEED-relative.

    There is no "EXPAND did not run" input. EXPAND always writes a fragment, and
    one carrying no route is what finding nothing looks like — the file existing
    is what says EXPAND ran, which no flag from the root could say.
    """
    seed_graph = Graph(seed)
    expand_graph = Graph(expand)
    errors = _header_errors(seed, expand) + _terminal_errors(seed_graph, expand_graph)
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
    # A name is the author's choice, so it cannot be what says two routes differ:
    # the walk is. Two names over one walk is one route recorded twice.
    walks = {tuple(p["nodes"]) for p in paths}
    for path_id, path in expand_graph.paths.items():
        if path_id in seed_graph.paths:
            errors.append(f"both fragments declare route {path_id}")
            continue
        walk = tuple(path["nodes"])
        if walk in walks:
            errors.append(f"EXPAND route {path_id} walks nodes SEED already recorded")
            continue
        walks.add(walk)
        paths.append(path)

    if errors:
        return None, {}, errors

    dropped = _prune(nodes, paths, set(seed_graph.nodes))
    document = {k: seed[k] for k in SHARED}
    document["nodes"] = list(nodes.values())
    document["paths"] = paths
    cut, cut_errors = _merge_cut(
        seed_graph, expand_graph, {p["id"] for p in paths}, set(nodes)
    )
    if cut_errors:
        return None, {}, cut_errors
    if cut is not None:
        document["advisory_cut"] = cut
    record = {
        "nodes_added": [i for i in nodes if i not in seed_graph.nodes],
        "predecessors_widened": [
            i for i, n in nodes.items()
            if i in seed_graph.nodes
            and (n.get("predecessors") or []) != (seed_graph.nodes[i].get("predecessors") or [])
        ],
        # Attribution is a fact of the union, not something the root should be
        # retyping downstream: the fragment a route arrived in *is* its author.
        # Routes are addressed by their position in the merged document.
        "routes": {
            p["id"]: ("seed" if p["id"] in seed_graph.paths else "expand") for p in paths
        },
        "routes_added": [p["id"] for p in paths if p["id"] not in seed_graph.paths],
        "nodes_dropped": dropped,
    }
    return document, record, []


def _merge_cut(
    seed: Graph, expand: Graph, kept: set[str], surviving_nodes: set[str]
) -> tuple[dict | None, list[str]]:
    """One advisory, one cut, so the two fragments' sides simply union.

    An entry naming a route the deliverable does not carry would say the fix was
    tested against something that is not there, so the sides follow the routes.
    """
    named = [c["advisory"] for c in (seed.advisory_cut, expand.advisory_cut)
             if c and c.get("advisory")]
    if len(set(named)) > 1:
        # Every other fragment disagreement is a hard error. Keeping one name over
        # the other would publish one advisory's fix as having guarded nodes and
        # left routes open that neither fragment claimed for it.
        return None, [f"fragments disagree on the advisory: {' vs '.join(sorted(set(named)))}"]
    advisory = named[0] if named else None
    nodes: list[str] = []
    merged: dict[str, list[dict]] = {key: [] for key in CUT_SIDES}
    for fragment in (seed.advisory_cut, expand.advisory_cut):
        for node_id in (fragment or {}).get("nodes") or []:
            # A pruned route can take the only node that reached a guarded
            # function with it; keeping the name would fail the merged graph
            # with a message about the graph rather than about the cause.
            if node_id not in nodes and node_id in surviving_nodes:
                nodes.append(node_id)
        for key in CUT_SIDES:
            for entry in (fragment or {}).get(key) or []:
                if entry["path"] in kept and entry not in merged[key]:
                    merged[key].append(entry)
    if not nodes and not any(merged.values()):
        return None, []
    return {"advisory": advisory, "nodes": nodes, **merged}, []


def _prune(nodes: dict[str, dict], paths: list[dict], seed_ids: set[str]) -> list[str]:
    """Drop EXPAND-only nodes no surviving route reaches, and any `predecessors` naming them."""
    used = {n for path in paths for n in path["nodes"]}
    dropped = sorted(i for i in nodes if i not in seed_ids and i not in used)
    for node_id in dropped:
        del nodes[node_id]
    gone = set(dropped)
    for node in nodes.values():
        # An entry may carry `predecessors: null`, which validates as requiring
        # nothing; this is the same guard `_graph._predecessors` uses.
        if isinstance(node.get("predecessors"), list):
            node["predecessors"] = [r for r in node["predecessors"] if r not in gone]
    return dropped


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("seed", type=Path)
    parser.add_argument("--out", type=Path, required=True, help="merged graph.json")
    parser.add_argument(
        "--record", type=Path, required=True, help="merge.json: what the union produced"
    )
    parser.add_argument("--expand", type=Path, required=True, help="EXPAND's fragment")
    parser.add_argument("--scope-registry", type=Path, required=True)
    args = parser.parse_args()

    seed, seed_errors = load(args.seed, args.scope_registry)
    errors = [f"SEED {e}" for e in seed_errors]
    expand, expand_errors = load(args.expand, args.scope_registry)
    errors += [f"EXPAND {e}" for e in expand_errors]
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1

    document, record, errors = merge(seed, expand)
    # Every record field is relative to whichever fragment was passed first, so
    # the record has to say which file that was.
    record = {"seed": str(args.seed), "expand": str(args.expand), **record}
    merged_errors = validate(document, args.scope_registry)
    errors = errors or [f"merged: {e}" for e in merged_errors]
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1

    for target, payload in ((args.out, document), (args.record, record)):
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(
        f"{args.out}: merged +{len(record['nodes_added'])} node(s), "
        f"+{len(record['routes_added'])} route(s)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
