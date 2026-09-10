"""Loading, validation, and analysis for the challenge graph IR.

The model itself is specified in references/graph-schema.md.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

SCHEMA_VERSION = 2
NODE_ROLES = {"entry", "function", "objective"}
TERMINAL_ROLES = {"entry", "objective"}
CUT_SIDES = ("refused", "survived")
HEX40 = re.compile(r"^[0-9a-f]{40}$")
MAX_SEARCH_NODES = 200_000
MIN_OBSERVED = 8


class Graph:
    """Indexed view over a graph document. Structure only; no validation."""

    def __init__(self, document: dict) -> None:
        self.document = document
        self.nodes = {n["id"]: n for n in _entries(document, "nodes")}
        self.paths = {p["id"]: p for p in _entries(document, "paths")}
        raw = document.get("advisory_cut")
        self.advisory_cut = raw if isinstance(raw, dict) else None

    def by_role(self, role: str) -> list[str]:
        return [i for i in self.nodes if self.role(i) == role]

    def role(self, node_id: str) -> str | None:
        """The declared role, or None when it is missing or not a string.

        Coercing here keeps every set-membership test downstream safe: a JSON
        `"role": {}` must produce the validator's message, not a TypeError.
        """
        role = self.nodes.get(node_id, {}).get("role")
        return role if isinstance(role, str) else None

    def path_nodes(self, path_id: str) -> list[str]:
        raw = self.paths[path_id].get("nodes")
        return list(raw) if isinstance(raw, list) else []

    def interior(self, path_id: str) -> frozenset[str]:
        """Nodes a defense may target on this path: everything but the terminals."""
        return frozenset(
            n
            for n in self.path_nodes(path_id)
            if n in self.nodes and self.role(n) not in TERMINAL_ROLES
        )


def _id(entry: object) -> bool:
    return isinstance(entry, dict) and isinstance(entry.get("id"), str)


def _entries(document: dict, key: str) -> list[dict]:
    raw = document.get(key)
    return [e for e in raw if _id(e)] if isinstance(raw, list) else []


def _predecessors(node: dict) -> list[str]:
    raw = node.get("predecessors")
    return [r for r in raw if isinstance(r, str)] if isinstance(raw, list) else []


def _conjunctive(node: dict) -> bool:
    """Whether every listed predecessor is needed, or any one of them suffices."""
    return bool(node.get("conjunctive"))


# --- analysis ---------------------------------------------------------------


def minimal_cuts(node_sets: list[frozenset[str]]) -> int | None:
    """Size of the smallest set of nodes that hits every recorded route.

    Branch and bound on an unhit path rather than searching by subset size:
    a cut always exists at or below the path count, so the depth is bounded
    even when the node universe is large. Cost still grows about 6x per added
    disjoint path, so a work cap keeps the tool terminating; when it fires the
    result is `None`, never a guess — an over-stated mincut manufactures a
    false `disjoint`.

    Only the size is computed. Enumerating the cheapest cuts told a reader which
    nodes to sever, and the cheapest set is routinely a shared executor every
    legitimate request needs, so the listing named defenses that were not
    defenses.
    """
    if not node_sets or any(not node_set for node_set in node_sets):
        return None
    for size in range(1, len(node_sets) + 1):
        work = [MAX_SEARCH_NODES]
        if _search(node_sets, size, frozenset(), work):
            return size
        if work[0] <= 0:
            return None
    return None


def _search(
    node_sets: list[frozenset[str]], depth: int, chosen: frozenset[str], work: list[int]
) -> bool:
    work[0] -= 1
    if work[0] <= 0:
        return False
    unhit = [node_set for node_set in node_sets if not (node_set & chosen)]
    if not unhit:
        return True
    if depth == 0:
        return False
    # Branching on the smallest unhit path keeps the factor as low as the data
    # allows; every cut must contain one of its nodes.
    for node in sorted(min(unhit, key=len)):
        if _search(node_sets, depth - 1, chosen | {node}, work):
            return True
    return False


def analyze(graph: Graph) -> dict:
    paths = list(graph.paths)
    objectives = graph.by_role("objective")
    interiors = {p: graph.interior(p) for p in paths}

    per_objective: dict[str, dict] = {}
    for objective in objectives:
        members = [p for p in paths if graph.paths[p].get("objective") == objective]
        per_objective[objective] = {
            "scope": graph.nodes[objective].get("scope"),
            "routes": len(members),
            "mincut": minimal_cuts([interiors[p] for p in members]),
        }

    mincut_all = minimal_cuts([interiors[p] for p in paths])

    # Every route counts, however short. A one-function route used to suppress
    # the labels below on the grounds that it was "just a one-step attack" —
    # an editorial call, and the label it hid was accurate.
    labels: list[str] = []
    spans = {
        node: {graph.paths[p].get("objective") for p in paths if node in interiors[p]}
        for node in set().union(*interiors.values())
    }
    if any(len(reached) >= 2 for reached in spans.values()):
        labels.append("fan_out")
    if any(d["routes"] >= 2 and d["mincut"] == 1 for d in per_objective.values()):
        labels.append("fan_in")
    if mincut_all is not None and mincut_all >= 2:
        labels.append("disjoint")

    # The advisory cut is authored, not computed, so it stays in graph.json where
    # its evidence is. Restating it here was a projection nothing derived.
    return {
        "geometry": sorted(set(labels)),
        "mincut_all": mincut_all,
        "objective_coverage": per_objective,
    }


def _witnesses(path: dict) -> list[dict]:
    raw = path.get("witnesses")
    return [w for w in raw if isinstance(w, dict)] if isinstance(raw, list) else []


# --- structural validation --------------------------------------------------


def _text(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def evidence_shape(evidence: object, where: str, errors: list[str]) -> None:
    """One observation: what was sent, what came back, and the part that carries
    the claim.

    Every observation is a response this run received. There is no field saying
    where the text came from, because there is only one place it may come from:
    the study says where to look and never what to record.

    Nothing here is resolved against the filesystem. A graph that cited a file
    outside itself stopped meaning what it meant the moment that file moved or
    was regenerated, and a stale citation that still matches its quoted string
    is worse than none: it reads as checked. So the excerpt travels with the
    claim and `source` is a label for a human, never a path to open.
    """
    if not isinstance(evidence, dict):
        errors.append(f"{where}.evidence must be an object")
        return
    for gone in ("kind", "locator", "provenance"):
        if gone in evidence:
            errors.append(
                f"{where}.evidence.{gone} was removed; an observation is source, "
                "excerpt and observed — every one of them a response this run received"
            )
    for field in ("source", "excerpt"):
        if not _text(evidence.get(field)):
            errors.append(f"{where}.evidence.{field} must be a non-empty string")
    observed = evidence.get("observed")
    if not _text(observed) or len(str(observed).strip()) < MIN_OBSERVED:
        errors.append(
            f"{where}.evidence.observed must quote at least {MIN_OBSERVED} characters "
            "of the excerpt"
        )
    elif _text(evidence.get("excerpt")) and str(observed) not in str(evidence["excerpt"]):
        errors.append(f"{where}.evidence.observed does not appear in the excerpt")


def structural_errors(document: object) -> list[str]:
    """Every check that needs no filesystem access."""
    errors: list[str] = []
    if not isinstance(document, dict):
        return ["graph must be a JSON object"]
    if document.get("schema_version") != SCHEMA_VERSION:
        return [f"graph must be a schema-version {SCHEMA_VERSION} JSON object"]
    for legacy in ("states", "operations"):
        if legacy in document:
            return [
                f"'{legacy}' is schema 1; schema 2 has one 'nodes' list of "
                "entry points, functions, and objectives"
            ]

    target = document.get("target")
    if not isinstance(target, dict):
        errors.append("target must be an object")
    else:
        if not _text(target.get("id")):
            errors.append("target.id must be a non-empty string")
        repository = target.get("repository")
        if not _text(repository) or str(repository).count("/") != 1:
            errors.append("target.repository must look like owner/project")
        if not HEX40.match(str(target.get("revision", ""))):
            errors.append("target.revision must be 40 lowercase hex characters")

    graph = Graph(document)
    raw_nodes = document.get("nodes")
    if not isinstance(raw_nodes, list) or not raw_nodes:
        errors.append("nodes must be a non-empty list")
    elif len(graph.nodes) != len(raw_nodes):
        errors.append("every nodes entry needs a unique string id")
    # `paths` may be empty here. This validates a *fragment* as often as a
    # finished graph, and EXPAND finding no further route is a real outcome that
    # has to be writable: the fragment's existence is what says EXPAND ran at
    # all. A finished deliverable with no route is rejected by graph_finalize.py,
    # which is the step that owns finished trees.
    raw_paths = document.get("paths")
    if not isinstance(raw_paths, list):
        errors.append("paths must be a list")
    elif len(graph.paths) != len(raw_paths):
        errors.append("every paths entry needs a unique string id")

    errors.extend(_node_errors(graph))
    if not graph.by_role("entry"):
        errors.append("graph needs at least one entry node")
    if not graph.by_role("objective"):
        errors.append("graph needs at least one objective node")

    for path_id, path in graph.paths.items():
        errors.extend(_path_errors(graph, path_id, path))
    # A route *is* its walk. Two entries over the same nodes are one route
    # recorded twice, which inflates the route count and can manufacture a
    # `fan_in` reading out of a single way in.
    walks: dict[tuple, str] = {}
    for path_id, path in graph.paths.items():
        walk = tuple(path.get("nodes") or [])
        if walk in walks:
            errors.append(f"route {path_id} walks the same nodes as route {walks[walk]}")
        else:
            walks[walk] = path_id

    errors.extend(_advisory_cut_errors(graph, document))
    errors.extend(_cycle_errors(graph))
    return errors


def _node_errors(graph: Graph) -> list[str]:
    errors: list[str] = []
    for node_id, node in graph.nodes.items():
        # `requires` read as AND to anyone writing it and as OR to the analyzer.
        # Silently ignoring it would leave the node with no predecessors at all,
        # which is a worse reading than either.
        for gone, now in (("requires", "predecessors"), ("requires_all", "conjunctive")):
            if gone in node:
                errors.append(f"node {node_id}.{gone} is now {now}")
    symbols: dict[str, str] = {}
    for node_id, node in graph.nodes.items():
        role = graph.role(node_id)
        if role not in NODE_ROLES:
            errors.append(f"node {node_id} has an unknown role")
            continue
        if role == "objective":
            for field in ("store", "scope"):
                if not _text(node.get(field)):
                    errors.append(f"objective {node_id} must declare {field}")
        elif not _text(node.get("title")):
            errors.append(f"node {node_id} must declare a title")

        # `symbol` is what says two nodes are one node: required on a function,
        # unique across the document. One function under two ids reads as two
        # routes sharing nothing, which halves the min-cut.
        symbol = node.get("symbol")
        if role == "function" and "symbol" not in node:
            errors.append(
                f"function {node_id} must declare symbol, the application function "
                f"or route it names"
            )
        elif "symbol" in node and not _text(symbol):
            errors.append(f"node {node_id}.symbol must be a non-empty string")
        elif _text(symbol):
            if symbol in symbols:
                errors.append(
                    f"nodes {symbols[symbol]} and {node_id} share symbol {symbol!r}; "
                    f"one application function is one node"
                )
            symbols.setdefault(symbol, node_id)

        raw = node.get("predecessors")
        if role == "entry":
            if raw:
                errors.append(f"entry {node_id} must not require another node")
            continue
        if not isinstance(raw, list) or not raw:
            errors.append(f"node {node_id}.predecessors must be a non-empty list")
            continue
        for other in raw:
            if not isinstance(other, str) or other not in graph.nodes:
                errors.append(f"node {node_id}.predecessors has unknown node {other}")
            elif graph.role(other) == "objective":
                errors.append(f"node {node_id} may not require objective {other}")
        if not isinstance(node.get("conjunctive", False), bool):
            errors.append(f"node {node_id}.conjunctive must be a boolean")
        if role == "function":
            evidence_shape(node.get("evidence"), f"node {node_id}", errors)
    return errors


def _derivable(graph: Graph, nodes: set[str], objective: str) -> bool:
    """Whether the objective still follows from this node set.

    A node holds once an entry needs nothing, all conjuncts hold, or any one
    disjunct holds. Both rules are monotone in the node set, which is why
    checking one dropped node at a time is complete: if the objective survives
    the loss of any subset, it survives the loss of some single node in it.
    """
    have: set[str] = set()
    changed = True
    while changed:
        changed = False
        for node_id in nodes - have:
            node = graph.nodes[node_id]
            needed = _predecessors(node)
            rule = all if _conjunctive(node) else any
            if rule(r in have for r in needed) if needed else graph.role(node_id) == "entry":
                have.add(node_id)
                changed = True
    return objective in have


def _droppable_errors(
    graph: Graph, path_id: str, nodes: list[str], objective: str
) -> list[str]:
    """A route may carry no node it could reach the objective without.

    See references/graph-schema.md, "Paths", for why this rule exists.
    """
    errors = []
    for node_id in nodes:
        if graph.role(node_id) != "function":
            continue
        if _derivable(graph, set(nodes) - {node_id}, objective):
            errors.append(
                f"route {path_id} still reaches {objective} without {node_id}; "
                "record the shorter route instead"
            )
    return errors


def _path_errors(graph: Graph, path_id: str, path: dict) -> list[str]:
    errors: list[str] = []
    objective = path.get("objective")
    if not isinstance(objective, str) or graph.role(objective) != "objective":
        errors.append(f"route {path_id}.objective must name an objective node")
        objective = None

    nodes = path.get("nodes")
    if not isinstance(nodes, list) or not nodes:
        return errors + [f"route {path_id}.nodes must be a non-empty list"]
    unknown = [n for n in nodes if not isinstance(n, str) or n not in graph.nodes]
    if unknown:
        listed = ", ".join(str(n) for n in unknown)
        return errors + [f"route {path_id} has unknown nodes: {listed}"]
    repeated = sorted({n for n in nodes if nodes.count(n) > 1})
    if repeated:
        # A route is a walk over distinct nodes; a repeat only inflates the node
        # count the renderer prints, since every computed set ignores it.
        return errors + [f"route {path_id} lists {', '.join(repeated)} more than once"]

    if graph.role(nodes[0]) != "entry":
        errors.append(f"route {path_id} must start at an entry node")
    if objective and nodes[-1] != objective:
        errors.append(f"route {path_id} must end at {objective}")
    for node_id in nodes[1:-1]:
        if graph.role(node_id) != "function":
            errors.append(f"route {path_id} interior node {node_id} must be a function")

    seen: set[str] = set()
    for node_id in nodes:
        node = graph.nodes[node_id]
        needed = _predecessors(node)
        if needed and _conjunctive(node):
            missing = [r for r in needed if r not in seen]
            if missing:
                errors.append(
                    f"route {path_id} reaches {node_id} without {', '.join(sorted(missing))}"
                )
        elif needed and not any(r in seen for r in needed):
            errors.append(
                f"route {path_id} reaches {node_id} before any of its predecessors"
            )
        seen.add(node_id)

    if not graph.interior(path_id):
        errors.append(f"route {path_id} needs at least one interior node")
    elif objective:
        errors.extend(_droppable_errors(graph, path_id, nodes, objective))

    witnesses = _witnesses(path)
    if not witnesses:
        errors.append(f"route {path_id}.witnesses must record at least one observation")
    for index, witness in enumerate(witnesses):
        evidence_shape(witness, f"route {path_id} witness {index}", errors)

    advisories = path.get("advisories")
    if advisories is not None and (
        not isinstance(advisories, list)
        or any(not _text(a) for a in advisories)
    ):
        errors.append(f"route {path_id}.advisories must be a list of identifiers")
    return errors


def _advisory_cut_errors(graph: Graph, document: dict) -> list[str]:
    """The one cut in the graph whose admissibility is known.

    `survived` is decisive and `refused` is not: one request reaching the
    objective proves the route open, while no number of refusals proves it
    closed. So `refused` records what this run sent, never that the fix severed
    the route, and each entry says which payload shapes it tried.

    Every other cut this tool reports is a candidate nobody has judged — the
    cheapest is routinely a shared executor every legitimate request needs, so
    severing it is feature amputation. This one shipped upstream with the
    feature intact, which makes it an exemplar: these nodes could be guarded,
    and the project accepted the result.

    `nodes` is what the fix touched. `refused` and `survived` are what that
    achieved over the recorded routes, so an accepted cut that leaves a route
    open is sayable — which is the whole reason to record it rather than trust
    it.

    One advisory, one cut, so there is no id and no `reference`. The earlier
    model let a defense be split across two ids, and the id holding only the
    refused routes then read as terminal for a defense a recorded route
    demonstrably escaped.
    """
    raw = document.get("advisory_cut")
    if raw is None:
        return []
    if not isinstance(raw, dict):
        return ["advisory_cut must be an object"]

    errors: list[str] = []
    if "blocked" in raw:
        # Ignoring it would drop the whole side: the routes it names vanish from
        # the render and from the merge, and the `tried` check never sees them.
        errors.append("advisory_cut.blocked is now refused, and each entry needs `tried`")
    # The cut is named for the advisory, so it must say which one. Most fixes
    # ship with a CVE; a few land as an ordinary commit, and naming that commit
    # is what keeps the cut from being anonymous.
    if not _text(raw.get("advisory")):
        errors.append("advisory_cut.advisory must name the advisory, or the "
                      "upstream commit where the fix shipped without one")
    nodes = raw.get("nodes")
    if not isinstance(nodes, list) or not nodes:
        errors.append("advisory_cut.nodes must be a non-empty list of the nodes the fix touched")
    else:
        for node_id in nodes:
            if node_id not in graph.nodes:
                errors.append(f"advisory_cut.nodes names {node_id}, which is not a node")
            elif graph.role(node_id) != "function":
                # A fix that severed a terminal would be removing the identity the
                # challenge grants, or the asset itself. Neither is a defense of
                # this boundary, and neither is what upstream shipped.
                errors.append(f"advisory_cut.nodes names {node_id}, a {graph.role(node_id)}")
    seen: set[str] = set()
    recorded = 0
    for key in CUT_SIDES:
        entries = raw.get(key, [])
        if not isinstance(entries, list):
            errors.append(f"advisory_cut.{key} must be a list")
            continue
        recorded += len(entries)
        for entry in entries:
            path_ref = entry.get("path") if isinstance(entry, dict) else None
            if not isinstance(path_ref, str) or path_ref not in graph.paths:
                errors.append(f"advisory_cut.{key} has an unknown route")
                continue
            if path_ref in seen:
                errors.append(f"advisory_cut records {path_ref} on both sides")
            seen.add(path_ref)
            evidence_shape(entry, f"advisory_cut {key} {path_ref}", errors)
            if key == "refused" and not _text(entry.get("tried")):
                # "Every request I sent failed" is not "the route is severed", and
                # a run that sent one family of payloads cannot tell them apart.
                # Saying what was tried is what lets a reader see the gap.
                errors.append(
                    f"advisory_cut.refused {path_ref} must say what was tried; "
                    "refusing every request of one shape is not severance"
                )
    if not recorded:
        errors.append("advisory_cut records no route; leave it out instead")
    return errors


def _cycle_errors(graph: Graph) -> list[str]:
    edges = {n: _predecessors(node) for n, node in graph.nodes.items()}
    colors: dict[str, int] = {}

    def visit(node: str) -> bool:
        colors[node] = 1
        for nxt in edges.get(node, []):
            if colors.get(nxt) == 1:
                return True
            if colors.get(nxt) is None and visit(nxt):
                return True
        colors[node] = 2
        return False

    for node in list(edges):
        if colors.get(node) is None and visit(node):
            return ["graph must be acyclic"]
    return []


# --- evidence validation ----------------------------------------------------


def scope_errors(graph: Graph, registry_path: Path) -> list[str]:
    """Objective scopes must be registered or explicitly challenge-local."""
    try:
        registry = json.loads(registry_path.read_text(encoding="utf-8"))
        known = {entry.get("id") for entry in registry["scopes"]}
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError,
            AttributeError) as exc:
        return [f"scope registry could not be read: {exc}"]
    errors = []
    for node_id in graph.by_role("objective"):
        scope = graph.nodes[node_id].get("scope")
        if scope not in known and not str(scope).startswith("custom."):
            errors.append(f"objective {node_id} scope {scope} is not registered")
    return errors


def validate(document: object, registry: Path) -> list[str]:
    """Every check, in the order that produces the most useful first message.

    Nothing outside the document is read but the scope registry, which is a
    fixed list rather than a per-study artifact. The registry is required: an
    optional one meant every objective scope went unchecked in silence.
    """
    errors = structural_errors(document)
    if errors:
        return errors
    return scope_errors(Graph(document), registry)


def load(path: Path, registry: Path) -> tuple[object, list[str]]:
    """Read and fully validate one graph, for every CLI."""
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None, [f"graph does not exist: {path}"]
    except (OSError, UnicodeDecodeError) as exc:
        return None, [f"{path} could not be read: {exc}"]
    except json.JSONDecodeError as exc:
        return None, [f"{path} is not valid JSON: {exc}"]
    return document, validate(document, registry)
