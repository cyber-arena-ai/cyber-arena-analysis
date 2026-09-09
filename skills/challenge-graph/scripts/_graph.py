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
LOCATOR = re.compile(r"^(?P<path>[^#]+)#L(?P<line>[1-9][0-9]*)$")
HEX40 = re.compile(r"^[0-9a-f]{40}$")
MAX_LISTED_CUTS = 32
MAX_SEARCH_NODES = 200_000
MIN_OBSERVED = 8


class Graph:
    """Indexed view over a graph document. Structure only; no validation."""

    def __init__(self, document: dict) -> None:
        self.document = document
        self.nodes = {n["id"]: n for n in _entries(document, "nodes")}
        self.paths = {p["id"]: p for p in _entries(document, "paths")}
        self.observed_cuts = _entries(document, "observed_cuts")

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


def _requires(node: dict) -> list[str]:
    raw = node.get("requires")
    return [r for r in raw if isinstance(r, str)] if isinstance(raw, list) else []


def _requires_all(node: dict) -> bool:
    """Whether every listed predecessor is needed, or any one of them suffices."""
    return bool(node.get("requires_all"))


# --- analysis ---------------------------------------------------------------


def minimal_cuts(node_sets: list[frozenset[str]]) -> tuple[list[frozenset[str]], int | None, bool]:
    """Minimum-cardinality hitting sets over the recorded paths.

    Branch and bound on an unhit path rather than searching by subset size:
    a cut always exists at or below the path count, so the depth is bounded
    even when the node universe is large. Cost still grows about 6x per added
    disjoint path, so a work cap keeps the tool terminating; when it fires the
    result is `mincut` `None` with `cuts_truncated` set, never a guess.
    """
    if not node_sets or any(not node_set for node_set in node_sets):
        return [], None, False
    for size in range(1, len(node_sets) + 1):
        found: set[frozenset[str]] = set()
        budget = [MAX_SEARCH_NODES]
        _search(node_sets, size, frozenset(), found, budget)
        if found:
            listed = sorted(found, key=sorted)
            truncated = len(listed) > MAX_LISTED_CUTS or budget[0] <= 0
            return listed[:MAX_LISTED_CUTS], size, truncated
        if budget[0] <= 0:
            # The exact search ran out of room. Say so rather than substitute an
            # estimate: an over-stated mincut manufactures a false `disjoint`.
            return [], None, True
    return [], None, False


def _search(
    node_sets: list[frozenset[str]],
    budget: int,
    chosen: frozenset[str],
    found: set[frozenset[str]],
    remaining: list[int],
) -> None:
    remaining[0] -= 1
    if remaining[0] <= 0:
        return
    unhit = [node_set for node_set in node_sets if not (node_set & chosen)]
    if not unhit:
        found.add(chosen)
        return
    if budget == 0 or len(found) > MAX_LISTED_CUTS:
        return
    # Branching on the smallest unhit path keeps the factor as low as the data
    # allows; every cut must contain one of its nodes.
    for node in sorted(min(unhit, key=len)):
        _search(node_sets, budget - 1, chosen | {node}, found, remaining)


def analyze(graph: Graph) -> dict:
    paths = list(graph.paths)
    objectives = graph.by_role("objective")
    interiors = {p: graph.interior(p) for p in paths}
    trivial = [p for p in paths if len(interiors[p]) < 2]

    per_objective: dict[str, dict] = {}
    for objective in objectives:
        members = [p for p in paths if graph.paths[p].get("objective") == objective]
        _, size, _ = minimal_cuts([interiors[p] for p in members])
        per_objective[objective] = {
            "scope": graph.nodes[objective].get("scope"),
            "paths": members,
            "mincut": size,
        }

    all_cuts, mincut_all, all_truncated = minimal_cuts([interiors[p] for p in paths])
    _, mincut_nontrivial, _ = minimal_cuts(
        [interiors[p] for p in paths if p not in trivial]
    )

    labels: list[str] = []
    if trivial:
        # A reproduced one-node route dominates every other reading: it would
        # otherwise inflate mincut_all and manufacture `disjoint`.
        labels.append("shallow")
    else:
        spans = {
            node: {graph.paths[p].get("objective") for p in paths if node in interiors[p]}
            for node in set().union(*interiors.values())
        }
        if any(len(reached) >= 2 for reached in spans.values()):
            labels.append("fan_out")
        if any(len(d["paths"]) >= 2 and d["mincut"] == 1 for d in per_objective.values()):
            labels.append("fan_in")
        if mincut_all is not None and mincut_all >= 2:
            labels.append("disjoint")
        if len(paths) == 1:
            labels.append("single_path")

    return {
        "geometry": sorted(set(labels)),
        "mincut_all": mincut_all,
        "mincut_nontrivial": mincut_nontrivial,
        "minimum_cuts_all": [sorted(c) for c in all_cuts],
        "cuts_truncated": all_truncated,
        "nontrivial_paths": {p: p not in trivial for p in paths},
        "objective_coverage": per_objective,
        "observed_cuts": _observed(graph),
        "frontier": _frontier(graph, per_objective),
        "citation_sources": _citation_sources(graph),
    }


def _citation_sources(graph: Graph) -> dict[str, int]:
    """Where the graph's citations land, as a fact rather than a judgment."""
    root = graph.document.get("evidence_root")
    counts = {"inside_evidence_root": 0, "elsewhere": 0}
    for _, evidence in _evidence_entries(graph):
        match = LOCATOR.match(str(evidence.get("locator", "")))
        inside = root is not None and Path(match.group("path")).is_relative_to(Path(str(root)))
        counts["inside_evidence_root" if inside else "elsewhere"] += 1
    return counts


def _witnesses(path: dict) -> list[dict]:
    raw = path.get("witnesses")
    return [w for w in raw if isinstance(w, dict)] if isinstance(raw, list) else []


def _observed(graph: Graph) -> list[dict]:
    results = []
    for cut in graph.observed_cuts:
        blocked = [e["path"] for e in cut.get("blocked", []) if _path_ref(graph, e)]
        survived = [e["path"] for e in cut.get("survived", []) if _path_ref(graph, e)]
        reading = "contestable_observed" if survived else "terminal_over_recorded_subgraph"
        implicated: set[str] = set()
        if blocked:
            # The extensional root cause: interior nodes common to every blocked
            # route and absent from every survivor.
            implicated = set.intersection(*(set(graph.interior(p)) for p in blocked))
            for path_id in survived:
                implicated -= set(graph.interior(path_id))
        results.append(
            {
                "id": cut["id"],
                "reference": cut.get("reference"),
                "blocked": blocked,
                "survived": survived,
                "reading": reading,
                "implicated_nodes": sorted(implicated),
            }
        )
    return results


def _path_ref(graph: Graph, entry: object) -> bool:
    return (
        isinstance(entry, dict)
        and isinstance(entry.get("path"), str)
        and entry["path"] in graph.paths
    )


def _frontier(graph: Graph, per_objective: dict) -> list[dict]:
    items = []
    for objective, detail in per_objective.items():
        if not detail["paths"]:
            items.append({"kind": "unreached_objective", "target": objective})
    tested = {
        entry["path"]
        for cut in graph.observed_cuts
        for key in ("blocked", "survived")
        for entry in cut.get(key, []) or []
        if _path_ref(graph, entry)
    }
    for path_id in graph.paths:
        if path_id not in tested:
            items.append({"kind": "untested_path", "target": path_id})
    return items


# --- structural validation --------------------------------------------------


def _text(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def evidence_shape(evidence: object, where: str, errors: list[str]) -> None:
    """A citation must point at a real line and quote enough of it to check."""
    if not isinstance(evidence, dict):
        errors.append(f"{where}.evidence must be an object")
        return
    if "kind" in evidence:
        errors.append(
            f"{where}.evidence.kind was removed in schema 2; a citation is a "
            "locator and an observed string"
        )
    observed = evidence.get("observed")
    if not _text(observed) or len(str(observed).strip()) < MIN_OBSERVED:
        errors.append(
            f"{where}.evidence.observed must quote at least {MIN_OBSERVED} characters "
            "of the cited line"
        )
    locator = evidence.get("locator")
    if not _text(locator) or not LOCATOR.match(str(locator)):
        errors.append(f"{where}.evidence.locator must look like path/to/file.txt#L12")


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

    root = document.get("evidence_root")
    if root is not None:
        parts = Path(str(root)).parts if _text(root) else ()
        if not parts or Path(str(root)).is_absolute() or ".." in parts:
            errors.append("evidence_root must name a directory inside the study")

    graph = Graph(document)
    for key, index in (("nodes", graph.nodes), ("paths", graph.paths)):
        raw = document.get(key)
        if not isinstance(raw, list) or not raw:
            errors.append(f"{key} must be a non-empty list")
        elif len(index) != len(raw):
            errors.append(f"every {key} entry needs a unique string id")

    errors.extend(_node_errors(graph))
    if not graph.by_role("entry"):
        errors.append("graph needs at least one entry node")
    if not graph.by_role("objective"):
        errors.append("graph needs at least one objective node")

    for path_id, path in graph.paths.items():
        errors.extend(_path_errors(graph, path_id, path))

    errors.extend(_cut_errors(graph, document))
    errors.extend(_cycle_errors(graph))
    return errors


def _node_errors(graph: Graph) -> list[str]:
    errors: list[str] = []
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

        raw = node.get("requires")
        if role == "entry":
            if raw:
                errors.append(f"entry {node_id} must not require another node")
            continue
        if not isinstance(raw, list) or not raw:
            errors.append(f"node {node_id}.requires must be a non-empty list")
            continue
        for other in raw:
            if not isinstance(other, str) or other not in graph.nodes:
                errors.append(f"node {node_id}.requires has unknown node {other}")
            elif graph.role(other) == "objective":
                errors.append(f"node {node_id} may not require objective {other}")
        if not isinstance(node.get("requires_all", False), bool):
            errors.append(f"node {node_id}.requires_all must be a boolean")
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
            needed = _requires(node)
            rule = all if _requires_all(node) else any
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
                f"path {path_id} still reaches {objective} without {node_id}; "
                "record the shorter route instead"
            )
    return errors


def _path_errors(graph: Graph, path_id: str, path: dict) -> list[str]:
    errors: list[str] = []
    objective = path.get("objective")
    if not isinstance(objective, str) or graph.role(objective) != "objective":
        errors.append(f"path {path_id}.objective must name an objective node")
        objective = None

    nodes = path.get("nodes")
    if not isinstance(nodes, list) or not nodes:
        return errors + [f"path {path_id}.nodes must be a non-empty list"]
    unknown = [n for n in nodes if not isinstance(n, str) or n not in graph.nodes]
    if unknown:
        listed = ", ".join(str(n) for n in unknown)
        return errors + [f"path {path_id} has unknown nodes: {listed}"]

    if graph.role(nodes[0]) != "entry":
        errors.append(f"path {path_id} must start at an entry node")
    if objective and nodes[-1] != objective:
        errors.append(f"path {path_id} must end at {objective}")
    for node_id in nodes[1:-1]:
        if graph.role(node_id) != "function":
            errors.append(f"path {path_id} interior node {node_id} must be a function")

    seen: set[str] = set()
    for node_id in nodes:
        node = graph.nodes[node_id]
        needed = _requires(node)
        if needed and _requires_all(node):
            missing = [r for r in needed if r not in seen]
            if missing:
                errors.append(
                    f"path {path_id} reaches {node_id} without {', '.join(sorted(missing))}"
                )
        elif needed and not any(r in seen for r in needed):
            errors.append(
                f"path {path_id} reaches {node_id} before any of its predecessors"
            )
        seen.add(node_id)

    if not graph.interior(path_id):
        errors.append(f"path {path_id} needs at least one interior node")
    elif objective:
        errors.extend(_droppable_errors(graph, path_id, nodes, objective))

    witnesses = _witnesses(path)
    if not witnesses:
        errors.append(f"path {path_id}.witnesses must record at least one observation")
    for index, witness in enumerate(witnesses):
        evidence_shape(witness, f"path {path_id} witness {index}", errors)

    advisories = path.get("advisories")
    if advisories is not None and (
        not isinstance(advisories, list)
        or any(not _text(a) for a in advisories)
    ):
        errors.append(f"path {path_id}.advisories must be a list of identifiers")
    return errors


def _cut_errors(graph: Graph, document: dict) -> list[str]:
    errors: list[str] = []
    raw = document.get("observed_cuts", [])
    if not isinstance(raw, list):
        return ["observed_cuts must be a list"]
    if len({c["id"] for c in graph.observed_cuts}) != len(raw):
        errors.append("every observed_cuts entry needs a unique string id")
    seen_reference: dict[str, str] = {}
    for cut in graph.observed_cuts:
        cut_id = cut["id"]
        reference = cut.get("reference")
        if not _text(reference):
            errors.append(f"cut {cut_id}.reference must be a non-empty string")
        elif reference in seen_reference:
            # Split ids give one defense two readings: the id holding only the
            # blocked routes reads terminal, for a defense a recorded route escaped.
            errors.append(
                f"cuts {seen_reference[reference]} and {cut_id} record the same "
                f"defense {reference!r}; use one id"
            )
        else:
            seen_reference[reference] = cut_id
        seen: set[str] = set()
        recorded = 0
        for key in ("blocked", "survived"):
            entries = cut.get(key, [])
            if not isinstance(entries, list):
                errors.append(f"cut {cut_id}.{key} must be a list")
                continue
            recorded += len(entries)
            for entry in entries:
                path_ref = entry.get("path") if isinstance(entry, dict) else None
                if not isinstance(path_ref, str) or path_ref not in graph.paths:
                    errors.append(f"cut {cut_id}.{key} has an unknown path")
                    continue
                if path_ref in seen:
                    errors.append(f"cut {cut_id} lists {path_ref} twice")
                seen.add(path_ref)
                evidence_shape(entry, f"cut {cut_id} entry {path_ref}", errors)
        if not recorded:
            # Survivors alone are a legitimate cut: "this defense was applied and
            # did not stop these routes" is the contestability signal, and an
            # EXPAND fragment carrying only a survivor must be able to say it.
            errors.append(f"cut {cut_id} must record at least one path")
    return errors


def _cycle_errors(graph: Graph) -> list[str]:
    edges = {n: _requires(node) for n, node in graph.nodes.items()}
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


# --- evidence and study validation ------------------------------------------


def study_errors(study_dir: Path) -> list[str]:
    """The study directory must be a real Stage 3 study, not a scratch tree."""
    if not study_dir.is_dir():
        return [f"study directory does not exist: {study_dir}"]
    if not (study_dir / "STAGE3_STUDY.md").is_file():
        return [
            f"{study_dir} is not a Stage 3 study; no STAGE3_STUDY.md. "
            "Evidence must resolve against the study that produced it."
        ]
    return []


def _evidence_entries(graph: Graph) -> list[tuple[str, dict]]:
    entries: list[tuple[str, dict]] = []
    for node_id, node in graph.nodes.items():
        if graph.role(node_id) == "function" and isinstance(node.get("evidence"), dict):
            entries.append((f"node {node_id}", node["evidence"]))
    for path_id, path in graph.paths.items():
        for index, witness in enumerate(_witnesses(path)):
            entries.append((f"path {path_id} witness {index}", witness))
    for cut in graph.observed_cuts:
        for key in ("blocked", "survived"):
            raw = cut.get(key, [])
            for entry in raw if isinstance(raw, list) else []:
                if isinstance(entry, dict):
                    entries.append((f"cut {cut['id']} {key} {entry.get('path')}", entry))
    return entries


def evidence_errors(graph: Graph, study_dir: Path) -> list[str]:
    """Resolve each locator to a real line holding the observed string."""
    errors: list[str] = []
    declared = graph.document.get("evidence_root")
    anchor = (
        (study_dir / str(declared)).resolve() if declared is not None else study_dir.resolve()
    )
    for where, evidence in _evidence_entries(graph):
        match = LOCATOR.match(str(evidence.get("locator", "")))
        relative = Path(match.group("path"))
        if relative.is_absolute() or ".." in relative.parts:
            errors.append(f"{where} locator must stay inside the study")
            continue
        resolved = study_dir / relative
        # resolve() first: a symlink inside the tree must not read out of it.
        if not resolved.resolve().is_relative_to(anchor):
            errors.append(f"{where} locator resolves outside {anchor.name}")
            continue
        if not resolved.is_file():
            errors.append(f"{where} locator does not exist: {relative}")
            continue
        lines = resolved.read_text(encoding="utf-8", errors="replace").split("\n")
        number = int(match.group("line"))
        if number > len(lines):
            errors.append(f"{where} locator points past the end of {relative}")
            continue
        if str(evidence.get("observed", "")) not in lines[number - 1]:
            errors.append(f"{where} observed string is not on {relative} line {number}")
    return errors


def discriminator_warnings(graph: Graph, study_dir: Path) -> list[dict]:
    """Flag a route's witness that reads the same on the repaired build.

    A witness claims the objective was reached, so text that also appears where
    the cut recorded that route blocked cannot support it. The comparison is
    against those exact cited lines: pooling whole files warned on every study
    that keeps one combined fixed-build log, and on a survivor's own success
    string, which is what surviving means.
    """
    blocked_lines: dict[str, list[str]] = {}
    for cut in graph.observed_cuts:
        for entry in cut.get("blocked", []) or []:
            match = LOCATOR.match(str(entry.get("locator", ""))) if isinstance(entry, dict) else None
            if not match:
                continue
            candidate = study_dir / match.group("path")
            if not candidate.is_file():
                continue
            lines = candidate.read_text(encoding="utf-8", errors="replace").split("\n")
            number = int(match.group("line"))
            if number <= len(lines):
                blocked_lines.setdefault(entry["path"], []).append(lines[number - 1])

    warnings = []
    for path_id, path in graph.paths.items():
        for index, witness in enumerate(_witnesses(path)):
            observed = str(witness.get("observed", ""))
            if observed and any(observed in line for line in blocked_lines.get(path_id, [])):
                warnings.append(
                    {
                        "kind": "non_discriminating_witness",
                        "where": f"path {path_id} witness {index}",
                        "detail": "observed text also appears where this route was "
                        "recorded blocked, so it does not show the objective was reached",
                    }
                )
    return warnings


def scope_errors(graph: Graph, registry_path: Path) -> list[str]:
    """Objective scopes must be registered or explicitly challenge-local."""
    try:
        registry = json.loads(registry_path.read_text(encoding="utf-8"))
        known = {entry.get("id") for entry in registry["scopes"]}
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError) as exc:
        return [f"scope registry could not be read: {exc}"]
    errors = []
    for node_id in graph.by_role("objective"):
        scope = graph.nodes[node_id].get("scope")
        if scope not in known and not str(scope).startswith("custom."):
            errors.append(f"objective {node_id} scope {scope} is not registered")
    return errors


def validate(document: object, study_dir: Path, registry: Path | None = None) -> list[str]:
    """Every check, in the order that produces the most useful first message."""
    errors = structural_errors(document)
    if errors:
        return errors
    graph = Graph(document)
    errors = study_errors(study_dir) or evidence_errors(graph, study_dir)
    if not errors and registry is not None:
        errors = scope_errors(graph, registry)
    return errors


def load(path: Path, study_dir: Path, registry: Path | None = None) -> tuple[object, list[str]]:
    """Read and fully validate one graph, for every CLI."""
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None, [f"graph does not exist: {path}"]
    except (OSError, UnicodeDecodeError) as exc:
        return None, [f"{path} could not be read: {exc}"]
    except json.JSONDecodeError as exc:
        return None, [f"{path} is not valid JSON: {exc}"]
    return document, validate(document, study_dir, registry)
