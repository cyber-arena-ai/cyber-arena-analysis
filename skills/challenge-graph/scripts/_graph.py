"""Shared loading, validation, and analysis helpers for the challenge graph IR."""

from __future__ import annotations

import itertools
import json
import math
import re
from pathlib import Path

SCHEMA_VERSION = 1
EVIDENCE_KINDS = {"reproduced", "dynamic"}
STATE_ROLES = {"entry", "objective", "intermediate"}
LOCATOR = re.compile(r"^(?P<path>[^#]+)#L(?P<line>[1-9][0-9]*)$")
HEX40 = re.compile(r"^[0-9a-f]{40}$")
MAX_LISTED_CUTS = 32
MAX_SEARCH_NODES = 200_000
MIN_OBSERVED = 8


class Graph:
    """Indexed view over a graph document. Structure only; no validation."""

    def __init__(self, document: dict) -> None:
        self.document = document
        self.states = {s["id"]: s for s in _entries(document, "states")}
        self.operations = {o["id"]: o for o in _entries(document, "operations")}
        self.paths = {p["id"]: p for p in _entries(document, "paths")}
        self.observed_cuts = _entries(document, "observed_cuts")

    def by_role(self, role: str) -> list[str]:
        return [i for i, s in self.states.items() if s.get("role") == role]

    def path_operations(self, path_id: str) -> list[str]:
        return list(self.paths[path_id].get("operations", []))

    def counting(self, operation_id: str) -> bool:
        return bool(self.operations[operation_id].get("counts_as_operation"))

    def cut_eligible(self, path_id: str) -> frozenset[str]:
        """Operations a defense may target: the ones contestability counts."""
        return frozenset(
            o for o in self.path_operations(path_id) if self.counting(o)
        )


def _id(entry: object) -> bool:
    return isinstance(entry, dict) and isinstance(entry.get("id"), str)


def _entries(document: dict, key: str) -> list[dict]:
    raw = document.get(key)
    return [e for e in raw if _id(e)] if isinstance(raw, list) else []


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


# --- analysis ---------------------------------------------------------------


def minimal_cuts(
    op_sets: list[frozenset[str]], max_listed: int = MAX_LISTED_CUTS
) -> tuple[list[frozenset[str]], int | None, bool]:
    """Minimum-cardinality hitting sets over the recorded paths.

    Cuts are computed over recorded paths rather than graph reachability, so
    the result stays a statement about what was actually reproduced. Only
    minimum-size cuts are returned: they are the cheapest defenses, and
    enumerating every minimal cut is exponential and unreadable.

    Branch and bound on an unhit path rather than searching by subset size:
    a cut always exists at or below the path count, so the depth is bounded
    even when the operation universe is large.
    """
    if not op_sets or any(not op_set for op_set in op_sets):
        return [], None, False
    remaining = _irredundant(op_sets)
    for size in range(1, len(remaining) + 1):
        found: set[frozenset[str]] = set()
        budget = [MAX_SEARCH_NODES]
        _search(remaining, size, frozenset(), found, max_listed, budget)
        if found:
            listed = sorted(found, key=sorted)
            return listed[:max_listed], size, len(listed) > max_listed
        if budget[0] <= 0:
            # The exact search ran out of room. Report a greedy cut so the
            # analysis still says something true: its size is an upper bound.
            greedy = _greedy(remaining)
            return [greedy], len(greedy), True
    return [], None, False


def _greedy(op_sets: list[frozenset[str]]) -> frozenset[str]:
    chosen: set[str] = set()
    unhit = list(op_sets)
    while unhit:
        counts: dict[str, int] = {}
        for op_set in unhit:
            for operation in op_set:
                counts[operation] = counts.get(operation, 0) + 1
        best = max(sorted(counts), key=lambda op: counts[op])
        chosen.add(best)
        unhit = [op_set for op_set in unhit if best not in op_set]
    return frozenset(chosen)


def _irredundant(op_sets: list[frozenset[str]]) -> list[frozenset[str]]:
    """Drop any path whose operations are a superset of another's."""
    unique = sorted(set(op_sets), key=len)
    kept: list[frozenset[str]] = []
    for op_set in unique:
        if not any(earlier <= op_set for earlier in kept):
            kept.append(op_set)
    return kept


def _search(
    op_sets: list[frozenset[str]],
    budget: int,
    chosen: frozenset[str],
    found: set[frozenset[str]],
    max_listed: int,
    nodes: list[int],
) -> None:
    nodes[0] -= 1
    if nodes[0] <= 0:
        return
    unhit = [op_set for op_set in op_sets if not (op_set & chosen)]
    if not unhit:
        found.add(chosen)
        return
    if budget == 0 or len(found) > max_listed:
        return
    # Branching on the smallest unhit path keeps the factor as low as the
    # data allows; every cut must contain one of its operations.
    for operation in sorted(min(unhit, key=len)):
        _search(op_sets, budget - 1, chosen | {operation}, found, max_listed, nodes)



def nontrivial(graph: Graph, path_id: str) -> bool:
    """Two counted operations linked through an intermediate state.

    Contestability anchors nontriviality on a real state dependency, so
    counting operations alone is not enough: one must create or expose
    application state a later one consumes.
    """
    order = graph.path_operations(path_id)
    for index, earlier in enumerate(order):
        if not graph.counting(earlier):
            continue
        produced = set(graph.operations[earlier].get("produces", []))
        for later in order[index + 1 :]:
            if not graph.counting(later):
                continue
            shared = produced & set(graph.operations[later].get("requires", []))
            if any(graph.states.get(s, {}).get("role") == "intermediate" for s in shared):
                return True
    return False


def analyze(graph: Graph) -> dict:
    paths = list(graph.paths)
    objectives = graph.by_role("objective")
    op_sets = {p: graph.cut_eligible(p) for p in paths}
    trivial = [p for p in paths if not nontrivial(graph, p)]

    per_objective: dict[str, dict] = {}
    for objective in objectives:
        members = [p for p in paths if graph.paths[p].get("objective") == objective]
        cuts, size, truncated = minimal_cuts([op_sets[p] for p in members])
        per_objective[objective] = {
            "scope": graph.states[objective].get("scope"),
            "paths": members,
            "minimum_cuts": [sorted(c) for c in cuts],
            "mincut": size,
            "cuts_truncated": truncated,
        }

    all_cuts, mincut_all, all_truncated = minimal_cuts([op_sets[p] for p in paths])
    nontrivial_only = [op_sets[p] for p in paths if p not in trivial]
    _, mincut_nontrivial, _ = minimal_cuts(nontrivial_only)

    labels: list[str] = []
    if trivial:
        # A reproduced one-operation shortcut dominates every other reading:
        # it would otherwise inflate mincut_all and manufacture `disjoint`.
        labels.append("shallow")
    else:
        spans = {
            op: {graph.paths[p].get("objective") for p in paths if op in op_sets[p]}
            for op in set().union(*op_sets.values())
        } if paths else {}
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
        "max_listed_cuts": MAX_LISTED_CUTS,
        "nontrivial_paths": {p: p not in trivial for p in paths},
        "objective_coverage": per_objective,
        "observed_cuts": _observed(graph),
        "frontier": _frontier(graph, per_objective),
    }


def _observed(graph: Graph) -> list[dict]:
    results = []
    for cut in graph.observed_cuts:
        blocked = [e["path"] for e in cut.get("blocked", [])]
        survived = [e["path"] for e in cut.get("survived", [])]
        reading = "contestable_observed" if survived else "terminal_over_recorded_subgraph"
        implicated: set[str] = set()
        if blocked:
            # The extensional root cause: only cut-eligible operations, since
            # an excluded step such as authentication cannot be a defense.
            implicated = set.intersection(*(set(graph.cut_eligible(p)) for p in blocked))
            for path_id in survived:
                implicated -= set(graph.cut_eligible(path_id))
        results.append(
            {
                "id": cut["id"],
                "reference": cut.get("reference"),
                "blocked": blocked,
                "survived": survived,
                "reading": reading,
                "implicated_operations": sorted(implicated),
            }
        )
    return results


def _frontier(graph: Graph, per_objective: dict) -> list[dict]:
    items = []
    for objective, detail in per_objective.items():
        if not detail["paths"]:
            items.append({"kind": "unreached_objective", "target": objective})
    tested = {
        entry["path"]
        for cut in graph.observed_cuts
        for key in ("blocked", "survived")
        for entry in cut.get(key, [])
        if isinstance(entry, dict) and isinstance(entry.get("path"), str)
    }
    for path_id in graph.paths:
        if path_id not in tested:
            items.append({"kind": "untested_path", "target": path_id})
    return items


# --- structural validation --------------------------------------------------


def _text(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def evidence_shape(evidence: object, where: str, errors: list[str]) -> None:
    if not isinstance(evidence, dict):
        errors.append(f"{where}.evidence must be an object")
        return
    kind = evidence.get("kind")
    if kind == "hypothesis":
        errors.append(
            f"{where}.evidence is a hypothesis; only reproduced or dynamic "
            "evidence may enter the graph"
        )
    elif kind not in EVIDENCE_KINDS:
        errors.append(f"{where}.evidence.kind must be reproduced or dynamic")
    observed = evidence.get("observed")
    if not _text(observed) or len(str(observed).strip()) < MIN_OBSERVED:
        errors.append(
            f"{where}.evidence.observed must quote at least {MIN_OBSERVED} characters "
            "of the cited output"
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
    root_parts = Path(str(root)).parts if _text(root) else ()
    if (
        not root_parts
        or Path(str(root)).is_absolute()
        or ".." in root_parts
        or root_parts == (".",)
    ):
        errors.append(
            "evidence_root must name a subdirectory of the study; '.' would let "
            "the study's own prose stand in for reproduced output"
        )

    graph = Graph(document)
    for key, index in (
        ("states", graph.states),
        ("operations", graph.operations),
        ("paths", graph.paths),
    ):
        raw = document.get(key)
        if not isinstance(raw, list) or not raw:
            errors.append(f"{key} must be a non-empty list")
        elif len(index) != len(raw):
            errors.append(f"every {key} entry needs a unique string id")

    for state_id, state in graph.states.items():
        if state.get("role") not in STATE_ROLES:
            errors.append(f"state {state_id} has an unknown role")
        if state.get("role") == "objective":
            for field in ("store", "scope"):
                if not _text(state.get(field)):
                    errors.append(f"objective {state_id} must declare {field}")
    if not graph.by_role("entry"):
        errors.append("graph needs at least one entry state")
    if not graph.by_role("objective"):
        errors.append("graph needs at least one objective state")

    for op_id, operation in graph.operations.items():
        for field in ("requires", "produces"):
            values = operation.get(field)
            if not isinstance(values, list) or not values:
                errors.append(f"operation {op_id}.{field} must be a non-empty list")
                continue
            for state_id in values:
                if state_id not in graph.states:
                    errors.append(f"operation {op_id}.{field} has unknown state {state_id}")
        if not isinstance(operation.get("counts_as_operation"), bool):
            errors.append(f"operation {op_id}.counts_as_operation must be a boolean")
        evidence_shape(operation.get("evidence"), f"operation {op_id}", errors)

    for path_id, path in graph.paths.items():
        errors.extend(_path_errors(graph, path_id, path))
        evidence_shape(path.get("evidence"), f"path {path_id}", errors)

    errors.extend(_cut_errors(graph, document))
    errors.extend(_cycle_errors(graph))
    return errors


def _path_errors(graph: Graph, path_id: str, path: dict) -> list[str]:
    errors: list[str] = []
    objective = path.get("objective")
    if not isinstance(objective, str) or graph.states.get(objective, {}).get("role") != "objective":
        errors.append(f"path {path_id}.objective must name an objective state")
        objective = None
    operations = path.get("operations")
    if not isinstance(operations, list) or not operations:
        return errors + [f"path {path_id}.operations must be a non-empty list"]
    unknown = [o for o in operations if not isinstance(o, str) or o not in graph.operations]
    if unknown:
        listed = ", ".join(str(o) for o in unknown)
        return errors + [f"path {path_id} has unknown operations: {listed}"]

    first = graph.operations[operations[0]]
    requires = first.get("requires")
    if not isinstance(requires, list):
        return errors + [f"path {path_id} starts at an operation with a malformed requires"]
    if not any(graph.states.get(s, {}).get("role") == "entry" for s in requires):
        errors.append(f"path {path_id} must start at an entry state")
    for earlier, later in zip(operations, operations[1:]):
        produced = set(graph.operations[earlier].get("produces", []))
        required = set(graph.operations[later].get("requires", []))
        if not produced & required:
            errors.append(
                f"path {path_id} does not chain: {earlier} produces nothing {later} requires"
            )
    last = graph.operations[operations[-1]]
    if objective and objective not in last.get("produces", []):
        errors.append(f"path {path_id} does not terminate at {objective}")
    if not any(graph.counting(o) for o in operations):
        errors.append(f"path {path_id} needs at least one counted operation")
    return errors


def _cut_errors(graph: Graph, document: dict) -> list[str]:
    errors: list[str] = []
    raw = document.get("observed_cuts", [])
    if not isinstance(raw, list):
        return ["observed_cuts must be a list"]
    if len(graph.observed_cuts) != len(raw):
        errors.append("every observed_cuts entry needs a unique string id")
    for cut in graph.observed_cuts:
        cut_id = cut["id"]
        if not _text(cut.get("reference")):
            errors.append(f"cut {cut_id}.reference must be a non-empty string")
        seen: set[str] = set()
        for key in ("blocked", "survived"):
            entries = cut.get(key, [])
            if not isinstance(entries, list):
                errors.append(f"cut {cut_id}.{key} must be a list")
                continue
            if key == "blocked" and not entries:
                errors.append(f"cut {cut_id}.blocked must record at least one path")
            for entry in entries:
                path_ref = entry.get("path") if isinstance(entry, dict) else None
                if not isinstance(path_ref, str) or path_ref not in graph.paths:
                    errors.append(f"cut {cut_id}.{key} has an unknown path")
                    continue
                path_id = path_ref
                if path_id in seen:
                    errors.append(f"cut {cut_id} lists {path_id} twice")
                seen.add(path_id)
                evidence_shape(
                    {"kind": "reproduced", **entry}, f"cut {cut_id} entry {path_id}", errors
                )
    return errors


def _cycle_errors(graph: Graph) -> list[str]:
    edges: dict[str, list[str]] = {}
    for op_id, operation in graph.operations.items():
        for state_id in operation.get("requires", []):
            edges.setdefault(state_id, []).append(op_id)
        for state_id in operation.get("produces", []):
            edges.setdefault(op_id, []).append(state_id)
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
    missing = [n for n in ("STAGE3_STUDY.md", "result.json") if not (study_dir / n).is_file()]
    if missing:
        return [
            f"{study_dir} is not a Stage 3 study; missing {', '.join(missing)}. "
            "Evidence must resolve against the study that produced it."
        ]
    return []


def _evidence_entries(graph: Graph) -> list[tuple[str, dict]]:
    entries: list[tuple[str, dict]] = []
    for op_id, operation in graph.operations.items():
        entries.append((f"operation {op_id}", operation.get("evidence", {})))
    for path_id, path in graph.paths.items():
        entries.append((f"path {path_id}", path.get("evidence", {})))
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
    root = Path(str(graph.document.get("evidence_root", "")))
    anchor = (study_dir / root).resolve()
    for where, evidence in _evidence_entries(graph):
        match = LOCATOR.match(str(evidence.get("locator", "")))
        if not match:
            continue
        relative = Path(match.group("path"))
        if relative.is_absolute() or ".." in relative.parts:
            errors.append(f"{where} locator must stay inside {root}")
            continue
        resolved = study_dir / relative
        # resolve() first: a symlink inside the evidence tree must not read out of it.
        if not resolved.resolve().is_relative_to(anchor):
            errors.append(f"{where} locator resolves outside {root}")
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


def scope_errors(graph: Graph, registry_path: Path) -> list[str]:
    """Objective scopes must be registered or explicitly challenge-local."""
    registry = json.loads(registry_path.read_text(encoding="utf-8"))
    scopes = registry.get("scopes", registry) if isinstance(registry, dict) else registry
    known = {s.get("id") for s in scopes if isinstance(s, dict)} if isinstance(scopes, list) else set()
    errors = []
    for state_id in graph.by_role("objective"):
        scope = graph.states[state_id].get("scope")
        if scope not in known and not str(scope).startswith("custom."):
            errors.append(f"objective {state_id} scope {scope} is not registered")
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


def read_graph(path: Path) -> tuple[dict | None, list[str]]:
    try:
        return json.loads(path.read_text(encoding="utf-8")), []
    except FileNotFoundError:
        return None, [f"graph does not exist: {path}"]
    except json.JSONDecodeError as exc:
        return None, [f"{path} is not valid JSON: {exc}"]
