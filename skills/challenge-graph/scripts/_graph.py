"""Shared loading, validation, and analysis helpers for the challenge graph IR."""

from __future__ import annotations

import itertools
import json
import re
from pathlib import Path

SCHEMA_VERSION = 1
EVIDENCE_KINDS = {"reproduced", "dynamic"}
STATE_ROLES = {"entry", "objective", "intermediate"}
LOCATOR = re.compile(r"^(?P<path>[^#]+)#L(?P<line>[1-9][0-9]*)$")
HEX40 = re.compile(r"^[0-9a-f]{40}$")
MAX_CUT_SIZE = 4


class Graph:
    """Indexed view over a graph document. Structure only; no validation."""

    def __init__(self, document: dict) -> None:
        self.document = document
        self.states = {s["id"]: s for s in document.get("states", []) if _id(s)}
        self.operations = {o["id"]: o for o in document.get("operations", []) if _id(o)}
        self.paths = {p["id"]: p for p in document.get("paths", []) if _id(p)}
        self.observed_cuts = [c for c in document.get("observed_cuts", []) if _id(c)]

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


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


# --- analysis ---------------------------------------------------------------


def minimal_cuts(
    op_sets: list[frozenset[str]], max_size: int = MAX_CUT_SIZE
) -> tuple[list[frozenset[str]], bool]:
    """Minimal hitting sets over the recorded paths' cut-eligible operations.

    Cuts are computed over recorded paths rather than graph reachability, so
    the result stays a statement about what was actually reproduced.
    """
    if not op_sets:
        return [], False
    if any(not s for s in op_sets):
        return [], False
    universe = sorted(set().union(*op_sets))
    found: list[frozenset[str]] = []
    for size in range(1, max_size + 1):
        for combo in itertools.combinations(universe, size):
            candidate = frozenset(combo)
            if any(earlier <= candidate for earlier in found):
                continue
            if all(candidate & op_set for op_set in op_sets):
                found.append(candidate)
    return found, not found


def analyze(graph: Graph) -> dict:
    paths = list(graph.paths)
    objectives = graph.by_role("objective")
    op_sets = {p: graph.cut_eligible(p) for p in paths}

    per_objective: dict[str, dict] = {}
    for objective in objectives:
        members = [p for p in paths if graph.paths[p].get("objective") == objective]
        cuts, truncated = minimal_cuts([op_sets[p] for p in members])
        per_objective[objective] = {
            "scope": graph.states[objective].get("scope"),
            "paths": members,
            "minimal_cuts": [sorted(c) for c in cuts],
            "mincut": min((len(c) for c in cuts), default=None),
            "cuts_truncated": truncated,
        }

    all_cuts, all_truncated = minimal_cuts([op_sets[p] for p in paths])
    mincut_all = min((len(c) for c in all_cuts), default=None)

    nontrivial = {
        p: sum(1 for o in graph.path_operations(p) if graph.counting(o)) >= 2
        for p in paths
    }

    labels: list[str] = []
    if any(not v for v in nontrivial.values()):
        labels.append("shallow")
    for cut in (c for c in all_cuts if len(c) == 1):
        spanned = {graph.paths[p].get("objective") for p in paths if cut & op_sets[p]}
        if len(spanned) >= 2:
            labels.append("fan_out")
            break
    for detail in per_objective.values():
        if len(detail["paths"]) >= 2 and detail["mincut"] == 1:
            labels.append("fan_in")
            break
    if mincut_all is not None and mincut_all >= 2:
        labels.append("disjoint")
    if len(paths) == 1:
        labels.append("single_path")

    return {
        "geometry": sorted(set(labels)),
        "mincut_all": mincut_all,
        "minimal_cuts_all": [sorted(c) for c in all_cuts],
        "cuts_truncated": all_truncated,
        "max_cut_size": MAX_CUT_SIZE,
        "nontrivial_paths": nontrivial,
        "objective_coverage": per_objective,
        "observed_cuts": _observed(graph),
        "frontier": _frontier(graph, per_objective),
    }


def _observed(graph: Graph) -> list[dict]:
    results = []
    for cut in graph.observed_cuts:
        blocked = [e["path"] for e in cut.get("blocked", [])]
        survived = [e["path"] for e in cut.get("survived", [])]
        if not blocked:
            reading = "no_effect"
        elif survived:
            reading = "contestable_observed"
        else:
            reading = "terminal_over_recorded_subgraph"
        implicated = set()
        if blocked:
            implicated = set.intersection(
                *(set(graph.path_operations(p)) for p in blocked)
            )
            for path_id in survived:
                implicated -= set(graph.path_operations(path_id))
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
    if not _text(evidence.get("observed")):
        errors.append(f"{where}.evidence.observed must be a non-empty string")
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
    if not _text(root) or Path(str(root)).is_absolute() or ".." in Path(str(root)).parts:
        errors.append("evidence_root must be a relative path inside the study")

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
    if objective not in graph.states or graph.states.get(objective, {}).get("role") != "objective":
        errors.append(f"path {path_id}.objective must name an objective state")
        objective = None
    operations = path.get("operations")
    if not isinstance(operations, list) or not operations:
        return errors + [f"path {path_id}.operations must be a non-empty list"]
    unknown = [o for o in operations if o not in graph.operations]
    if unknown:
        return errors + [f"path {path_id} has unknown operations: {', '.join(unknown)}"]

    first = graph.operations[operations[0]]
    if not any(graph.states[s].get("role") == "entry" for s in first.get("requires", [])):
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
                if not isinstance(entry, dict) or entry.get("path") not in graph.paths:
                    errors.append(f"cut {cut_id}.{key} has an unknown path")
                    continue
                path_id = entry["path"]
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
