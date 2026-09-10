import base64
import http.server
import json
import re
import subprocess
import sys
import threading
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
REGISTRY = (
    Path(__file__).resolve().parents[2]
    / "challenge-create"
    / "references"
    / "attack-scopes.json"
)
REVISION = "a" * 40

def _cite(source, observed, excerpt=None):
    """One observation: the request, what came back, and the part carrying the claim."""
    return {
        "source": source,
        "excerpt": excerpt if excerpt is not None else observed,
        "observed": observed,
    }


def _fn(node_id, title, predecessors, source, observed, **extra):
    return {
        "id": node_id,
        "role": "function",
        "title": title,
        "symbol": f"App.{node_id.removeprefix('N-').replace('-', '_')}",
        "predecessors": predecessors,
        "evidence": _cite(source, observed),
        **extra,
    }


def _graph():
    """Two vertex-disjoint routes to one objective; the upstream cut blocks one."""
    return {
        "schema_version": 2,
        "target": {"id": "acme-reports", "repository": "acme/reports", "revision": REVISION},
        "nodes": [
            {"id": "N-entry", "role": "entry", "title": "Baseline principal"},
            _fn("N-create-share", "create share link", ["N-entry"],
                "vulnerable build · GET /pov · 200 #L1", "201 Created share",
                symbol="ShareController.create"),
            _fn("N-resolve-share", "resolve share link", ["N-create-share"],
                "vulnerable build · GET /pov · 200 #L2", "recovered victim",
                symbol="ShareController.resolve"),
            _fn("N-upload-template", "upload template", ["N-entry"],
                "vulnerable build · GET /alt · 200 #L1", "201 Created template",
                symbol="TemplateController.create"),
            _fn("N-render-template", "render template", ["N-upload-template"],
                "vulnerable build · GET /alt · 200 #L2", "recovered victim",
                symbol="ExportRenderer.render"),
            {
                "id": "N-obj",
                "role": "objective",
                "store": "report_store",
                "scope": "app.cross_boundary.read",
                "predecessors": ["N-resolve-share", "N-render-template"],
            },
        ],
        "paths": [
            {
                "id": "PATH-pov",
                "objective": "N-obj",
                "nodes": ["N-entry", "N-create-share", "N-resolve-share", "N-obj"],
                "advisories": ["CVE-2026-0001"],
                "witnesses": [_cite("vulnerable build · GET /pov · 200 #L2", "recovered victim report")],
            },
            {
                "id": "PATH-alt",
                "objective": "N-obj",
                "nodes": ["N-entry", "N-upload-template", "N-render-template", "N-obj"],
                "advisories": [],
                "witnesses": [_cite("vulnerable build · GET /alt · 200 #L2", "recovered victim report")],
            },
        ],
    }


def _node(graph, node_id):
    return next(n for n in graph["nodes"] if n["id"] == node_id)


def _path(graph, path_id):
    return next(p for p in graph["paths"] if p["id"] == path_id)


def _write(tmp_path, graph):
    path = tmp_path / "graph.json"
    path.write_text(json.dumps(graph, indent=2) + "\n", encoding="utf-8")
    return path


def _run(script, tmp_path, graph, *extra):
    return subprocess.run(
        [sys.executable, str(SCRIPTS / script), str(_write(tmp_path, graph)),
         "--scope-registry", str(REGISTRY), *extra],
        capture_output=True,
        text=True,
    )


def _validate(tmp_path, graph):
    return _run("graph_validate.py", tmp_path, graph)


def _analyze(tmp_path, graph):
    out = tmp_path / "derived" / "analysis.json"
    result = _run("graph_analyze.py", tmp_path, graph, "--out", str(out))
    assert result.returncode == 0, result.stderr
    return json.loads(out.read_text(encoding="utf-8"))


def _render(tmp_path, graph):
    """graph.md as a reader meets it. `graph_finalize.py` writes it; this calls
    the same two functions rather than standing up a whole deliverable."""
    sys.path.insert(0, str(SCRIPTS))
    try:
        from _graph import Graph, analyze
        from graph_render import report
    finally:
        sys.path.pop(0)
    assert _validate(tmp_path, graph).returncode == 0
    return report(Graph(graph), analyze(Graph(graph)))


def _fails(tmp_path, mutate, needle):
    graph = _graph()
    mutate(graph)
    result = _validate(tmp_path, graph)
    assert result.returncode == 1, f"expected rejection, got: {result.stdout}"
    assert needle in result.stderr, f"expected {needle!r} in: {result.stderr}"
    return result


# --- the advisory's own fix -------------------------------------------------


def _cut(graph, refused=("PATH-pov",), survived=("PATH-alt",), nodes=("N-resolve-share",)):
    graph["advisory_cut"] = {
        "advisory": "CVE-2026-0001",
        "nodes": list(nodes),
        "refused": [_cite("fixed build · GET /s/7f2a · 403", "403 Forbidden owner_check")
                    | {"path": p, "tried": "token guess, direct id, and the study's payload"}
                    for p in refused],
        "survived": [_cite("fixed build · GET /reports/9/export · 200",
                           "recovered victim report") | {"path": p} for p in survived],
    }
    return graph


def test_the_advisory_fix_records_the_cut_it_accepted_and_what_it_left_open(tmp_path):
    """The one cut whose admissibility is known, and what it actually achieved."""
    body = _render(tmp_path, _cut(_graph()))
    assert "| advisory | CVE-2026-0001 |" in body
    assert "| nodes it guarded | N-resolve-share |" in body
    assert "| routes that refused every request tried | PATH-pov |" in body
    assert "| routes it left open | PATH-alt |" in body


def test_an_accepted_cut_cannot_name_a_terminal(tmp_path):
    """Upstream did not ship a fix that removed the login or the asset."""
    _fails(tmp_path, lambda g: _cut(g, nodes=("N-entry",)),
           "advisory_cut.nodes names N-entry, a entry")


def test_one_route_cannot_be_both_refused_and_open(tmp_path):
    """It would read as a defense that worked, next to the proof it did not."""
    _fails(tmp_path, lambda g: _cut(g, refused=("PATH-pov",), survived=("PATH-pov",)),
           "records PATH-pov on both sides")


def test_the_renamed_side_is_rejected_rather_than_dropped(tmp_path):
    """The worked example kept `blocked` through the rename and still validated,
    so the routes it recorded vanished from the render and the merge."""
    def rename(g):
        _cut(g)
        g["advisory_cut"]["blocked"] = g["advisory_cut"].pop("refused")
    _fails(tmp_path, rename, "advisory_cut.blocked is now refused")


def test_a_refusal_must_say_what_it_tried(tmp_path):
    """A run recorded three routes closed on one payload family; a fourth opened
    them. No count of refusals is severance, so the record says what it sent."""
    def drop(g):
        _cut(g)
        del g["advisory_cut"]["refused"][0]["tried"]
    _fails(tmp_path, drop, "must say what was tried")


# --- the fixture itself -----------------------------------------------------


def test_two_disjoint_routes_read_as_disjoint(tmp_path):
    analysis = _analyze(tmp_path, _graph())
    assert analysis["geometry"] == ["disjoint"]
    assert analysis["mincut_all"] == 2


# --- schema 2 migration -----------------------------------------------------


def test_a_schema_1_document_is_rejected_by_version_not_by_accident(tmp_path):
    """The rejection must name the version, so a v1 graph is not read as malformed."""
    graph = _graph()
    graph["schema_version"] = 1
    result = _validate(tmp_path, graph)
    assert result.returncode == 1
    assert "schema-version 2" in result.stderr


def test_a_v1_shaped_document_names_the_structural_change(tmp_path):
    def mutate(graph):
        graph["states"] = graph.pop("nodes")
    _fails(tmp_path, mutate, "'states' is schema 1")


def test_the_removed_evidence_fields_are_rejected_rather_than_ignored(tmp_path):
    """Silently accepting one would let a graph carry a dependency it cannot check."""
    for gone in ("kind", "locator"):
        _fails(
            tmp_path,
            lambda g, gone=gone: _node(g, "N-create-share")["evidence"].__setitem__(gone, "x"),
            f"evidence.{gone} was removed",
        )


# --- a route walks its predecessors -----------------------------------------


def test_a_route_must_reach_each_node_through_a_predecessor(tmp_path):
    def mutate(graph):
        _path(graph, "PATH-pov")["nodes"] = ["N-entry", "N-resolve-share", "N-obj"]
    _fails(tmp_path, mutate, "before any of its predecessors")


# --- AND / OR ---------------------------------------------------------------


def test_a_conjunctive_node_demands_every_predecessor_on_the_route(tmp_path):
    def mutate(graph):
        node = _node(graph, "N-resolve-share")
        node["predecessors"] = ["N-create-share", "N-upload-template"]
        node["conjunctive"] = True
    _fails(tmp_path, mutate, "without N-upload-template")


def _shared_serializer(graph):
    """Both routes pass through one function, as Airflow's two reads do."""
    graph["nodes"].append(
        _fn("N-serialize", "shared response serializer",
            ["N-resolve-share", "N-render-template"],
            "vulnerable build · GET /pov · 200 #L2", "recovered victim")
    )
    _node(graph, "N-obj")["predecessors"] = ["N-serialize"]
    for path_id in ("PATH-pov", "PATH-alt"):
        path = _path(graph, path_id)
        path["nodes"] = path["nodes"][:-1] + ["N-serialize", "N-obj"]
    return graph


def test_a_shared_node_reached_by_either_branch_reads_as_fan_in(tmp_path):
    """The Airflow shape: two routes, one shared function, so one fix covers both."""
    analysis = _analyze(tmp_path, _shared_serializer(_graph()))
    assert analysis["geometry"] == ["fan_in"]
    assert analysis["mincut_all"] == 1


# --- terminals are never cut ------------------------------------------------


# --- geometry ---------------------------------------------------------------


def _shortcut(graph):
    graph["nodes"].append(
        _fn("N-direct", "one-hop shortcut", ["N-entry"], "vulnerable build · GET /pov · 200 #L2", "recovered victim")
    )
    _node(graph, "N-obj")["predecessors"].append("N-direct")
    graph["paths"].append(
        {
            "id": "PATH-short",
            "objective": "N-obj",
            "nodes": ["N-entry", "N-direct", "N-obj"],
            "advisories": [],
            "witnesses": [_cite("vulnerable build · GET /pov · 200 #L2", "recovered victim report")],
        }
    )


def test_a_one_node_route_is_recorded_like_any_other(tmp_path):
    """A one-function route is still a route: it raises the min-cut and takes
    whatever label the shape earns, rather than blanking the reading."""
    graph = _graph()
    _shortcut(graph)
    analysis = _analyze(tmp_path, graph)
    assert analysis["mincut_all"] == 3
    assert "disjoint" in analysis["geometry"]


def test_one_node_reaching_two_objectives_reads_as_fan_out(tmp_path):
    graph = _graph()
    graph["nodes"].append(
        {
            "id": "N-obj2",
            "role": "objective",
            "store": "second_store",
            "scope": "app.cross_boundary.write",
            "predecessors": ["N-resolve-share"],
        }
    )
    graph["paths"].append(
        {
            "id": "PATH-second",
            "objective": "N-obj2",
            "nodes": ["N-entry", "N-create-share", "N-resolve-share", "N-obj2"],
            "advisories": [],
            "witnesses": [_cite("vulnerable build · GET /pov · 200 #L2", "recovered victim report")],
        }
    )
    assert "fan_out" in _analyze(tmp_path, graph)["geometry"]


# --- witnesses and advisories -----------------------------------------------


def test_a_route_needs_at_least_one_witness(tmp_path):
    def mutate(graph):
        _path(graph, "PATH-pov")["witnesses"] = []
    _fails(tmp_path, mutate, "must record at least one observation")


def test_advisories_record_every_cve_in_a_chained_route(tmp_path):
    graph = _graph()
    _path(graph, "PATH-pov")["advisories"] = ["CVE-2026-0001", "CVE-2026-0002"]
    assert _validate(tmp_path, graph).returncode == 0
    assert "CVE-2026-0002" in _render(tmp_path, graph)


# --- citations --------------------------------------------------------------


def test_observed_must_appear_in_the_excerpt_it_was_taken_from(tmp_path):
    """The one check left once nothing is resolved: the quote is in the text."""
    def mutate(graph):
        _node(graph, "N-create-share")["evidence"]["observed"] = "never appeared anywhere"
    _fails(tmp_path, mutate, "does not appear in the excerpt")


def test_observed_must_quote_enough_to_identify_the_line(tmp_path):
    def mutate(graph):
        _node(graph, "N-create-share")["evidence"]["observed"] = "201"
    _fails(tmp_path, mutate, "at least 8 characters")


# --- structure --------------------------------------------------------------


def test_cycles_are_rejected(tmp_path):
    def mutate(graph):
        _node(graph, "N-entry")["role"] = "function"
        _node(graph, "N-entry")["predecessors"] = ["N-resolve-share"]
        _node(graph, "N-entry")["evidence"] = _cite("vulnerable build · GET /pov · 200 #L1", "201 Created share")
    _fails(tmp_path, mutate, "acyclic")


def test_duplicate_node_ids_are_rejected(tmp_path):
    def mutate(graph):
        graph["nodes"].append(dict(_node(graph, "N-create-share")))
    _fails(tmp_path, mutate, "unique string id")


def test_an_objective_must_declare_its_scope(tmp_path):
    def mutate(graph):
        _node(graph, "N-obj").pop("scope")
    _fails(tmp_path, mutate, "must declare scope")


def test_an_entry_may_not_require_another_node(tmp_path):
    def mutate(graph):
        _node(graph, "N-entry")["predecessors"] = ["N-create-share"]
    _fails(tmp_path, mutate, "must not require another node")


def test_a_route_must_end_at_its_objective(tmp_path):
    def mutate(graph):
        _path(graph, "PATH-pov")["nodes"] = ["N-entry", "N-create-share", "N-resolve-share"]
    _fails(tmp_path, mutate, "must end at N-obj")


def test_an_unregistered_objective_scope_is_rejected(tmp_path):
    graph = _graph()
    _node(graph, "N-obj")["scope"] = "not.a.real.scope"
    result = _run("graph_validate.py", tmp_path, graph)
    assert result.returncode == 1
    assert "not registered" in result.stderr


def test_a_challenge_local_scope_is_accepted(tmp_path):
    graph = _graph()
    _node(graph, "N-obj")["scope"] = "custom.acme-reports.share_read"
    result = _run("graph_validate.py", tmp_path, graph)
    assert result.returncode == 0, result.stderr


# --- malformed input produces a message, never a traceback ------------------


def test_an_unknown_node_id_reports_an_error_rather_than_crashing(tmp_path):
    result = _fails(tmp_path, lambda g: _path(g, "PATH-pov")["nodes"].insert(1, "N-nope"),
                    "unknown nodes")
    assert "Traceback" not in result.stderr


def test_an_unhashable_role_reports_an_error_rather_than_crashing(tmp_path):
    result = _fails(tmp_path, lambda g: _node(g, "N-create-share").update({"role": {}}),
                    "unknown role")
    assert "Traceback" not in result.stderr


def test_a_non_boolean_conjunctive_reports_an_error(tmp_path):
    _fails(tmp_path, lambda g: _node(g, "N-create-share").update({"conjunctive": "yes"}),
           "must be a boolean")


def test_a_function_must_name_what_it_is(tmp_path):
    """`symbol` is what says two nodes are one node, so a function needs one."""
    _fails(tmp_path, lambda g: _node(g, "N-create-share").pop("symbol"),
           "function N-create-share must declare symbol")


def test_an_unusable_symbol_is_reported_rather_than_ignored(tmp_path):
    """Shape is checked for every role, including an entry, which skips the rest
    of the node rules. Without it a malformed symbol falls past the uniqueness
    branch — which is gated on the value being text — and is silently dropped."""
    _fails(tmp_path, lambda g: _node(g, "N-entry").update({"symbol": {"a": 1}}),
           "node N-entry.symbol must be a non-empty string")


def test_two_nodes_may_not_name_one_application_function(tmp_path):
    """One function under two ids reads as two routes sharing nothing, which
    halves the min-cut and manufactures a `disjoint` reading."""
    _fails(tmp_path, lambda g: _node(g, "N-upload-template").update(
        {"symbol": _node(g, "N-create-share")["symbol"]}),
        "nodes N-create-share and N-upload-template share symbol")


def test_an_unusable_scope_registry_reports_an_error_rather_than_crashing(tmp_path):
    """Each of these produced a traceback: the statement that raises them sat
    outside the try that named them."""
    shapes = {
        "absent.json": None,
        "list.json": b"[]",
        "nokey.json": b'{"not_scopes": 1}',
        "binary.json": b"\xff\xfe\x00",
    }
    for name, body in shapes.items():
        registry = tmp_path / name
        if body is not None:
            registry.write_bytes(body)
        result = _run("graph_validate.py", tmp_path, _graph(), "--scope-registry", str(registry))
        assert result.returncode == 1, name
        assert "scope registry could not be read" in result.stderr, name
        assert "Traceback" not in result.stderr, name


def test_malformed_json_reports_an_error_rather_than_crashing(tmp_path):
    path = tmp_path / "graph.json"
    path.write_text("{not json", encoding="utf-8")
    result = subprocess.run(
        [sys.executable, str(SCRIPTS / "graph_validate.py"), str(path),
         "--scope-registry", str(REGISTRY)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1
    assert "not valid JSON" in result.stderr
    assert "Traceback" not in result.stderr


# --- rendering --------------------------------------------------------------


def test_the_report_names_each_node_s_code_symbol(tmp_path):
    assert "ShareController.create" in _render(tmp_path, _graph())


def test_the_report_says_it_does_not_judge_admissibility(tmp_path):
    """Both claims travel with graph.md, so they are part of the deliverable."""
    body = _render(tmp_path, _graph())
    assert "never which ones are allowed to be touched" in body
    assert "unchecked author claim" in body


# --- cut search -------------------------------------------------------------


def test_a_wide_disjoint_graph_still_reports_its_mincut(tmp_path):
    graph = _graph()
    graph["paths"] = []
    _node(graph, "N-obj")["predecessors"] = []
    for index in range(6):
        first, second = f"N-a{index}", f"N-b{index}"
        graph["nodes"].append(
            _fn(first, f"step a{index}", ["N-entry"], "vulnerable build · GET /pov · 200 #L1", "201 Created share")
        )
        graph["nodes"].append(
            _fn(second, f"step b{index}", [first], "vulnerable build · GET /pov · 200 #L2", "recovered victim")
        )
        _node(graph, "N-obj")["predecessors"].append(second)
        graph["paths"].append(
            {
                "id": f"PATH-{index}",
                "objective": "N-obj",
                "nodes": ["N-entry", first, second, "N-obj"],
                "advisories": [],
                "witnesses": [_cite("vulnerable build · GET /pov · 200 #L2", "recovered victim report")],
            }
        )
    assert _analyze(tmp_path, graph)["mincut_all"] == 6


def test_an_exhausted_cut_search_reports_unknown_rather_than_guessing():
    sys.path.insert(0, str(SCRIPTS))
    try:
        from _graph import minimal_cuts
    finally:
        sys.path.pop(0)
    wide = [frozenset({f"n{group}_{index}" for index in range(40)}) for group in range(14)]
    assert minimal_cuts(wide) is None


# --- the worked example -----------------------------------------------------


def test_the_worked_example_is_structurally_valid():
    sys.path.insert(0, str(SCRIPTS))
    try:
        from _graph import structural_errors
    finally:
        sys.path.pop(0)
    example = json.loads(
        (SCRIPTS.parent / "references" / "example-graph.json").read_text(encoding="utf-8")
    )
    assert structural_errors(example) == []


# --- droppability: the rule that replaced exactly-one ------------------------


def _nested_or(graph):
    """A parser reachable from the session directly, or after a stored upload."""
    graph["nodes"].insert(2, _fn("N-upload", "store an upload", ["N-create-share"],
                                 "vulnerable build · GET /pov · 200 #L1", "201 Created share"))
    _node(graph, "N-resolve-share")["predecessors"] = ["N-upload", "N-create-share"]
    _path(graph, "PATH-pov")["nodes"] = [
        "N-entry", "N-create-share", "N-upload", "N-resolve-share", "N-obj"
    ]
    return graph


def test_a_route_carrying_a_node_it_could_skip_names_that_node(tmp_path):
    """If the parser is reachable without the upload, then cutting the upload
    stops nothing, and listing it would put a false defense in the cut list."""
    result = _validate(tmp_path, _nested_or(_graph()))
    assert result.returncode == 1
    assert "still reaches N-obj without N-upload" in result.stderr
    assert "record the shorter route" in result.stderr


def test_the_same_route_validates_once_the_dependency_is_declared_honestly(tmp_path):
    """Declaring that the parser really needs the upload makes the route real.
    The rule forces `predecessors` to describe the application, not the transcript."""
    graph = _nested_or(_graph())
    _node(graph, "N-resolve-share")["predecessors"] = ["N-upload"]
    assert _validate(tmp_path, graph).returncode == 0
    assert _analyze(tmp_path, graph)["mincut_all"] == 2


def test_a_conjunction_route_is_not_forced_into_adjacency(tmp_path):
    """Both conjuncts of a conjunctive node are parallel branches. Demanding
    they sit next to each other would invent an edge the application lacks."""
    graph = _graph()
    _node(graph, "N-resolve-share")["predecessors"] = ["N-create-share", "N-upload-template"]
    _node(graph, "N-resolve-share")["conjunctive"] = True
    _node(graph, "N-obj")["predecessors"] = ["N-resolve-share"]
    graph["paths"] = [
        {
            "id": "PATH-pov",
            "objective": "N-obj",
            "nodes": ["N-entry", "N-create-share", "N-upload-template",
                      "N-resolve-share", "N-obj"],
            "advisories": [],
            "witnesses": [_cite("vulnerable build · GET /pov · 200 #L2", "recovered victim report")],
        }
    ]
    assert _validate(tmp_path, graph).returncode == 0
    assert _analyze(tmp_path, graph)["mincut_all"] == 1, "either conjunct alone cuts it"


# --- the guard against an unsound-small cut ---------------------------------


def test_an_interior_node_must_be_a_function(tmp_path):
    """A mid-route node relabelled `entry` would vanish from every cut, which is
    the one way left to understate a min-cut."""
    def mutate(graph):
        _node(graph, "N-create-share")["role"] = "entry"
        _node(graph, "N-create-share").pop("predecessors")
    _fails(tmp_path, mutate, "interior node N-create-share must be a function")


def test_a_route_must_start_at_an_entry_node(tmp_path):
    def mutate(graph):
        _path(graph, "PATH-pov")["nodes"] = ["N-create-share", "N-resolve-share", "N-obj"]
    _fails(tmp_path, mutate, "must start at an entry node")


# --- read failures ----------------------------------------------------------


def test_a_json_null_document_is_rejected_rather_than_passing(tmp_path):
    """`null` is a document, not a read failure. Conflating them let it skip
    validation entirely and report success."""
    path = tmp_path / "graph.json"
    path.write_text("null", encoding="utf-8")
    result = subprocess.run(
        [sys.executable, str(SCRIPTS / "graph_validate.py"), str(path),
         "--scope-registry", str(REGISTRY)],
        capture_output=True, text=True,
    )
    assert result.returncode == 1, f"null validated clean: {result.stdout}"
    assert "Traceback" not in result.stderr


# --- multi-role merge -------------------------------------------------------


def _seed():
    """What SEED authors: the terminals plus the advisory-backed route."""
    graph = _graph()
    keep = {"N-entry", "N-create-share", "N-resolve-share", "N-obj"}
    graph["nodes"] = [n for n in graph["nodes"] if n["id"] in keep]
    _node(graph, "N-obj")["predecessors"] = ["N-resolve-share"]
    graph["paths"] = [_path(graph, "PATH-pov")]
    return graph


def _expand():
    """What EXPAND appends: a further route to the objective SEED already declared."""
    graph = _graph()
    keep = {"N-entry", "N-upload-template", "N-render-template", "N-obj"}
    graph["nodes"] = [n for n in graph["nodes"] if n["id"] in keep]
    _node(graph, "N-obj")["predecessors"] = ["N-render-template"]
    graph["paths"] = [_path(graph, "PATH-alt")]
    return graph


def _merge(tmp_path, seed, expand, *extra):
    seed_path = tmp_path / "seed.json"
    seed_path.write_text(json.dumps(seed, indent=2) + "\n", encoding="utf-8")
    expand_path = tmp_path / "expand.json"
    expand_path.write_text(json.dumps(expand, indent=2) + "\n", encoding="utf-8")
    selector = ["--expand", str(expand_path)]
    out = tmp_path / "merged" / "graph.json"
    record = tmp_path / "merged" / "merge.json"
    result = subprocess.run(
        [sys.executable, str(SCRIPTS / "graph_merge.py"), str(seed_path), *selector,
         "--out", str(out), "--record", str(record),
         "--scope-registry", str(REGISTRY), *extra],
        capture_output=True,
        text=True,
    )
    return result, out, record


def test_merge_reunites_the_fragments_into_the_disjoint_reading(tmp_path):
    """Fragment-local ids may collide; the merged graph assigns its own sequence."""
    seed = _cut(_seed(), refused=("PATH-pov",), survived=())
    expand = _expand()
    _path(expand, "PATH-alt")["id"] = "PATH-pov"
    _cut(expand, refused=(), survived=("PATH-pov",), nodes=("N-render-template",))
    result, out, record = _merge(tmp_path, seed, expand)
    assert result.returncode == 0, result.stderr

    merged = json.loads(out.read_text(encoding="utf-8"))
    assert _node(merged, "N-obj")["predecessors"] == ["N-resolve-share", "N-render-template"]
    assert [p["id"] for p in merged["paths"]] == ["PATH-1", "PATH-2"]
    assert [entry["path"] for entry in merged["advisory_cut"]["refused"]] == ["PATH-1"]
    assert [entry["path"] for entry in merged["advisory_cut"]["survived"]] == ["PATH-2"]

    analysis = _analyze(tmp_path, merged)
    assert analysis["geometry"] == ["disjoint"]
    assert analysis["mincut_all"] == 2

    written = json.loads(record.read_text(encoding="utf-8"))
    assert written["routes"] == {"PATH-1": "seed", "PATH-2": "expand"}
    assert written["routes_added"] == ["PATH-2"]
    assert sorted(written["nodes_added"]) == ["N-render-template", "N-upload-template"]
    assert written["predecessors_widened"] == ["N-obj"]


def test_expand_may_declare_an_objective_it_reached(tmp_path):
    """A run reached an administrative token the registry already names, and the
    old rule discarded it: at Stage 3 nothing declares the objective, so both
    roles reconstruct it and neither has the better claim."""
    expand = _expand()
    _node(expand, "N-obj")["id"] = "N-obj-new"
    _node(expand, "N-obj-new")["scope"] = "app.privileged.control"
    _path(expand, "PATH-alt")["objective"] = "N-obj-new"
    _path(expand, "PATH-alt")["nodes"][-1] = "N-obj-new"
    result, out, _ = _merge(tmp_path, _seed(), expand)
    assert result.returncode == 0, result.stderr
    merged = json.loads(out.read_text(encoding="utf-8"))
    assert {n["id"] for n in merged["nodes"] if n["role"] == "objective"} == {"N-obj", "N-obj-new"}


def test_expand_may_not_declare_an_entry(tmp_path):
    """A node declared `entry` leaves every cut, so a second one lowers them all."""
    expand = _expand()
    _node(expand, "N-entry")["id"] = "N-entry-2"
    for node in expand["nodes"]:
        node["predecessors"] = ["N-entry-2" if p == "N-entry" else p
                                for p in node.get("predecessors") or []]
    _path(expand, "PATH-alt")["nodes"][0] = "N-entry-2"
    result, _, _ = _merge(tmp_path, _seed(), expand)
    assert result.returncode == 1
    assert "EXPAND introduced entry node N-entry-2" in result.stderr


def test_merge_will_not_widen_a_conjunction(tmp_path):
    """conjunctive over a union would silently demand the new predecessor too."""
    seed, expand = _seed(), _expand()
    for graph, extra in ((seed, "N-create-share"), (expand, "N-upload-template")):
        node = _node(graph, "N-obj")
        node["predecessors"] = [node["predecessors"][0], extra]
        node["conjunctive"] = True
    result, _, _ = _merge(tmp_path, seed, expand)
    assert result.returncode == 1
    assert "sets conjunctive" in result.stderr


def test_merge_validates_each_fragment_and_names_which_one(tmp_path):
    expand = _expand()
    _node(expand, "N-render-template")["evidence"]["observed"] = "never written anywhere"
    result, _, _ = _merge(tmp_path, _seed(), expand)
    assert result.returncode == 1
    assert result.stderr.startswith("EXPAND ")


def test_merge_rejects_fragments_over_different_revisions(tmp_path):
    expand = _expand()
    expand["target"]["revision"] = "b" * 40
    result, _, _ = _merge(tmp_path, _seed(), expand)
    assert result.returncode == 1
    assert "fragments disagree on target" in result.stderr


def test_merge_revalidates_what_the_union_produced(tmp_path):
    """Two fragments that each validate can still merge into an invalid graph: the
    `predecessors` union can open a shortcut that makes an EXPAND route droppable."""
    expand = _seed()
    expand["nodes"].append(
        _fn("N-exfil", "bulk export", ["N-resolve-share"],
            "vulnerable build · GET /alt · 200 #L2", "recovered victim", symbol="ExportController.bulk")
    )
    _node(expand, "N-obj")["predecessors"] = ["N-exfil"]
    path = _path(expand, "PATH-pov")
    path["id"] = "PATH-alt"
    path["nodes"].insert(-1, "N-exfil")
    result, out, _ = _merge(tmp_path, _seed(), expand)
    assert result.returncode == 1
    assert "merged: route PATH-2 still reaches N-obj without" in result.stderr
    assert not out.exists(), "an invalid merge must not be written"


def test_merge_rejects_a_node_the_fragments_identify_differently(tmp_path):
    """A scope disagreement is a disagreement about what asset class was reached."""
    disagreements = [
        ("N-obj", "store", "some_other_store"),
        ("N-obj", "scope", "secret.credential.read"),
        ("N-obj", "conjunctive", True),
        ("N-entry", "symbol", "Some.other.symbol"),
    ]
    for node_id, field, value in disagreements:
        expand = _expand()
        _node(expand, node_id)[field] = value
        result, _, _ = _merge(tmp_path, _seed(), expand)
        assert result.returncode == 1, f"{field} merged silently"
        assert f"fragments disagree on node {node_id}: {field}" in result.stderr


def test_seeds_declaration_wins_where_the_fragments_may_differ(tmp_path):
    """EXPAND redeclares shared nodes to validate standalone, and legitimately
    cites its own evidence line for a node it reaches another way."""
    expand = _expand()
    _node(expand, "N-entry")["title"] = "Baseline principal, reached the other way"
    result, out, _ = _merge(tmp_path, _seed(), expand)
    assert result.returncode == 0, result.stderr
    assert _node(json.loads(out.read_text()), "N-entry")["title"] == "Baseline principal"


def test_an_explicit_conjunctive_false_is_not_a_disagreement(tmp_path):
    """Writing the default out is semantically identical to omitting it."""
    expand = _expand()
    _node(expand, "N-obj")["conjunctive"] = False
    result, _, _ = _merge(tmp_path, _seed(), expand)
    assert result.returncode == 0, result.stderr


def test_a_symbol_cannot_break_the_rendered_table(tmp_path):
    """`symbol` became mandatory on every function node, so it is the cell most
    likely to carry a pipe: unescaped it adds a phantom column."""
    graph = _graph()
    _node(graph, "N-create-share")["symbol"] = 'Router.match GET /a|/b "x"'
    body = _render(tmp_path, graph)

    rows = [line for line in body.splitlines() if line.startswith("| N-create-share |")]
    assert len(rows) == 1
    assert rows[0].count("|") == 5, rows[0]


def test_the_record_names_which_fragment_was_which(tmp_path):
    """Every other field is relative to whichever fragment was passed first, so
    reading the record at all depends on these two."""
    _, _, record = _merge(tmp_path, _seed(), _expand())
    written = json.loads(record.read_text())
    assert written["seed"].endswith("seed.json")
    assert written["expand"].endswith("expand.json")


def test_a_route_may_not_list_one_node_twice(tmp_path):
    """Every computed set ignores the repeat, so it only inflates the node count
    the renderer prints for that route."""
    def mutate(graph):
        _path(graph, "PATH-pov")["nodes"].insert(-1, "N-create-share")
    _fails(tmp_path, mutate, "route PATH-pov lists N-create-share more than once")


# --- declared inputs: incomplete is rejected, never silently degraded --------


def test_a_missing_scope_registry_is_refused_rather_than_skipping_the_check(tmp_path):
    """It used to be optional, so omitting it left every objective scope unchecked."""
    graph = _graph()
    _node(graph, "N-obj")["scope"] = "app.not_a_registered_scope"
    result = subprocess.run(
        [sys.executable, str(SCRIPTS / "graph_validate.py"), str(_write(tmp_path, graph))],
        capture_output=True, text=True,
    )
    assert result.returncode == 2, result.stderr
    assert "--scope-registry" in result.stderr, result.stderr


def test_expand_finding_nothing_is_a_fragment_carrying_no_route(tmp_path):
    """Finding nothing is a real outcome, so it has to be writable as a fragment."""
    expand = _expand()
    expand["paths"] = []
    result, out, record = _merge(tmp_path, _seed(), expand)
    assert result.returncode == 0, result.stderr

    merged = json.loads(out.read_text(encoding="utf-8"))
    assert [p["id"] for p in merged["paths"]] == ["PATH-1"]
    written = json.loads(record.read_text(encoding="utf-8"))
    assert written["routes_added"] == [] and written["nodes_added"] == []


def test_a_role_that_never_ran_cannot_be_asserted_away(tmp_path):
    """The fragment existing is what says EXPAND ran; no flag can say it instead."""
    seed = tmp_path / "seed.json"
    seed.write_text(json.dumps(_seed(), indent=2) + "\n", encoding="utf-8")
    result = subprocess.run(
        [sys.executable, str(SCRIPTS / "graph_merge.py"), str(seed),
         "--out", str(tmp_path / "g.json"), "--record", str(tmp_path / "r.json"),
         "--scope-registry", str(REGISTRY)],
        capture_output=True, text=True,
    )
    assert result.returncode == 2
    assert "--expand" in result.stderr, result.stderr


# --- the deliverable checks itself; nothing downstream will -------------------


def _merge_record(graph, **override):
    record = {
        "routes": {p["id"]: "seed" for p in graph["paths"]},
    }
    record.update(override)
    return record


def _provenance(graph, **override):
    record = {
        "fault": {"statement": "the share resolver skips the owner check"},
        "unsettled": [], "notes": [],
    }
    record.update(override)
    return record


def _finalize(tmp_path, graph, record, drop=(), derive=False, merged=None):
    """`derive` runs the real analyze/render; finalize only stats those two, so
    every test but one stubs them rather than spawning two more interpreters."""
    out = tmp_path / "deliverable"
    out.mkdir(exist_ok=True)
    (out / "graph.json").write_text(json.dumps(graph, indent=2) + "\n", encoding="utf-8")
    if derive:
        assert subprocess.run(
            [sys.executable, str(SCRIPTS / "graph_analyze.py"), str(out / "graph.json"),
             "--out", str(out / "analysis.json"),
             "--scope-registry", str(REGISTRY)], capture_output=True, text=True
        ).returncode == 0
    else:
        (out / "analysis.json").write_text("stub\n", encoding="utf-8")
    (out / "provenance.json").write_text(json.dumps(record, indent=2), encoding="utf-8")
    merge_path = tmp_path / "merge.json"
    if merged is None:
        merged = _merge_record(graph)
    merge_path.write_text(json.dumps(merged, indent=2), encoding="utf-8")
    for name in drop:
        (out / name).unlink()
    return subprocess.run(
        [sys.executable, str(SCRIPTS / "graph_finalize.py"), str(out),
         "--merge-record", str(merge_path),
         "--scope-registry", str(REGISTRY)],
        capture_output=True, text=True,
    ), out


def test_a_complete_deliverable_renders_its_findings(tmp_path):
    """findings.md is derived, so it cannot drift from the record it reports."""
    graph = _graph()
    result, out = _finalize(tmp_path, graph, _provenance(graph), derive=True)
    assert result.returncode == 0, result.stderr

    rendered = (out / "findings.md").read_text(encoding="utf-8")
    assert "the share resolver skips the owner check" in rendered
    assert "`PATH-pov` — seed" in rendered


def test_a_partial_tree_is_refused_rather_than_read_as_finished(tmp_path):
    """The one boundary with no downstream consumer to reject it."""
    graph = _graph()
    result, _ = _finalize(tmp_path, graph, _provenance(graph), drop=("analysis.json",))
    assert result.returncode == 1
    assert "missing analysis.json" in result.stderr, result.stderr


def test_an_analysis_of_an_older_graph_cannot_ship(tmp_path):
    """Repair the graph at step 6, skip step 7, and the numbers would be stale."""
    graph = _graph()
    result, out = _finalize(tmp_path, graph, _provenance(graph), derive=True)
    assert result.returncode == 0, result.stderr

    stale = json.loads((out / "analysis.json").read_text(encoding="utf-8"))
    stale["mincut_all"] += 1
    (out / "analysis.json").write_text(json.dumps(stale, indent=2), encoding="utf-8")
    again = subprocess.run(
        [sys.executable, str(SCRIPTS / "graph_finalize.py"), str(out),
         "--merge-record", str(tmp_path / "merge.json"),
         "--scope-registry", str(REGISTRY)],
        capture_output=True, text=True,
    )
    assert again.returncode == 1
    assert "not derived from this graph.json" in again.stderr, again.stderr


def test_a_deliverable_recording_no_route_is_refused(tmp_path):
    """`paths` may be empty in a fragment; a finished graph with none says nothing."""
    graph = _graph()
    graph["paths"] = []
    result, _ = _finalize(tmp_path, graph, _provenance(graph))
    assert result.returncode == 1
    assert "records no route" in result.stderr, result.stderr


def test_every_route_must_say_which_role_found_it(tmp_path):
    """Attribution is the merge's own fact, so nothing downstream retypes it."""
    graph = _graph()
    merged = _merge_record(graph)
    del merged["routes"]["PATH-alt"]
    result, _ = _finalize(tmp_path, graph, _provenance(graph), merged=merged)
    assert result.returncode == 1
    assert "does not say which role found PATH-alt" in result.stderr, result.stderr


def test_a_deliverable_must_name_the_fault(tmp_path):
    """Unchecked, the run ships with `_not stated_` where its whole point goes."""
    graph = _graph()
    result, _ = _finalize(tmp_path, graph, _provenance(graph, fault={}))
    assert result.returncode == 1
    assert "must name the fault" in result.stderr, result.stderr


def test_an_unsettled_claim_must_name_what_blocked_it(tmp_path):
    """A check the pass could have run is unfinished work, not a finding."""
    graph = _graph()
    record = _provenance(graph, unsettled=[{"claim": "another route", "check": "GET /x"}])
    result, _ = _finalize(tmp_path, graph, record)
    assert result.returncode == 1
    assert "must carry blocked_by" in result.stderr, result.stderr




# --- the probe harness: one request, and the evidence it earns -----------------

WITNESS = "CYBERARENA-witness-9f2a"


class _Target(http.server.BaseHTTPRequestHandler):
    """Stands in for the study's build: echoes what it was sent, denies /denied."""

    def _respond(self, status, body, extra=()):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("X-Study-Witness", f"{WITNESS}-header")
        for name, value in extra:
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802 - BaseHTTPRequestHandler's spelling
        if self.path.startswith("/redir"):
            self._respond(302, b'{"moved": true}', [("Location", "/api/settings")])
            return
        if self.path.startswith("/login"):
            # Two, because Set-Cookie is the header that repeats.
            self._respond(200, b'{"logged_in": true}',
                          [("Set-Cookie", "session=MINTED-BY-THE-RUN; Path=/"),
                           ("Set-Cookie", "flavour=second; Path=/")])
            return
        if self.path.startswith("/deep"):
            # The disclosure lands past the excerpt the log keeps, as it does in
            # any application that renders it inside a page.
            self._respond(200, ("." * 6000 + WITNESS + "tail").encode())
            return
        body = json.dumps({
            "auth": self.headers.get("Authorization"),
            "path": self.path,
            "extra": self.headers.get("X-Extra"),
            "cookie": self.headers.get("Cookie"),
            "value": WITNESS,
        }).encode()
        self._respond(403 if self.path.startswith("/denied") else 200, body)

    def do_POST(self):  # noqa: N802 - BaseHTTPRequestHandler's spelling
        raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        self._respond(200, json.dumps({
            "content_type": self.headers.get("Content-Type"),
            "body": raw.decode("utf-8", "replace"),
            "body_hex": raw.hex(),
            "value": WITNESS,
        }).encode())

    def log_message(self, *args):
        pass


@pytest.fixture
def target(tmp_path):
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Target)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    path = tmp_path / "target.json"
    path.write_text(json.dumps({"builds": {"vulnerable": {
        "base_url": f"http://127.0.0.1:{server.server_address[1]}",
        "auth_header": "Authorization: token analyst:s3cret",
    }}}), encoding="utf-8")
    yield path
    server.shutdown()


def _probe(target, *extra):
    return subprocess.run(
        [sys.executable, str(SCRIPTS / "probe.py"), "--target", str(target),
         "--build", "vulnerable", "--path", "/api/settings", *extra],
        capture_output=True, text=True,
    )


def test_a_probe_earns_evidence_the_graph_accepts(tmp_path, target):
    """The point of the harness: the four fields are built from the response."""
    result = _probe(target, "--observed", WITNESS)
    assert result.returncode == 0, result.stderr
    earned = json.loads(result.stdout.split("evidence:", 1)[1])

    graph = _graph()
    _node(graph, "N-upload-template")["evidence"] = earned
    assert _validate(tmp_path, graph).returncode == 0, _validate(tmp_path, graph).stderr


def test_a_query_string_request_reaches_the_target(tmp_path, target):
    """A run found --param broken for well-formed input too: urlencode takes
    tuples, and the split returned lists, so every query-string probe died."""
    result = _probe(target, "--param", "per_page=100", "--param", "query=a b")
    assert result.returncode == 0, result.stderr
    sent = json.loads(json.loads(result.stdout)["body"])["path"]
    assert sent == "/api/settings?per_page=100&query=a+b", sent


@pytest.mark.parametrize("observed, message", [
    ("a string the target never sent", "no evidence here to record"),
    ("short", "observed must carry at least"),
])
def test_a_rejected_observation_keeps_the_exchange(tmp_path, target, observed, message):
    """An unsupported claim must not erase the response that refuted it."""
    result = _probe(target, "--observed", observed)
    assert result.returncode == 1
    assert message in result.stderr, result.stderr
    logged = [json.loads(line) for line in
              (target.parent / "probes.log").read_text().splitlines()]
    assert len(logged) == 1
    assert logged[0] == json.loads(result.stdout)
    assert logged[0]["status"] == 200
    assert json.loads(logged[0]["body"])["value"] == WITNESS
    assert "evidence" not in logged[0]


def test_a_denial_is_a_result_not_a_failure(tmp_path, target):
    """A 403 is what a route being closed looks like; it has to be recordable."""
    result = subprocess.run(
        [sys.executable, str(SCRIPTS / "probe.py"), "--target", str(target),
         "--build", "vulnerable", "--path", "/denied"],
        capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["status"] == 403


def test_every_probe_is_logged_beside_the_target(tmp_path, target):
    """A run that ended badly still has to say what was sent."""
    _probe(target, "--note", "first")
    _probe(target, "--note", "second")
    logged = [json.loads(line) for line in
              (target.parent / "probes.log").read_text(encoding="utf-8").splitlines()]
    assert [record["note"] for record in logged] == ["first", "second"]


def test_a_probe_goes_out_as_the_entry_principal(tmp_path, target):
    """The entry node is an identity; a probe sent as anyone else proves nothing."""
    result = _probe(target)
    assert json.loads(json.loads(result.stdout)["body"])["auth"] == "token analyst:s3cret"


def test_a_study_with_no_runnable_bundle_is_not_probed(tmp_path):
    """`none: true` is the root saying there is nothing to reach."""
    path = tmp_path / "target.json"
    path.write_text(json.dumps({"none": True}), encoding="utf-8")
    result = _probe(path)
    assert result.returncode == 1
    assert "nothing to probe" in result.stderr, result.stderr


def test_a_response_header_reaches_the_log(tmp_path, target):
    """A study served its archive with the key that decrypts it in a header.

    probe.py read the headers and kept only Content-Type, so the shipped witness
    proved a zip had been served and not that the secret was recovered.
    """
    result = _probe(target, "--note", "headers")
    assert result.returncode == 0, result.stderr
    logged = json.loads((target.parent / "probes.log").read_text().splitlines()[-1])
    assert ["X-Study-Witness", f"{WITNESS}-header"] in logged["headers"]


def test_a_form_body_is_sent_form_encoded(tmp_path, target):
    """Two studies needed request.form; --data is JSON, which leaves it empty."""
    result = _probe(target, "--method", "POST", "--form", "query=a b", "--form", "page=2")
    assert result.returncode == 0, result.stderr
    echoed = json.loads(json.loads(result.stdout)["body"])
    assert echoed["content_type"] == "application/x-www-form-urlencoded"
    assert echoed["body"] == "query=a+b&page=2"


@pytest.mark.parametrize("payload", [b"\x00\xffA\n", b"\x00\xfeB\n"])
def test_a_binary_request_keeps_its_bytes_in_the_evidence(tmp_path, target, payload):
    """Equal-size files with the same name must retain their distinct contents."""
    source = tmp_path / "upload.bin"
    source.write_bytes(payload)
    result = _probe(target, "--method", "POST", "--data-file", str(source),
                    "--observed", WITNESS)
    assert result.returncode == 0, result.stderr
    source.unlink()

    logged = json.loads((target.parent / "probes.log").read_text().splitlines()[-1])
    received = json.loads(logged["body"])
    assert bytes.fromhex(received["body_hex"]) == payload
    assert logged["sent"].startswith("base64:")
    assert base64.b64decode(logged["sent"].removeprefix("base64:")) == payload
    earned = json.loads(result.stdout.split("evidence:", 1)[1])
    assert f"body {logged['sent']}" in earned["source"]
    assert logged["evidence"] == earned


def test_a_claim_deeper_than_the_log_excerpt_still_earns_evidence(tmp_path, target):
    """A witness sat at character 22466 of a rendered page and was unrecordable.

    The log excerpt stays capped, so the evidence excerpt has to follow the match
    instead of the start — otherwise `observed` is not inside its own `excerpt`
    and the graph is rejected at validation.
    """
    result = _probe(target, "--path", "/deep", "--observed", WITNESS)
    assert result.returncode == 0, result.stderr
    earned = json.loads(result.stdout.split("evidence:", 1)[1])
    assert earned["observed"] in earned["excerpt"]
    # A window, not the whole body — and the log excerpt stays capped regardless.
    assert len(earned["excerpt"]) <= 4000
    logged = json.loads((target.parent / "probes.log").read_text().splitlines()[-1])
    assert len(logged["body"]) == 4000 and WITNESS not in logged["body"]

    graph = _graph()
    _node(graph, "N-upload-template")["evidence"] = earned
    assert _validate(tmp_path, graph).returncode == 0, _validate(tmp_path, graph).stderr


def test_a_header_may_not_replace_the_entry_principal(tmp_path, target):
    """--header widens the request; it must not let a probe walk as someone else."""
    result = _probe(target, "--header", "Authorization: token root:all")
    assert result.returncode == 1
    assert "may not replace the entry principal" in result.stderr, result.stderr


def test_a_repeated_response_header_is_kept_whole(tmp_path, target):
    """Set-Cookie is the header this keeps for, and the one that repeats.

    A mapping kept only the first, losing a cookie the response actually set.
    """
    assert _probe(target, "--path", "/login").returncode == 0
    logged = json.loads((target.parent / "probes.log").read_text().splitlines()[-1])
    cookies = [value for name, value in logged["headers"] if name == "Set-Cookie"]
    assert len(cookies) == 2, cookies


def test_a_claim_carried_by_a_response_header_earns_evidence(tmp_path, target):
    """A study served ciphertext with the key that decrypts it in a header.

    Matching the body alone made that claim unrecordable, so the witness could
    say only that an archive had been served.
    """
    result = _probe(target, "--path", "/deep",
                    "--observed", f"X-Study-Witness: {WITNESS}-header")
    assert result.returncode == 0, result.stderr
    earned = json.loads(result.stdout.split("evidence:", 1)[1])
    assert earned["observed"] in earned["excerpt"]

    graph = _graph()
    _node(graph, "N-upload-template")["evidence"] = earned
    assert _validate(tmp_path, graph).returncode == 0, _validate(tmp_path, graph).stderr


def test_a_cookie_is_merged_into_a_cookie_principal_the_granted_one_winning(tmp_path, target):
    """A session alongside a cookie principal is ordinary; replacing it is not.

    The principal is the identity the challenge granted, so where both name the
    same cookie the granted value is the one the route is walked with.
    """
    spec = json.loads(target.read_text())
    spec["builds"]["vulnerable"]["auth_header"] = "Cookie: i_like_gogs=GRANTED; seat=1"
    target.write_text(json.dumps(spec), encoding="utf-8")

    result = _probe(target, "--header", "Cookie: session=MINTED; i_like_gogs=ROTATED",
                    "--observed", WITNESS)
    assert result.returncode == 0, result.stderr
    record = json.loads(result.stdout.split("evidence:", 1)[0])
    seen = json.loads(record["body"])["cookie"]
    assert "session=MINTED" in seen and "i_like_gogs=GRANTED" in seen, seen
    assert "ROTATED" not in seen, seen
    assert record["added"]["Cookie"] == seen
    earned = json.loads(result.stdout.split("evidence:", 1)[1])
    assert f"Cookie: {seen}" in earned["source"]
    assert "ROTATED" not in earned["source"]


def test_case_variant_headers_record_only_the_value_sent(tmp_path, target):
    result = _probe(target, "--header", "X-Extra: first", "--header", "x-extra: second",
                    "--observed", WITNESS)
    assert result.returncode == 0, result.stderr
    record = json.loads(result.stdout.split("evidence:", 1)[0])
    seen = json.loads(record["body"])["extra"]
    assert seen == "second"
    assert record["added"] == {"X-Extra": seen}
    earned = json.loads(result.stdout.split("evidence:", 1)[1])
    assert f"X-Extra: {seen}" in earned["source"]
    assert "first" not in earned["source"]


def test_a_redirect_is_a_result_and_is_not_followed(tmp_path, target):
    """One invocation is one request.

    Following a 302 puts two requests behind one record, and lets a cookie the
    first hop sets walk the second under the first's name. The Location is the
    useful part, and it is in the headers.
    """
    result = _probe(target, "--path", "/redir")
    assert result.returncode == 0, result.stderr
    record = json.loads(result.stdout)
    assert record["status"] == 302
    assert ["Location", "/api/settings"] in record["headers"]


def test_an_exchange_another_client_ran_can_be_recorded(tmp_path, target):
    """probe.py sends HTTP; the studies in the corpus do not all speak it.

    The record is what the graph rests on, so an exchange a role ran with its own
    client earns evidence through the same containment check — and says so.
    """
    captured = tmp_path / "captured.txt"
    captured.write_text(f"SUBACK 0x00\nretained: {WITNESS}\n", encoding="utf-8")
    result = _probe(target, "--record", "--request", "MQTT SUBSCRIBE victim/+/report42",
                    "--response-file", str(captured), "--status", "0",
                    "--observed", WITNESS)
    assert result.returncode == 0, result.stderr
    earned = json.loads(result.stdout.split("evidence:", 1)[1])
    assert "attested" in earned["source"]
    assert "MQTT SUBSCRIBE victim/+/report42" in earned["source"]
    assert json.loads(result.stdout.split("evidence:", 1)[0])["witness"] == "attested"

    graph = _graph()
    _node(graph, "N-upload-template")["evidence"] = earned
    assert _validate(tmp_path, graph).returncode == 0, _validate(tmp_path, graph).stderr


def test_the_evidence_a_probe_earned_is_kept_in_the_log(tmp_path, target):
    """The root checks citations against probes.log, and an excerpt can follow a
    match past the head the log keeps — so the log carries the excerpt too."""
    assert _probe(target, "--path", "/deep", "--observed", WITNESS).returncode == 0
    logged = json.loads((target.parent / "probes.log").read_text().splitlines()[-1])
    assert logged["evidence"]["observed"] == WITNESS
    assert WITNESS in logged["evidence"]["excerpt"]
    assert WITNESS not in logged["body"]


def test_an_added_header_reaches_the_target_and_is_named(tmp_path, target):
    """Two studies needed a second header; the graph must show it was sent."""
    result = _probe(target, "--header", "X-Extra: csrf-token", "--observed", WITNESS)
    assert result.returncode == 0, result.stderr
    record = json.loads(result.stdout.split("evidence:", 1)[0])
    assert json.loads(record["body"])["extra"] == "csrf-token"
    earned = json.loads(result.stdout.split("evidence:", 1)[1])
    assert "X-Extra: csrf-token" in earned["source"]


# --- provisioning: the parts that do not need Docker ---------------------------

def _provision(*args):
    return subprocess.run(
        [sys.executable, str(SCRIPTS / "graph_provision.py"), *args],
        capture_output=True, text=True,
    )


def test_provisioning_refuses_a_directory_that_is_not_a_study(tmp_path):
    """Nothing below step 2 may discover that the study was not there."""
    result = _provision(str(tmp_path / "nowhere"), "--run", str(tmp_path / "run"),
                        "--reproducer", "true")
    assert result.returncode == 1
    assert "no STAGE3_STUDY.md" in result.stderr, result.stderr


def test_teardown_takes_nothing_it_did_not_start(tmp_path):
    """Tearing down by guesswork would take containers this run never started.

    A run that recorded no project started nothing, so there is nothing to
    remove and that is not a failure: a Jenkins run reported teardown as broken
    on a host it had left perfectly clean.
    """
    run = tmp_path / "run"
    run.mkdir()
    (run / "target.json").write_text(json.dumps({"builds": {}}), encoding="utf-8")
    result = _provision(str(tmp_path), "--run", str(run), "--down")
    assert result.returncode == 0
    assert "nothing to tear down" in result.stdout, result.stdout


def test_provisioning_will_not_write_over_an_existing_bundle_copy(tmp_path):
    """A second provision into a live run would silently reuse the first's state."""
    study = tmp_path / "study"
    (study / "evidence").mkdir(parents=True)
    (study / "STAGE3_STUDY.md").write_text("# study\n", encoding="utf-8")
    run = tmp_path / "run"
    (run / "env").mkdir(parents=True)
    result = _provision(str(study), "--run", str(run), "--reproducer", "true")
    assert result.returncode == 1
    assert "already exists" in result.stderr, result.stderr

# --- provisioning: what the exit status has to mean (needs Docker) ------------

def test_provisioning_that_discovers_no_build_is_a_failure(tmp_path):
    """Exit status is the one signal step 2 tells the caller to trust.

    Four studies in one batch ran a reproducer that passed and left nothing
    standing; the script wrote `"builds": {}` and exited 0, so provisioning
    that produced no target read as success and the next thing to notice would
    have been a role rejecting an empty `target.json` one dispatch later.
    """
    study = tmp_path / "study"
    (study / "evidence").mkdir(parents=True)
    (study / "STAGE3_STUDY.md").write_text("# study\n", encoding="utf-8")
    result = _provision(str(study), "--run", str(tmp_path / "run"),
                        "--reproducer", "true")
    assert result.returncode == 1
    assert "no build was discovered" in result.stderr, result.stderr
