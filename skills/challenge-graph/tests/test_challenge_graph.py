import json
import subprocess
import sys
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
REGISTRY = (
    Path(__file__).resolve().parents[2]
    / "challenge-create"
    / "references"
    / "attack-scopes.json"
)
REVISION = "a" * 40

EVIDENCE = {
    "pov.txt": "201 Created share=7f2a\nrecovered victim report body\n",
    "alt.txt": "201 Created template=t9\nrecovered victim report body\n",
    "fixed-pov.txt": "403 Forbidden denied\n",
    "fixed-alt.txt": "recovered victim report body\n",
}


def _cite(locator, observed):
    return {"locator": locator, "observed": observed}


def _fn(node_id, title, requires, locator, observed, **extra):
    return {
        "id": node_id,
        "role": "function",
        "title": title,
        "symbol": f"App.{node_id.removeprefix('N-').replace('-', '_')}",
        "requires": requires,
        "evidence": _cite(locator, observed),
        **extra,
    }


def _graph():
    """Two vertex-disjoint routes to one objective; the upstream cut blocks one."""
    return {
        "schema_version": 2,
        "target": {"id": "acme-reports", "repository": "acme/reports", "revision": REVISION},
        "evidence_root": "evidence",
        "nodes": [
            {"id": "N-entry", "role": "entry", "title": "Baseline principal"},
            _fn("N-create-share", "create share link", ["N-entry"],
                "evidence/pov.txt#L1", "201 Created share",
                symbol="ShareController.create"),
            _fn("N-resolve-share", "resolve share link", ["N-create-share"],
                "evidence/pov.txt#L2", "recovered victim",
                symbol="ShareController.resolve"),
            _fn("N-upload-template", "upload template", ["N-entry"],
                "evidence/alt.txt#L1", "201 Created template",
                symbol="TemplateController.create"),
            _fn("N-render-template", "render template", ["N-upload-template"],
                "evidence/alt.txt#L2", "recovered victim",
                symbol="ExportRenderer.render"),
            {
                "id": "N-obj",
                "role": "objective",
                "store": "report_store",
                "scope": "app.cross_boundary.read",
                "requires": ["N-resolve-share", "N-render-template"],
            },
        ],
        "paths": [
            {
                "id": "PATH-pov",
                "objective": "N-obj",
                "nodes": ["N-entry", "N-create-share", "N-resolve-share", "N-obj"],
                "advisories": ["CVE-2026-0001"],
                "witnesses": [_cite("evidence/pov.txt#L2", "recovered victim report")],
            },
            {
                "id": "PATH-alt",
                "objective": "N-obj",
                "nodes": ["N-entry", "N-upload-template", "N-render-template", "N-obj"],
                "advisories": [],
                "witnesses": [_cite("evidence/alt.txt#L2", "recovered victim report")],
            },
        ],
        "observed_cuts": [
            {
                "id": "CUT-upstream",
                "reference": "upstream_fix",
                "blocked": [_cite("evidence/fixed-pov.txt#L1", "403 Forbidden") | {"path": "PATH-pov"}],
                "survived": [
                    _cite("evidence/fixed-alt.txt#L1", "recovered victim") | {"path": "PATH-alt"}
                ],
            }
        ],
    }


def _node(graph, node_id):
    return next(n for n in graph["nodes"] if n["id"] == node_id)


def _path(graph, path_id):
    return next(p for p in graph["paths"] if p["id"] == path_id)


def _study(tmp_path):
    study = tmp_path / "study"
    (study / "evidence").mkdir(parents=True, exist_ok=True)
    for name, body in EVIDENCE.items():
        (study / "evidence" / name).write_text(body, encoding="utf-8")
    (study / "STAGE3_STUDY.md").write_text(
        "The attacker resolves the share link and reads the victim report body.\n",
        encoding="utf-8",
    )
    return study


def _write(tmp_path, graph):
    path = tmp_path / "graph.json"
    path.write_text(json.dumps(graph, indent=2) + "\n", encoding="utf-8")
    return path


def _run(script, tmp_path, graph, *extra, study=None):
    return subprocess.run(
        [sys.executable, str(SCRIPTS / script), str(_write(tmp_path, graph)),
         "--study-dir", str(study or _study(tmp_path)), *extra],
        capture_output=True,
        text=True,
    )


def _validate(tmp_path, graph, study=None):
    return _run("graph_validate.py", tmp_path, graph, study=study)


def _analyze(tmp_path, graph):
    out = tmp_path / "derived" / "analysis.json"
    result = _run("graph_analyze.py", tmp_path, graph, "--out", str(out))
    assert result.returncode == 0, result.stderr
    return json.loads(out.read_text(encoding="utf-8"))


def _render(tmp_path, graph):
    out = tmp_path / "derived" / "graph.md"
    result = _run("graph_render.py", tmp_path, graph, "--out", str(out))
    assert result.returncode == 0, result.stderr
    return out.read_text(encoding="utf-8")


def _fails(tmp_path, mutate, needle):
    graph = _graph()
    mutate(graph)
    result = _validate(tmp_path, graph)
    assert result.returncode == 1, f"expected rejection, got: {result.stdout}"
    assert needle in result.stderr, f"expected {needle!r} in: {result.stderr}"
    return result


# --- the fixture itself -----------------------------------------------------


def test_two_disjoint_routes_read_as_disjoint_and_contestable(tmp_path):
    analysis = _analyze(tmp_path, _graph())
    assert analysis["geometry"] == ["disjoint"]
    assert analysis["mincut_all"] == 2
    assert analysis["observed_cuts"][0]["reading"] == "contestable_observed"


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


def test_evidence_kind_is_rejected_rather_than_ignored(tmp_path):
    """Silently accepting `kind` would let v1 habits survive unnoticed."""
    def mutate(graph):
        _node(graph, "N-create-share")["evidence"]["kind"] = "reproduced"
    _fails(tmp_path, mutate, "kind was removed in schema 2")


# --- routes may not merge (the cut-shrinking regression) --------------------


def test_a_route_may_not_absorb_another_routes_nodes(tmp_path):
    """Listing both branches in one path shrinks the hitting set and understates
    the mincut: the tool would claim one node cuts routes it never touches."""
    def mutate(graph):
        _path(graph, "PATH-pov")["nodes"] = [
            "N-entry", "N-create-share", "N-resolve-share",
            "N-upload-template", "N-render-template", "N-obj",
        ]
    _fails(tmp_path, mutate, "still reaches N-obj without")


def test_a_route_must_reach_each_node_through_a_predecessor(tmp_path):
    def mutate(graph):
        _path(graph, "PATH-pov")["nodes"] = ["N-entry", "N-resolve-share", "N-obj"]
    _fails(tmp_path, mutate, "before any of its predecessors")


def test_a_node_nothing_on_the_route_uses_is_rejected(tmp_path):
    def mutate(graph):
        graph["nodes"].append(
            _fn("N-idle", "unused probe", ["N-entry"], "evidence/pov.txt#L1", "201 Created share")
        )
        _path(graph, "PATH-pov")["nodes"] = [
            "N-entry", "N-idle", "N-create-share", "N-resolve-share", "N-obj"
        ]
    _fails(tmp_path, mutate, "still reaches N-obj without N-idle")


# --- AND / OR ---------------------------------------------------------------


def test_requires_all_demands_every_predecessor_on_the_route(tmp_path):
    def mutate(graph):
        node = _node(graph, "N-resolve-share")
        node["requires"] = ["N-create-share", "N-upload-template"]
        node["requires_all"] = True
    _fails(tmp_path, mutate, "without N-upload-template")


def _shared_serializer(graph):
    """Both routes pass through one function, as Airflow's two reads do."""
    graph["nodes"].append(
        _fn("N-serialize", "shared response serializer",
            ["N-resolve-share", "N-render-template"],
            "evidence/pov.txt#L2", "recovered victim")
    )
    _node(graph, "N-obj")["requires"] = ["N-serialize"]
    for path_id in ("PATH-pov", "PATH-alt"):
        path = _path(graph, path_id)
        path["nodes"] = path["nodes"][:-1] + ["N-serialize", "N-obj"]
    return graph


def test_a_shared_node_reached_by_either_branch_reads_as_fan_in(tmp_path):
    """The Airflow shape: two routes, one shared function, so one fix covers both."""
    analysis = _analyze(tmp_path, _shared_serializer(_graph()))
    assert analysis["geometry"] == ["fan_in"]
    assert analysis["mincut_all"] == 1
    assert analysis["minimum_cuts_all"] == [["N-serialize"]]


# --- terminals are never cut ------------------------------------------------


def test_no_cut_ever_contains_a_terminal(tmp_path):
    """The entry is the identity the challenge grants, so 'disable login' is not
    a defense of this boundary; including it would make every mincut 1."""
    analysis = _analyze(tmp_path, _graph())
    flat = {node for cut in analysis["minimum_cuts_all"] for node in cut}
    assert "N-entry" not in flat and "N-obj" not in flat


# --- geometry ---------------------------------------------------------------


def _shortcut(graph):
    graph["nodes"].append(
        _fn("N-direct", "one-hop shortcut", ["N-entry"], "evidence/pov.txt#L2", "recovered victim")
    )
    _node(graph, "N-obj")["requires"].append("N-direct")
    graph["paths"].append(
        {
            "id": "PATH-short",
            "objective": "N-obj",
            "nodes": ["N-entry", "N-direct", "N-obj"],
            "advisories": [],
            "witnesses": [_cite("evidence/pov.txt#L2", "recovered victim report")],
        }
    )


def test_a_one_node_route_is_labelled_shallow_not_rejected(tmp_path):
    graph = _graph()
    _shortcut(graph)
    analysis = _analyze(tmp_path, graph)
    assert analysis["geometry"] == ["shallow"]
    assert analysis["nontrivial_paths"]["PATH-short"] is False


def test_a_shallow_route_cannot_manufacture_disjoint_geometry(tmp_path):
    """`shallow` is exclusive: a trivial shortcut raises mincut_all but must not
    be reported as two materially different routes."""
    graph = _graph()
    _shortcut(graph)
    analysis = _analyze(tmp_path, graph)
    assert analysis["mincut_all"] == 3
    assert analysis["mincut_nontrivial"] == 2


def test_a_lone_route_is_labelled_single_path(tmp_path):
    graph = _graph()
    graph["paths"] = [_path(graph, "PATH-pov")]
    graph["observed_cuts"][0]["survived"] = []
    analysis = _analyze(tmp_path, graph)
    assert analysis["geometry"] == ["single_path"]
    assert analysis["observed_cuts"][0]["reading"] == "terminal_over_recorded_subgraph"


def test_one_node_reaching_two_objectives_reads_as_fan_out(tmp_path):
    graph = _graph()
    graph["nodes"].append(
        {
            "id": "N-obj2",
            "role": "objective",
            "store": "second_store",
            "scope": "app.cross_boundary.write",
            "requires": ["N-resolve-share"],
        }
    )
    graph["paths"].append(
        {
            "id": "PATH-second",
            "objective": "N-obj2",
            "nodes": ["N-entry", "N-create-share", "N-resolve-share", "N-obj2"],
            "advisories": [],
            "witnesses": [_cite("evidence/pov.txt#L2", "recovered victim report")],
        }
    )
    assert "fan_out" in _analyze(tmp_path, graph)["geometry"]


def test_implicated_nodes_drop_anything_the_survivor_also_uses(tmp_path):
    """The extensional root cause: what the cut removed and the survivor kept.

    The shared node must be subtracted; the fixture's own routes are disjoint,
    so testing this on them would pass with the subtraction deleted.
    """
    graph = _shared_serializer(_graph())
    implicated = _analyze(tmp_path, graph)["observed_cuts"][0]["implicated_nodes"]
    assert implicated == ["N-create-share", "N-resolve-share"], (
        "N-serialize is on the survivor and must not be implicated"
    )


# --- frontier ---------------------------------------------------------------


def test_a_path_no_cut_was_run_against_lands_on_the_frontier(tmp_path):
    graph = _graph()
    graph["observed_cuts"][0]["survived"] = []
    frontier = _analyze(tmp_path, graph)["frontier"]
    assert {"kind": "untested_path", "target": "PATH-alt"} in frontier


def test_an_objective_with_no_route_lands_on_the_frontier(tmp_path):
    graph = _graph()
    graph["nodes"].append(
        {
            "id": "N-obj2",
            "role": "objective",
            "store": "second_store",
            "scope": "app.cross_boundary.write",
            "requires": ["N-resolve-share"],
        }
    )
    frontier = _analyze(tmp_path, graph)["frontier"]
    assert {"kind": "unreached_objective", "target": "N-obj2"} in frontier


# --- witnesses and advisories -----------------------------------------------


def test_a_route_needs_at_least_one_witness(tmp_path):
    def mutate(graph):
        _path(graph, "PATH-pov")["witnesses"] = []
    _fails(tmp_path, mutate, "must record at least one observation")


def test_a_repeat_execution_is_a_second_witness_not_a_second_route(tmp_path):
    """A study that re-ran its chain retained better evidence, not another route.
    Recording the replay as a path would manufacture geometry out of one route."""
    graph = _graph()
    _path(graph, "PATH-pov")["witnesses"].append(
        _cite("evidence/pov.txt#L2", "recovered victim report body")
    )
    analysis = _analyze(tmp_path, graph)
    assert analysis["geometry"] == ["disjoint"]
    assert analysis["mincut_all"] == 2


def test_advisories_record_every_cve_in_a_chained_route(tmp_path):
    graph = _graph()
    _path(graph, "PATH-pov")["advisories"] = ["CVE-2026-0001", "CVE-2026-0002"]
    assert _validate(tmp_path, graph).returncode == 0
    assert "CVE-2026-0002" in _render(tmp_path, graph)


def test_advisories_must_be_a_list_of_identifiers(tmp_path):
    def mutate(graph):
        _path(graph, "PATH-pov")["advisories"] = "CVE-2026-0001"
    _fails(tmp_path, mutate, "must be a list of identifiers")


# --- citations --------------------------------------------------------------


def test_observed_string_must_be_on_the_cited_line(tmp_path):
    def mutate(graph):
        _node(graph, "N-create-share")["evidence"]["observed"] = "never appeared anywhere"
    _fails(tmp_path, mutate, "observed string is not on")


def test_observed_must_quote_enough_to_identify_the_line(tmp_path):
    def mutate(graph):
        _node(graph, "N-create-share")["evidence"]["observed"] = "201"
    _fails(tmp_path, mutate, "at least 8 characters")


def test_a_locator_cannot_leave_the_evidence_root(tmp_path):
    """Names the message, so a rejection for some other reason cannot pass."""
    def mutate(graph):
        _node(graph, "N-create-share")["evidence"] = _cite(
            "STAGE3_STUDY.md#L1", "The attacker resolves"
        )
    _fails(tmp_path, mutate, "resolves outside evidence")


def test_a_locator_cannot_traverse_out_of_the_study(tmp_path):
    def mutate(graph):
        _node(graph, "N-create-share")["evidence"] = _cite(
            "evidence/../../outside.txt#L1", "201 Created share"
        )
    _fails(tmp_path, mutate, "must stay inside the study")


def test_a_symlink_cannot_read_outside_the_study(tmp_path):
    secret = tmp_path / "outside.txt"
    secret.write_text("201 Created share=7f2a\n", encoding="utf-8")
    study = _study(tmp_path)
    (study / "evidence" / "link.txt").symlink_to(secret)
    graph = _graph()
    _node(graph, "N-create-share")["evidence"] = _cite("evidence/link.txt#L1", "201 Created share")
    result = _validate(tmp_path, graph, study=study)
    assert result.returncode == 1
    assert "resolves outside" in result.stderr


def test_a_graph_without_evidence_root_may_cite_the_study_document(tmp_path):
    """Some studies retained no evidence directory; the graph is still buildable."""
    graph = _graph()
    graph.pop("evidence_root")
    for node in graph["nodes"]:
        if node["role"] == "function":
            node["evidence"] = _cite("STAGE3_STUDY.md#L1", "The attacker resolves")
    for path in graph["paths"]:
        path["witnesses"] = [_cite("STAGE3_STUDY.md#L1", "reads the victim report")]
    for cut in graph["observed_cuts"]:
        for key in ("blocked", "survived"):
            for entry in cut[key]:
                entry.update(_cite("STAGE3_STUDY.md#L1", "The attacker resolves"))
    assert _validate(tmp_path, graph).returncode == 0


def test_citation_sources_expose_a_graph_built_from_study_prose(tmp_path):
    graph = _graph()
    _node(graph, "N-create-share")["evidence"] = _cite("STAGE3_STUDY.md#L1", "The attacker resolves")
    graph.pop("evidence_root")
    analysis = _analyze(tmp_path, graph)
    assert analysis["citation_sources"]["elsewhere"] >= 1


def test_fabricated_cut_evidence_is_rejected(tmp_path):
    def mutate(graph):
        graph["observed_cuts"][0]["blocked"][0]["observed"] = "418 I am a teapot"
    _fails(tmp_path, mutate, "observed string is not on")


# --- the discriminator warning ----------------------------------------------


def test_a_witness_that_reads_the_same_on_the_fixed_build_warns(tmp_path):
    """A blocked route's witness must differ across builds or it shows nothing."""
    graph = _graph()
    graph["observed_cuts"][0]["blocked"][0].update(
        _cite("evidence/fixed-alt.txt#L1", "recovered victim")
    )
    analysis = _analyze(tmp_path, graph)
    assert any(w["where"].startswith("path PATH-pov") for w in analysis["warnings"])


def test_only_a_blocked_route_can_warn(tmp_path):
    """A survivor has no blocked citation to compare against, so reproducing on
    the repaired build — the contestable finding itself — never warns."""
    analysis = _analyze(tmp_path, _graph())
    assert not [w for w in analysis["warnings"] if w["where"].startswith("path PATH-alt")]


def test_the_fixed_build_is_found_by_citation_not_by_filename(tmp_path):
    """A study naming its repaired run `patched.txt` must still be checked; an
    empty warning list otherwise reads as 'checked and clean'."""
    study = _study(tmp_path)
    (study / "evidence" / "patched.txt").write_text(
        "recovered victim report body\n", encoding="utf-8"
    )
    (study / "evidence" / "fixed-pov.txt").unlink()
    (study / "evidence" / "fixed-alt.txt").unlink()
    graph = _graph()
    graph["observed_cuts"][0]["blocked"][0].update(
        _cite("evidence/patched.txt#L1", "recovered victim")
    )
    graph["observed_cuts"][0]["survived"] = []
    out = tmp_path / "derived" / "analysis.json"
    result = _run("graph_analyze.py", tmp_path, graph, "--out", str(out), study=study)
    assert result.returncode == 0, result.stderr
    warnings = json.loads(out.read_text(encoding="utf-8"))["warnings"]
    assert any(w["where"].startswith("path PATH-pov") for w in warnings)


# --- structure --------------------------------------------------------------


def test_the_study_dir_must_be_a_real_stage3_study(tmp_path):
    scratch = tmp_path / "scratch"
    (scratch / "evidence").mkdir(parents=True)
    for name, body in EVIDENCE.items():
        (scratch / "evidence" / name).write_text(body, encoding="utf-8")
    result = _validate(tmp_path, _graph(), study=scratch)
    assert result.returncode == 1
    assert "not a Stage 3 study" in result.stderr


def test_cycles_are_rejected(tmp_path):
    def mutate(graph):
        _node(graph, "N-entry")["role"] = "function"
        _node(graph, "N-entry")["requires"] = ["N-resolve-share"]
        _node(graph, "N-entry")["evidence"] = _cite("evidence/pov.txt#L1", "201 Created share")
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
        _node(graph, "N-entry")["requires"] = ["N-create-share"]
    _fails(tmp_path, mutate, "must not require another node")


def test_a_cut_must_record_a_path(tmp_path):
    def mutate(graph):
        graph["observed_cuts"][0]["blocked"] = []
        graph["observed_cuts"][0]["survived"] = []
    _fails(tmp_path, mutate, "must record at least one path")


def test_a_cut_recording_only_survivors_reads_contestable(tmp_path):
    """An EXPAND fragment carrying only its surviving route must validate."""
    graph = _graph()
    graph["observed_cuts"][0]["blocked"] = []
    analysis = _analyze(tmp_path, graph)
    assert analysis["observed_cuts"][0]["reading"] == "contestable_observed"
    assert analysis["observed_cuts"][0]["implicated_nodes"] == []


def test_a_cut_cannot_list_one_path_as_both_blocked_and_survived(tmp_path):
    def mutate(graph):
        graph["observed_cuts"][0]["survived"][0]["path"] = "PATH-pov"
    _fails(tmp_path, mutate, "twice")


def test_a_route_must_end_at_its_objective(tmp_path):
    def mutate(graph):
        _path(graph, "PATH-pov")["nodes"] = ["N-entry", "N-create-share", "N-resolve-share"]
    _fails(tmp_path, mutate, "must end at N-obj")


def test_an_unregistered_objective_scope_is_rejected(tmp_path):
    graph = _graph()
    _node(graph, "N-obj")["scope"] = "not.a.real.scope"
    result = _run("graph_validate.py", tmp_path, graph, "--scope-registry", str(REGISTRY))
    assert result.returncode == 1
    assert "not registered" in result.stderr


def test_a_challenge_local_scope_is_accepted(tmp_path):
    graph = _graph()
    _node(graph, "N-obj")["scope"] = "custom.acme-reports.share_read"
    result = _run("graph_validate.py", tmp_path, graph, "--scope-registry", str(REGISTRY))
    assert result.returncode == 0, result.stderr


# --- malformed input produces a message, never a traceback ------------------


def test_an_unknown_node_id_reports_an_error_rather_than_crashing(tmp_path):
    result = _fails(tmp_path, lambda g: _path(g, "PATH-pov")["nodes"].insert(1, "N-nope"),
                    "unknown nodes")
    assert "Traceback" not in result.stderr


def test_a_non_list_requires_reports_an_error_rather_than_crashing(tmp_path):
    result = _fails(tmp_path, lambda g: _node(g, "N-create-share").update({"requires": "N-entry"}),
                    "must be a non-empty list")
    assert "Traceback" not in result.stderr


def test_an_unhashable_role_reports_an_error_rather_than_crashing(tmp_path):
    result = _fails(tmp_path, lambda g: _node(g, "N-create-share").update({"role": {}}),
                    "unknown role")
    assert "Traceback" not in result.stderr


def test_a_non_boolean_requires_all_reports_an_error(tmp_path):
    _fails(tmp_path, lambda g: _node(g, "N-create-share").update({"requires_all": "yes"}),
           "must be a boolean")


def test_a_function_must_name_what_it_is(tmp_path):
    """`symbol` is what says two nodes are one node, so a function needs one."""
    _fails(tmp_path, lambda g: _node(g, "N-create-share").pop("symbol"),
           "function N-create-share must declare symbol")


def test_an_empty_symbol_says_what_is_wrong_with_it(tmp_path):
    """It did declare one, so "must declare symbol" would send the author nowhere."""
    _fails(tmp_path, lambda g: _node(g, "N-create-share").update({"symbol": "  "}),
           "node N-create-share.symbol must be a non-empty string")


def test_an_unusable_symbol_reports_an_error_rather_than_crashing(tmp_path):
    """It is used as a dict key while matching nodes, so its shape is checked for
    every role — an entry's included, which skips the rest of the node rules."""
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
         "--study-dir", str(_study(tmp_path))],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1
    assert "not valid JSON" in result.stderr
    assert "Traceback" not in result.stderr


# --- rendering --------------------------------------------------------------


def test_a_survived_route_stays_solid_in_the_diagram(tmp_path):
    """Contestability has to be visible: the blocked branch dashes, the other
    does not. A diagram with every edge dashed would show nothing."""
    body = _render(tmp_path, _graph())
    dashed = [line for line in body.splitlines() if "stroke-dasharray" in line]
    edges = [line for line in body.splitlines() if "-->" in line]
    assert dashed, "the blocked branch must be marked"
    assert len(dashed) < len(edges), "a survived branch must stay solid"


def test_the_report_names_each_node_s_code_symbol(tmp_path):
    assert "ShareController.create" in _render(tmp_path, _graph())


def test_the_report_says_it_does_not_judge_admissibility(tmp_path):
    """Both claims travel with graph.md, so they are part of the deliverable."""
    body = _render(tmp_path, _graph())
    assert "admissibility not judged" in body
    assert "unchecked author claim" in body


# --- cut search -------------------------------------------------------------


def test_a_wide_disjoint_graph_still_reports_its_mincut(tmp_path):
    graph = _graph()
    graph["paths"] = []
    graph["observed_cuts"] = []
    _node(graph, "N-obj")["requires"] = []
    for index in range(6):
        first, second = f"N-a{index}", f"N-b{index}"
        graph["nodes"].append(
            _fn(first, f"step a{index}", ["N-entry"], "evidence/pov.txt#L1", "201 Created share")
        )
        graph["nodes"].append(
            _fn(second, f"step b{index}", [first], "evidence/pov.txt#L2", "recovered victim")
        )
        _node(graph, "N-obj")["requires"].append(second)
        graph["paths"].append(
            {
                "id": f"PATH-{index}",
                "objective": "N-obj",
                "nodes": ["N-entry", first, second, "N-obj"],
                "advisories": [],
                "witnesses": [_cite("evidence/pov.txt#L2", "recovered victim report")],
            }
        )
    analysis = _analyze(tmp_path, graph)
    assert analysis["mincut_all"] == 6
    assert analysis["cuts_truncated"] is True


def test_an_exhausted_cut_search_reports_unknown_rather_than_guessing():
    sys.path.insert(0, str(SCRIPTS))
    try:
        from _graph import minimal_cuts
    finally:
        sys.path.pop(0)
    wide = [frozenset({f"n{group}_{index}" for index in range(40)}) for group in range(14)]
    cuts, size, truncated = minimal_cuts(wide)
    assert cuts == [] and size is None and truncated is True


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
                                 "evidence/pov.txt#L1", "201 Created share"))
    _node(graph, "N-resolve-share")["requires"] = ["N-upload", "N-create-share"]
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
    The rule forces `requires` to describe the application, not the transcript."""
    graph = _nested_or(_graph())
    _node(graph, "N-resolve-share")["requires"] = ["N-upload"]
    assert _validate(tmp_path, graph).returncode == 0
    analysis = _analyze(tmp_path, graph)
    assert "N-upload" in {n for cut in analysis["minimum_cuts_all"] for n in cut}


def test_a_conjunction_route_is_not_forced_into_adjacency(tmp_path):
    """Both conjuncts of a requires_all node are parallel branches. Demanding
    they sit next to each other would invent an edge the application lacks."""
    graph = _graph()
    _node(graph, "N-resolve-share")["requires"] = ["N-create-share", "N-upload-template"]
    _node(graph, "N-resolve-share")["requires_all"] = True
    _node(graph, "N-obj")["requires"] = ["N-resolve-share"]
    graph["paths"] = [
        {
            "id": "PATH-pov",
            "objective": "N-obj",
            "nodes": ["N-entry", "N-create-share", "N-upload-template",
                      "N-resolve-share", "N-obj"],
            "advisories": [],
            "witnesses": [_cite("evidence/pov.txt#L2", "recovered victim report")],
        }
    ]
    graph["observed_cuts"][0]["survived"] = []
    assert _validate(tmp_path, graph).returncode == 0
    cuts = {n for cut in _analyze(tmp_path, graph)["minimum_cuts_all"] for n in cut}
    assert {"N-create-share", "N-upload-template"} <= cuts, "both conjuncts are cuttable"


# --- the guard against an unsound-small cut ---------------------------------


def test_an_interior_node_must_be_a_function(tmp_path):
    """A mid-route node relabelled `entry` would vanish from every cut, which is
    the one way left to understate a min-cut."""
    def mutate(graph):
        _node(graph, "N-create-share")["role"] = "entry"
        _node(graph, "N-create-share").pop("requires")
    _fails(tmp_path, mutate, "interior node N-create-share must be a function")


def test_a_route_must_start_at_an_entry_node(tmp_path):
    def mutate(graph):
        _path(graph, "PATH-pov")["nodes"] = ["N-create-share", "N-resolve-share", "N-obj"]
    _fails(tmp_path, mutate, "must start at an entry node")


def test_evidence_root_may_not_be_the_study_itself(tmp_path):
    """`.` would let the study's own prose stand in for retained output."""
    def mutate(graph):
        graph["evidence_root"] = "."
    _fails(tmp_path, mutate, "evidence_root")


def test_a_duplicate_cut_id_is_named_as_a_cut(tmp_path):
    """'unique string id' alone also matches the nodes and paths messages, so a
    rejection for the wrong reason would pass."""
    def mutate(graph):
        graph["observed_cuts"].append(json.loads(json.dumps(graph["observed_cuts"][0])))
    _fails(tmp_path, mutate, "observed_cuts entry")


# --- read failures ----------------------------------------------------------


def test_a_json_null_document_is_rejected_rather_than_passing(tmp_path):
    """`null` is a document, not a read failure. Conflating them let it skip
    validation entirely and report success."""
    path = tmp_path / "graph.json"
    path.write_text("null", encoding="utf-8")
    result = subprocess.run(
        [sys.executable, str(SCRIPTS / "graph_validate.py"), str(path),
         "--study-dir", str(_study(tmp_path))],
        capture_output=True, text=True,
    )
    assert result.returncode == 1, f"null validated clean: {result.stdout}"
    assert "Traceback" not in result.stderr


def test_an_unreadable_graph_file_reports_an_error_rather_than_crashing(tmp_path):
    study = _study(tmp_path)
    for name, body in (("adir", None), ("binary.json", b"\xff\xfe\x00\x01")):
        target = tmp_path / name
        target.mkdir() if body is None else target.write_bytes(body)
        result = subprocess.run(
            [sys.executable, str(SCRIPTS / "graph_validate.py"), str(target),
             "--study-dir", str(study)],
            capture_output=True, text=True,
        )
        assert result.returncode == 1, name
        assert "Traceback" not in result.stderr, name


# --- reporting --------------------------------------------------------------


def test_a_healthy_graph_emits_no_citation_warning(tmp_path):
    """A survivor's fixed-build output holds the success string by definition;
    pooling it made a clean graph warn about itself."""
    assert _analyze(tmp_path, _graph())["warnings"] == []


def test_citation_sources_follow_a_nested_evidence_root(tmp_path):
    """Counting only the first path segment inverted the one signal that says a
    graph rests on the study's prose."""
    study = _study(tmp_path)
    (study / "evidence" / "run1").mkdir()
    for name, body in EVIDENCE.items():
        (study / "evidence" / "run1" / name).write_text(body, encoding="utf-8")
    graph = _graph()
    graph["evidence_root"] = "evidence/run1"
    payload = json.dumps(graph).replace('"evidence/', '"evidence/run1/')
    graph = json.loads(payload)
    graph["evidence_root"] = "evidence/run1"
    out = tmp_path / "derived" / "analysis.json"
    result = _run("graph_analyze.py", tmp_path, graph, "--out", str(out), study=study)
    assert result.returncode == 0, result.stderr
    sources = json.loads(out.read_text(encoding="utf-8"))["citation_sources"]
    assert sources["elsewhere"] == 0 and sources["inside_evidence_root"] > 0


# --- multi-role merge -------------------------------------------------------


def _seed():
    """What SEED authors: the terminals plus the advisory-backed route."""
    graph = _graph()
    keep = {"N-entry", "N-create-share", "N-resolve-share", "N-obj"}
    graph["nodes"] = [n for n in graph["nodes"] if n["id"] in keep]
    _node(graph, "N-obj")["requires"] = ["N-resolve-share"]
    graph["paths"] = [_path(graph, "PATH-pov")]
    graph["observed_cuts"][0]["survived"] = []
    return graph


def _expand():
    """What EXPAND appends: a further route to the objective SEED already declared."""
    graph = _graph()
    keep = {"N-entry", "N-upload-template", "N-render-template", "N-obj"}
    graph["nodes"] = [n for n in graph["nodes"] if n["id"] in keep]
    _node(graph, "N-obj")["requires"] = ["N-render-template"]
    graph["paths"] = [_path(graph, "PATH-alt")]
    graph["observed_cuts"][0]["blocked"] = []
    return graph


def _merge(tmp_path, seed, expand, *extra):
    study = _study(tmp_path)
    paths = {}
    for name, document in (("seed", seed), ("expand", expand)):
        paths[name] = tmp_path / f"{name}.json"
        paths[name].write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    out = tmp_path / "merged" / "graph.json"
    record = tmp_path / "merged" / "merge.json"
    result = subprocess.run(
        [sys.executable, str(SCRIPTS / "graph_merge.py"), str(paths["seed"]),
         str(paths["expand"]), "--out", str(out), "--record", str(record),
         "--study-dir", str(study), *extra],
        capture_output=True,
        text=True,
    )
    return result, out, record


def test_merge_reunites_the_fragments_into_the_disjoint_reading(tmp_path):
    """Split authoring must reproduce exactly what one agent would have written."""
    result, out, record = _merge(tmp_path, _seed(), _expand())
    assert result.returncode == 0, result.stderr

    merged = json.loads(out.read_text(encoding="utf-8"))
    assert _node(merged, "N-obj")["requires"] == ["N-resolve-share", "N-render-template"]
    assert [p["id"] for p in merged["paths"]] == ["PATH-pov", "PATH-alt"]

    cut = merged["observed_cuts"][0]
    assert [e["path"] for e in cut["blocked"]] == ["PATH-pov"]
    assert [e["path"] for e in cut["survived"]] == ["PATH-alt"]

    analysis = _analyze(tmp_path, merged)
    assert analysis["geometry"] == ["disjoint"]
    assert analysis["mincut_all"] == 2
    assert analysis["observed_cuts"][0]["reading"] == "contestable_observed"

    written = json.loads(record.read_text(encoding="utf-8"))
    assert written["routes_added"] == ["PATH-alt"]
    assert sorted(written["nodes_added"]) == ["N-render-template", "N-upload-template"]
    assert written["requires_widened"] == ["N-obj"]


def test_merge_rejects_an_objective_expand_invented(tmp_path):
    """CH-4: objectives derive from the asset graph, never from the vulnerability."""
    expand = _expand()
    _node(expand, "N-obj")["id"] = "N-obj-new"
    _path(expand, "PATH-alt")["objective"] = "N-obj-new"
    _path(expand, "PATH-alt")["nodes"][-1] = "N-obj-new"
    expand["observed_cuts"] = []
    result, _, _ = _merge(tmp_path, _seed(), expand)
    assert result.returncode == 1
    assert "EXPAND introduced objective node N-obj-new" in result.stderr


def test_merge_refuses_a_route_only_on_the_record(tmp_path):
    """The root owns the deliverable, so a refusal must leave a reason behind."""
    result, out, record = _merge(
        tmp_path, _seed(), _expand(), "--refute", "PATH-alt=witness cites the vulnerable build"
    )
    assert result.returncode == 0, result.stderr

    merged = json.loads(out.read_text(encoding="utf-8"))
    assert [p["id"] for p in merged["paths"]] == ["PATH-pov"]
    # The refuted route's nodes go with it, including the widened requirement.
    assert {n["id"] for n in merged["nodes"]} == set(n["id"] for n in _seed()["nodes"])
    assert _node(merged, "N-obj")["requires"] == ["N-resolve-share"]

    written = json.loads(record.read_text(encoding="utf-8"))
    assert written["routes_refuted"] == [
        {"path": "PATH-alt", "reason": "witness cites the vulnerable build"}
    ]


def test_merge_rejects_a_refutation_naming_an_unknown_route(tmp_path):
    """A typo must not silently keep the route it meant to refuse."""
    result, _, _ = _merge(tmp_path, _seed(), _expand(), "--refute", "PATH-typo=stale")
    assert result.returncode == 1
    assert "PATH-typo, which is not an EXPAND route" in result.stderr


def test_merge_will_not_widen_a_conjunction(tmp_path):
    """requires_all over a union would silently demand the new predecessor too."""
    seed, expand = _seed(), _expand()
    for graph, extra in ((seed, "N-create-share"), (expand, "N-upload-template")):
        node = _node(graph, "N-obj")
        node["requires"] = [node["requires"][0], extra]
        node["requires_all"] = True
        _path(graph, graph["paths"][0]["id"])["nodes"].insert(-1, extra)
    result, _, _ = _merge(tmp_path, seed, expand)
    assert result.returncode == 1
    assert "sets requires_all" in result.stderr


def test_merge_validates_each_fragment_and_names_which_one(tmp_path):
    expand = _expand()
    _node(expand, "N-render-template")["evidence"]["observed"] = "never written anywhere"
    result, _, _ = _merge(tmp_path, _seed(), expand)
    assert result.returncode == 1
    assert result.stderr.startswith("EXPAND ")


def test_merge_rejects_one_function_under_two_ids(tmp_path):
    """Two ids for one application function read as routes sharing nothing, which
    halves the min-cut and manufactures `disjoint` — a false contestable reading."""
    expand = _expand()
    _node(expand, "N-upload-template")["symbol"] = _node(_seed(), "N-create-share")["symbol"]
    result, _, _ = _merge(tmp_path, _seed(), expand)
    assert result.returncode == 1
    # Each fragment is fine alone; only the union names one function twice.
    assert result.stderr.startswith("merged: ")
    assert "one application function is one node" in result.stderr


def test_merge_rejects_one_defense_under_two_cut_ids(tmp_path):
    """Split ids give SEED's cut a terminal reading a recorded route escaped."""
    expand = _expand()
    expand["observed_cuts"][0]["id"] = "CUT-expand-only"
    result, _, _ = _merge(tmp_path, _seed(), expand)
    assert result.returncode == 1
    assert "record the same defense 'upstream_fix'" in result.stderr


def test_a_refutation_cannot_mask_a_route_id_collision(tmp_path):
    """Refuting the colliding id would exit 0 with a record claiming a SEED route
    was refused while that route is still in the graph."""
    expand = _expand()
    _path(expand, "PATH-alt")["id"] = "PATH-pov"
    expand["observed_cuts"][0]["survived"][0]["path"] = "PATH-pov"
    result, _, _ = _merge(tmp_path, _seed(), expand, "--refute", "PATH-pov=stale")
    assert result.returncode == 1
    assert "both fragments declare route PATH-pov" in result.stderr


def test_the_record_reports_only_widenings_that_survived_pruning(tmp_path):
    """Refuting the route that widened a node leaves its requires as SEED wrote it."""
    result, out, record = _merge(tmp_path, _seed(), _expand(), "--refute", "PATH-alt=unproven")
    assert result.returncode == 0, result.stderr
    assert _node(json.loads(out.read_text()), "N-obj")["requires"] == ["N-resolve-share"]
    assert json.loads(record.read_text())["requires_widened"] == []


def test_merge_rejects_an_entry_expand_invented(tmp_path):
    """An entry is excluded from every cut, so inventing one lowers the min-cut."""
    expand = _expand()
    expand["nodes"].append({"id": "N-entry-2", "role": "entry", "title": "Second principal"})
    result, _, _ = _merge(tmp_path, _seed(), expand)
    assert result.returncode == 1
    assert "EXPAND introduced entry node N-entry-2" in result.stderr


def test_merge_rejects_fragments_over_different_revisions(tmp_path):
    expand = _expand()
    expand["target"]["revision"] = "b" * 40
    result, _, _ = _merge(tmp_path, _seed(), expand)
    assert result.returncode == 1
    assert "fragments disagree on target" in result.stderr


def test_merge_revalidates_what_the_union_produced(tmp_path):
    """Two fragments that each validate can still merge into an invalid graph: the
    `requires` union can open a shortcut that makes an EXPAND route droppable."""
    expand = _seed()
    expand["nodes"].append(
        _fn("N-exfil", "bulk export", ["N-resolve-share"],
            "evidence/alt.txt#L2", "recovered victim", symbol="ExportController.bulk")
    )
    _node(expand, "N-obj")["requires"] = ["N-exfil"]
    path = _path(expand, "PATH-pov")
    path["id"] = "PATH-alt"
    path["nodes"].insert(-1, "N-exfil")
    expand["observed_cuts"][0]["blocked"][0]["path"] = "PATH-alt"
    result, out, _ = _merge(tmp_path, _seed(), expand)
    assert result.returncode == 1
    assert "merged: path PATH-alt still reaches N-obj without" in result.stderr
    assert not out.exists(), "an invalid merge must not be written"


def test_a_refutation_needs_a_reason(tmp_path):
    """A reasonless refusal would satisfy the on-the-record contract vacuously."""
    result, _, _ = _merge(tmp_path, _seed(), _expand(), "--refute", "PATH-alt=")
    assert result.returncode == 1
    assert "needs PATH-ID=REASON" in result.stderr


def test_merge_rejects_a_node_the_fragments_identify_differently(tmp_path):
    expand = _expand()
    _node(expand, "N-obj")["store"] = "some_other_store"
    result, _, _ = _merge(tmp_path, _seed(), expand)
    assert result.returncode == 1
    assert "fragments disagree on node N-obj: store" in result.stderr


def test_seeds_declaration_wins_where_the_fragments_may_differ(tmp_path):
    """EXPAND redeclares shared nodes to validate standalone, and legitimately
    cites its own evidence line for a node it reaches another way."""
    expand = _expand()
    _node(expand, "N-entry")["title"] = "Baseline principal, reached the other way"
    result, out, _ = _merge(tmp_path, _seed(), expand)
    assert result.returncode == 0, result.stderr
    assert _node(json.loads(out.read_text()), "N-entry")["title"] == "Baseline principal"


def test_two_cut_ids_may_not_record_one_defense(tmp_path):
    """Split ids give one defense two readings: the id holding only the blocked
    routes reads terminal, for a defense a recorded route escaped. Validated
    rather than merged, because the no-agents path writes graph.json directly."""
    def mutate(graph):
        second = json.loads(json.dumps(graph["observed_cuts"][0]))
        second["id"] = "CUT-upstream-2"
        graph["observed_cuts"].append(second)
    _fails(tmp_path, mutate, "record the same defense 'upstream_fix'")


def test_expand_must_name_the_function_it_introduces(tmp_path):
    """Without a symbol the duplicate-node guard has nothing to compare, and one
    application function under two ids reads as two routes sharing nothing."""
    expand = _expand()
    del _node(expand, "N-upload-template")["symbol"]
    result, _, _ = _merge(tmp_path, _seed(), expand)
    assert result.returncode == 1
    assert "EXPAND function N-upload-template must declare symbol" in result.stderr


def test_a_refutation_that_empties_a_cut_records_the_drop(tmp_path):
    expand = _expand()
    expand["observed_cuts"] = [
        {
            "id": "CUT-config",
            "reference": "config_toggle",
            "blocked": [],
            "survived": [
                _cite("evidence/fixed-alt.txt#L1", "recovered victim") | {"path": "PATH-alt"}
            ],
        }
    ]
    result, out, record = _merge(tmp_path, _seed(), expand, "--refute", "PATH-alt=unproven")
    assert result.returncode == 0, result.stderr
    assert json.loads(record.read_text())["cuts_dropped"] == ["CUT-config"]
    assert [c["id"] for c in json.loads(out.read_text())["observed_cuts"]] == ["CUT-upstream"]


def test_an_explicit_requires_all_false_is_not_a_disagreement(tmp_path):
    """Writing the default out is semantically identical to omitting it."""
    expand = _expand()
    _node(expand, "N-obj")["requires_all"] = False
    result, _, _ = _merge(tmp_path, _seed(), expand)
    assert result.returncode == 0, result.stderr


def test_the_record_names_which_fragment_was_which(tmp_path):
    """Every other field is relative to whichever fragment was passed first."""
    _, _, record = _merge(tmp_path, _seed(), _expand())
    written = json.loads(record.read_text())
    assert written["seed"].endswith("seed.json")
    assert written["expand"].endswith("expand.json")


def test_merge_rejects_two_defenses_sharing_one_cut_id(tmp_path):
    """Without this the EXPAND reference is silently discarded and two different
    defenses collapse into one cut."""
    expand = _expand()
    expand["observed_cuts"][0]["reference"] = "config_toggle"
    result, _, _ = _merge(tmp_path, _seed(), expand)
    assert result.returncode == 1
    assert "fragments disagree on the reference of cut CUT-upstream" in result.stderr


def test_a_symbol_cannot_break_the_rendered_table(tmp_path):
    """`symbol` became mandatory on every function node, so it is the cell most
    likely to carry a pipe: unescaped it adds a phantom column."""
    graph = _graph()
    _node(graph, "N-create-share")["symbol"] = 'Router.match GET /a|/b "x"'
    rows = [
        line for line in _render(tmp_path, graph).splitlines()
        if line.startswith("| N-create-share |")
    ]
    assert len(rows) == 1
    assert rows[0].count("|") == 5, rows[0]
