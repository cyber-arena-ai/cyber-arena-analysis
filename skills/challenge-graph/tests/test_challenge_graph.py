import json
import subprocess
import sys
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
REVISION = "a" * 40

EVIDENCE = {
    "pov.txt": "201 Created share=7f2a\nrecovered victim report body\n",
    "alt.txt": "201 Created template=t9\nrecovered victim report body\n",
    "fixed-pov.txt": "403 Forbidden\n",
    "fixed-alt.txt": "recovered victim report body\n",
}


def _evidence(kind, locator, observed):
    return {"kind": kind, "locator": locator, "observed": observed}


def _graph():
    return {
        "schema_version": 1,
        "target": {"id": "acme-reports", "repository": "acme/reports", "revision": REVISION},
        "evidence_root": "evidence",
        "states": [
            {"id": "ST-entry", "role": "entry", "title": "Baseline principal"},
            {"id": "ST-token", "role": "intermediate", "title": "Share token"},
            {"id": "ST-template", "role": "intermediate", "title": "Stored template"},
            {
                "id": "ST-obj",
                "role": "objective",
                "store": "report_store",
                "scope": "app.cross_boundary.read",
            },
        ],
        "operations": [
            {
                "id": "OP-create-share",
                "title": "create share link",
                "requires": ["ST-entry"],
                "produces": ["ST-token"],
                "counts_as_operation": True,
                "evidence": _evidence("reproduced", "evidence/pov.txt#L1", "201 Created share"),
            },
            {
                "id": "OP-resolve-share",
                "title": "resolve share link",
                "requires": ["ST-token"],
                "produces": ["ST-obj"],
                "counts_as_operation": True,
                "evidence": _evidence("reproduced", "evidence/pov.txt#L2", "recovered victim"),
            },
            {
                "id": "OP-upload-template",
                "title": "upload template",
                "requires": ["ST-entry"],
                "produces": ["ST-template"],
                "counts_as_operation": True,
                "evidence": _evidence("reproduced", "evidence/alt.txt#L1", "201 Created template"),
            },
            {
                "id": "OP-render-template",
                "title": "render template",
                "requires": ["ST-template"],
                "produces": ["ST-obj"],
                "counts_as_operation": True,
                "evidence": _evidence("reproduced", "evidence/alt.txt#L2", "recovered victim"),
            },
        ],
        "paths": [
            {
                "id": "PATH-pov",
                "objective": "ST-obj",
                "operations": ["OP-create-share", "OP-resolve-share"],
                "advisory_backed": True,
                "evidence": _evidence("reproduced", "evidence/pov.txt#L2", "recovered victim"),
            },
            {
                "id": "PATH-alt",
                "objective": "ST-obj",
                "operations": ["OP-upload-template", "OP-render-template"],
                "advisory_backed": False,
                "evidence": _evidence("reproduced", "evidence/alt.txt#L2", "recovered victim"),
            },
        ],
        "observed_cuts": [
            {
                "id": "CUT-upstream",
                "reference": "upstream_fix",
                "blocked": [
                    {
                        "path": "PATH-pov",
                        "locator": "evidence/fixed-pov.txt#L1",
                        "observed": "403 Forbidden",
                    }
                ],
                "survived": [
                    {
                        "path": "PATH-alt",
                        "locator": "evidence/fixed-alt.txt#L1",
                        "observed": "recovered victim",
                    }
                ],
            }
        ],
    }


def _study(tmp_path):
    study = tmp_path / "study"
    (study / "evidence").mkdir(parents=True, exist_ok=True)
    for name, body in EVIDENCE.items():
        (study / "evidence" / name).write_text(body, encoding="utf-8")
    (study / "STAGE3_STUDY.md").write_text("recovered victim report body\n", encoding="utf-8")
    (study / "result.json").write_text('{"repository": "acme/reports"}\n', encoding="utf-8")
    return study


def _write(tmp_path, graph):
    path = tmp_path / "graph.json"
    path.write_text(json.dumps(graph, indent=2) + "\n", encoding="utf-8")
    return path


def _validate(tmp_path, graph):
    study = _study(tmp_path)
    return subprocess.run(
        [sys.executable, str(SCRIPTS / "graph_validate.py"), str(_write(tmp_path, graph)),
         "--study-dir", str(study)],
        capture_output=True,
        text=True,
    )


def _analyze(tmp_path, graph):
    out = tmp_path / "derived" / "analysis.json"
    study = _study(tmp_path)
    result = subprocess.run(
        [sys.executable, str(SCRIPTS / "graph_analyze.py"), str(_write(tmp_path, graph)),
         "--out", str(out), "--study-dir", str(study)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    return json.loads(out.read_text(encoding="utf-8"))


def test_recorded_graph_validates(tmp_path):
    assert _validate(tmp_path, _graph()).returncode == 0


def test_observed_string_must_be_on_the_cited_line(tmp_path):
    graph = _graph()
    graph["operations"][0]["evidence"]["observed"] = "never printed this"
    result = _validate(tmp_path, graph)
    assert result.returncode == 1
    assert "observed string is not on" in result.stderr


def test_hypothesis_evidence_cannot_enter_the_graph(tmp_path):
    graph = _graph()
    graph["paths"][0]["evidence"]["kind"] = "hypothesis"
    result = _validate(tmp_path, graph)
    assert result.returncode == 1
    assert "hypothesis" in result.stderr


def test_path_operations_must_chain(tmp_path):
    graph = _graph()
    graph["operations"][1]["requires"] = ["ST-template"]
    result = _validate(tmp_path, graph)
    assert result.returncode == 1
    assert "does not chain" in result.stderr


def test_locator_cannot_leave_the_evidence_root(tmp_path):
    graph = _graph()
    graph["operations"][0]["evidence"]["locator"] = "elsewhere/secret.txt#L1"
    result = _validate(tmp_path, graph)
    assert result.returncode == 1
    assert "evidence" in result.stderr


def test_locator_cannot_traverse_out_of_the_study(tmp_path):
    graph = _graph()
    graph["operations"][0]["evidence"]["locator"] = "../secret.txt#L1"
    assert _validate(tmp_path, graph).returncode == 1


def test_path_must_terminate_at_its_objective(tmp_path):
    graph = _graph()
    graph["operations"][1]["produces"] = ["ST-template"]
    result = _validate(tmp_path, graph)
    assert result.returncode == 1
    assert "does not terminate" in result.stderr


def test_two_independent_paths_read_as_disjoint_and_contestable(tmp_path):
    analysis = _analyze(tmp_path, _graph())
    assert analysis["geometry"] == ["disjoint"]
    assert analysis["mincut_all"] == 2
    observed = analysis["observed_cuts"][0]
    assert observed["reading"] == "contestable_observed"
    assert observed["implicated_operations"] == ["OP-create-share", "OP-resolve-share"]


def test_shared_operation_reads_as_fan_in_not_contestable(tmp_path):
    graph = _graph()
    graph["operations"][2]["produces"] = ["ST-token"]
    graph["paths"][1]["operations"] = ["OP-upload-template", "OP-resolve-share"]
    analysis = _analyze(tmp_path, graph)
    assert "fan_in" in analysis["geometry"]
    assert analysis["mincut_all"] == 1


def test_shallow_path_is_labelled_rather_than_rejected(tmp_path):
    graph = _graph()
    graph["operations"][1]["requires"] = ["ST-entry"]
    graph["paths"][0]["operations"] = ["OP-resolve-share"]
    assert _validate(tmp_path, graph).returncode == 0
    analysis = _analyze(tmp_path, graph)
    assert "shallow" in analysis["geometry"]
    assert analysis["nontrivial_paths"]["PATH-pov"] is False


def test_survived_cut_leaves_a_solid_route_in_the_diagram(tmp_path):
    out = tmp_path / "graph.md"
    study = _study(tmp_path)
    result = subprocess.run(
        [sys.executable, str(SCRIPTS / "graph_render.py"), str(_write(tmp_path, _graph())),
         "--out", str(out), "--study-dir", str(study)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    rendered = out.read_text(encoding="utf-8")
    assert "```mermaid" in rendered
    assert "contestable_observed" in rendered
    # Only the blocked route is dashed: the surviving route must stay solid,
    # which is the whole point of the picture.
    edges = [l for l in rendered.splitlines() if "-->" in l]
    dashed = [l for l in rendered.splitlines() if l.strip().startswith("linkStyle")]
    assert len(edges) == 8
    assert len(dashed) == 4


def test_untested_path_appears_on_the_frontier(tmp_path):
    graph = _graph()
    graph["observed_cuts"][0]["survived"] = []
    analysis = _analyze(tmp_path, graph)
    assert {"kind": "untested_path", "target": "PATH-alt"} in analysis["frontier"]
    assert analysis["observed_cuts"][0]["reading"] == "terminal_over_recorded_subgraph"


# --- guards the first round of review found unproven -------------------------


def _fails(tmp_path, mutate, needle):
    graph = _graph()
    mutate(graph)
    result = _validate(tmp_path, graph)
    assert result.returncode == 1, result.stdout
    assert needle in result.stderr, result.stderr


def test_study_dir_must_be_a_real_stage3_study(tmp_path):
    scratch = tmp_path / "scratch" / "evidence"
    scratch.mkdir(parents=True)
    for name, body in EVIDENCE.items():
        (scratch / name).write_text(body, encoding="utf-8")
    result = subprocess.run(
        [sys.executable, str(SCRIPTS / "graph_validate.py"), str(_write(tmp_path, _graph())),
         "--study-dir", str(tmp_path / "scratch")],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1
    assert "not a Stage 3 study" in result.stderr


def test_evidence_root_cannot_be_the_study_itself(tmp_path):
    def mutate(graph):
        graph["evidence_root"] = "."
        graph["operations"][0]["evidence"]["locator"] = "STAGE3_STUDY.md#L1"
        graph["operations"][0]["evidence"]["observed"] = "recovered victim report body"
    _fails(tmp_path, mutate, "evidence_root")


def test_observed_must_quote_enough_to_identify_the_output(tmp_path):
    _fails(tmp_path, lambda g: g["operations"][0]["evidence"].update(observed="2"), "at least")


def test_symlinked_evidence_cannot_read_outside_the_study(tmp_path):
    study = _study(tmp_path)
    outside = tmp_path / "outside.txt"
    outside.write_text("recovered victim report body\n", encoding="utf-8")
    (study / "evidence" / "link.txt").symlink_to(outside)
    graph = _graph()
    graph["operations"][0]["evidence"] = _evidence(
        "reproduced", "evidence/link.txt#L1", "recovered victim"
    )
    result = subprocess.run(
        [sys.executable, str(SCRIPTS / "graph_validate.py"), str(_write(tmp_path, graph)),
         "--study-dir", str(study)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1
    assert "outside" in result.stderr


def test_unknown_state_id_reports_an_error_rather_than_crashing(tmp_path):
    result = _validate(tmp_path, {**_graph(), "operations": [
        {**op, "requires": ["ST-typo"]} if op["id"] == "OP-create-share" else op
        for op in _graph()["operations"]
    ]})
    assert result.returncode == 1
    assert "unknown state" in result.stderr
    assert "Traceback" not in result.stderr


def test_malformed_requires_reports_an_error_rather_than_crashing(tmp_path):
    result = _validate(tmp_path, {**_graph(), "operations": [
        {**op, "requires": "ST-entry"} if op["id"] == "OP-create-share" else op
        for op in _graph()["operations"]
    ]})
    assert result.returncode == 1
    assert "Traceback" not in result.stderr


def test_cycles_are_rejected(tmp_path):
    def mutate(graph):
        graph["operations"][0]["produces"] = ["ST-token", "ST-entry"]
    _fails(tmp_path, mutate, "acyclic")


def test_duplicate_ids_are_rejected(tmp_path):
    _fails(tmp_path, lambda g: g["states"].append(g["states"][0]), "unique string id")


def test_objective_must_declare_its_scope(tmp_path):
    _fails(tmp_path, lambda g: g["states"][3].pop("scope"), "must declare scope")


def test_cut_must_record_a_blocked_path(tmp_path):
    _fails(tmp_path, lambda g: g["observed_cuts"][0].update(blocked=[]), "at least one path")


def test_cut_cannot_list_one_path_as_both_blocked_and_survived(tmp_path):
    def mutate(graph):
        graph["observed_cuts"][0]["survived"] = [
            {"path": "PATH-pov", "locator": "evidence/fixed-alt.txt#L1", "observed": "recovered victim"}
        ]
    _fails(tmp_path, mutate, "twice")


def test_fabricated_cut_evidence_is_rejected(tmp_path):
    def mutate(graph):
        graph["observed_cuts"][0]["blocked"][0]["observed"] = "500 Internal Server Error"
    _fails(tmp_path, mutate, "observed string is not on")


def test_unregistered_objective_scope_is_rejected(tmp_path):
    registry = tmp_path / "scopes.json"
    registry.write_text(json.dumps([{"id": "app.cross_boundary.write"}]), encoding="utf-8")
    graph = _graph()
    result = subprocess.run(
        [sys.executable, str(SCRIPTS / "graph_validate.py"), str(_write(tmp_path, graph)),
         "--study-dir", str(_study(tmp_path)), "--scope-registry", str(registry)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1
    assert "not registered" in result.stderr


def test_two_counted_operations_need_an_intermediate_state_between_them(tmp_path):
    """One request split in two is not a nontrivial chain."""
    graph = _graph()
    graph["states"][1]["role"] = "entry"
    analysis = _analyze(tmp_path, graph)
    assert analysis["nontrivial_paths"]["PATH-pov"] is False
    assert "shallow" in analysis["geometry"]


def test_shallow_path_cannot_manufacture_disjoint_geometry(tmp_path):
    graph = _graph()
    graph["operations"].append({
        "id": "OP-direct", "title": "direct read", "requires": ["ST-entry"],
        "produces": ["ST-obj"], "counts_as_operation": True,
        "evidence": _evidence("reproduced", "evidence/alt.txt#L2", "recovered victim"),
    })
    graph["paths"].append({
        "id": "PATH-short", "objective": "ST-obj", "operations": ["OP-direct"],
        "evidence": _evidence("reproduced", "evidence/alt.txt#L2", "recovered victim"),
    })
    analysis = _analyze(tmp_path, graph)
    assert analysis["geometry"] == ["shallow"]
    assert analysis["mincut_nontrivial"] == 2


def test_a_wide_disjoint_graph_still_reports_its_mincut(tmp_path):
    """Five disjoint paths must not fall off the end of the cut search."""
    graph = _graph()
    graph["states"] = graph["states"][:1] + [graph["states"][3]]
    graph["operations"] = []
    graph["paths"] = []
    graph["observed_cuts"] = []
    for index in range(5):
        mid = f"ST-mid-{index}"
        graph["states"].append({"id": mid, "role": "intermediate", "title": f"step {index}"})
        graph["operations"] += [
            {"id": f"OP-a{index}", "requires": ["ST-entry"], "produces": [mid],
             "counts_as_operation": True,
             "evidence": _evidence("reproduced", "evidence/alt.txt#L1", "201 Created template")},
            {"id": f"OP-b{index}", "requires": [mid], "produces": ["ST-obj"],
             "counts_as_operation": True,
             "evidence": _evidence("reproduced", "evidence/alt.txt#L2", "recovered victim")},
        ]
        graph["paths"].append({
            "id": f"PATH-{index}", "objective": "ST-obj",
            "operations": [f"OP-a{index}", f"OP-b{index}"],
            "evidence": _evidence("reproduced", "evidence/alt.txt#L2", "recovered victim"),
        })
    analysis = _analyze(tmp_path, graph)
    assert analysis["mincut_all"] == 5
    assert "disjoint" in analysis["geometry"]


def test_implicated_operations_exclude_uncuttable_steps(tmp_path):
    graph = _graph()
    graph["operations"].insert(0, {
        "id": "OP-login", "title": "authenticate", "requires": ["ST-entry"],
        "produces": ["ST-session"], "counts_as_operation": False,
        "evidence": _evidence("reproduced", "evidence/pov.txt#L1", "201 Created share"),
    })
    graph["states"].append({"id": "ST-session", "role": "intermediate", "title": "session"})
    graph["operations"][1]["requires"] = ["ST-session"]
    graph["paths"][0]["operations"] = ["OP-login", "OP-create-share", "OP-resolve-share"]
    analysis = _analyze(tmp_path, graph)
    assert "OP-login" not in analysis["observed_cuts"][0]["implicated_operations"]


def test_malformed_json_reports_an_error_rather_than_crashing(tmp_path):
    bad = tmp_path / "graph.json"
    bad.write_text("{not json", encoding="utf-8")
    result = subprocess.run(
        [sys.executable, str(SCRIPTS / "graph_validate.py"), str(bad),
         "--study-dir", str(_study(tmp_path))],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1
    assert "not valid JSON" in result.stderr
    assert "Traceback" not in result.stderr


def _second_objective(graph):
    graph["states"].append({
        "id": "ST-obj2", "role": "objective",
        "store": "config_store", "scope": "app.privileged.control",
    })
    return graph


def test_one_operation_reaching_two_objectives_reads_as_fan_out(tmp_path):
    graph = _second_objective(_graph())
    graph["operations"][3]["produces"] = ["ST-obj", "ST-obj2"]
    graph["paths"].append({
        "id": "PATH-second", "objective": "ST-obj2",
        "operations": ["OP-upload-template", "OP-render-template"],
        "evidence": _evidence("reproduced", "evidence/alt.txt#L2", "recovered victim"),
    })
    analysis = _analyze(tmp_path, graph)
    assert "fan_out" in analysis["geometry"]


def test_objective_with_no_path_lands_on_the_frontier(tmp_path):
    analysis = _analyze(tmp_path, _second_objective(_graph()))
    assert {"kind": "unreached_objective", "target": "ST-obj2"} in analysis["frontier"]
    assert analysis["objective_coverage"]["ST-obj2"]["mincut"] is None


def test_a_lone_path_is_labelled_single_path(tmp_path):
    graph = _graph()
    graph["paths"] = graph["paths"][:1]
    graph["observed_cuts"][0]["survived"] = []
    analysis = _analyze(tmp_path, graph)
    assert analysis["geometry"] == ["single_path"]
    assert analysis["mincut_all"] == 1


def test_more_cuts_than_the_listing_cap_are_reported_as_truncated(tmp_path):
    graph = _graph()
    graph["observed_cuts"] = []
    for index in range(5):
        mid = f"ST-extra-{index}"
        graph["states"].append({"id": mid, "role": "intermediate", "title": f"extra {index}"})
        graph["operations"] += [
            {"id": f"OP-x{index}", "requires": ["ST-entry"], "produces": [mid],
             "counts_as_operation": True,
             "evidence": _evidence("reproduced", "evidence/alt.txt#L1", "201 Created template")},
            {"id": f"OP-y{index}", "requires": [mid], "produces": ["ST-obj"],
             "counts_as_operation": True,
             "evidence": _evidence("reproduced", "evidence/alt.txt#L2", "recovered victim")},
        ]
        graph["paths"].append({
            "id": f"PATH-x{index}", "objective": "ST-obj",
            "operations": [f"OP-x{index}", f"OP-y{index}"],
            "evidence": _evidence("reproduced", "evidence/alt.txt#L2", "recovered victim"),
        })
    analysis = _analyze(tmp_path, graph)
    assert analysis["cuts_truncated"] is True
    assert len(analysis["minimum_cuts_all"]) == analysis["max_listed_cuts"]


def test_recorded_evidence_may_cite_the_study_document(tmp_path):
    """A study that retained no raw evidence tree can still be represented."""
    graph = _graph()
    graph.pop("evidence_root")
    for element in graph["operations"] + graph["paths"]:
        element["evidence"] = _evidence("recorded", "STAGE3_STUDY.md#L1", "recovered victim")
    for key in ("blocked", "survived"):
        for entry in graph["observed_cuts"][0][key]:
            entry.update(kind="recorded", locator="STAGE3_STUDY.md#L1", observed="recovered victim")
    assert _validate(tmp_path, graph).returncode == 0
    assert _analyze(tmp_path, graph)["evidence_strength"]["recorded_only"] is True


def test_raw_evidence_needs_a_declared_evidence_root(tmp_path):
    graph = _graph()
    graph.pop("evidence_root")
    result = _validate(tmp_path, graph)
    assert result.returncode == 1
    assert "no evidence_root" in result.stderr


def test_non_list_requires_reports_an_error_rather_than_crashing(tmp_path):
    for malformed in (5, None, {"a": 1}):
        graph = _graph()
        graph["operations"][0]["requires"] = malformed
        result = _validate(tmp_path, graph)
        assert result.returncode == 1, malformed
        assert "Traceback" not in result.stderr, (malformed, result.stderr)
        assert "must be a non-empty list" in result.stderr


def test_duplicate_observed_cut_ids_are_rejected(tmp_path):
    graph = _graph()
    graph["observed_cuts"].append(dict(graph["observed_cuts"][0]))
    result = _validate(tmp_path, graph)
    assert result.returncode == 1
    assert "unique string id" in result.stderr


def test_the_worked_example_is_structurally_valid():
    """The example SKILL.md tells authors to copy must not rot."""
    sys.path.insert(0, str(SCRIPTS))
    from _graph import structural_errors

    example = SCRIPTS.parent / "references/example-graph.json"
    document = json.loads(example.read_text(encoding="utf-8"))
    assert structural_errors(document) == []


def test_an_exhausted_cut_search_reports_unknown_rather_than_guessing():
    """An over-stated mincut would manufacture a false `disjoint` reading."""
    sys.path.insert(0, str(SCRIPTS))
    import _graph

    wide = [frozenset(f"OP-{p}-{o}" for o in range(6)) for p in range(12)]
    original = _graph.MAX_SEARCH_NODES
    try:
        _graph.MAX_SEARCH_NODES = 500
        cuts, size, truncated = _graph.minimal_cuts(wide)
    finally:
        _graph.MAX_SEARCH_NODES = original
    assert cuts == []
    assert size is None
    assert truncated is True
