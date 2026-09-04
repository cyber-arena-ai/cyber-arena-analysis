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
    evidence_dir = tmp_path / "study" / "evidence"
    evidence_dir.mkdir(parents=True)
    for name, body in EVIDENCE.items():
        (evidence_dir / name).write_text(body, encoding="utf-8")
    return tmp_path / "study"


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
    out = tmp_path / "analysis.json"
    result = subprocess.run(
        [sys.executable, str(SCRIPTS / "graph_analyze.py"), str(_write(tmp_path, graph)),
         "--out", str(out)],
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
    graph["operations"][0]["evidence"]["locator"] = "../secret.txt#L1"
    result = _validate(tmp_path, graph)
    assert result.returncode == 1
    assert "stay inside" in result.stderr


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
    result = subprocess.run(
        [sys.executable, str(SCRIPTS / "graph_render.py"), str(_write(tmp_path, _graph())),
         "--out", str(out)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    rendered = out.read_text(encoding="utf-8")
    assert "```mermaid" in rendered
    assert "linkStyle" in rendered
    assert "contestable_observed" in rendered


def test_untested_path_appears_on_the_frontier(tmp_path):
    graph = _graph()
    graph["observed_cuts"][0]["survived"] = []
    analysis = _analyze(tmp_path, graph)
    assert {"kind": "untested_path", "target": "PATH-alt"} in analysis["frontier"]
    assert analysis["observed_cuts"][0]["reading"] == "terminal_over_recorded_subgraph"
