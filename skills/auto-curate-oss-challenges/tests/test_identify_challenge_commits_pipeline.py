import hashlib
import json
import subprocess
import sys
import zipfile
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

from shortlist_candidates import InputError, generate  # noqa: E402
from compute_candidate_overlaps import generate as generate_overlaps  # noqa: E402
from resolve_git_windows import (  # noqa: E402
    refresh_repository,
    resolve_project,
    write_outputs,
)


def _record(identifier, published, commit, *, aliases=(), withdrawn=None):
    record = {
        "id": identifier,
        "aliases": list(aliases),
        "published": published,
        "summary": "Authorization bypass exposes protected application data",
        "affected": [
            {"package": {"ecosystem": "PyPI", "name": "example-app"}}
        ],
        "references": [
            {
                "type": "FIX",
                "url": f"https://github.com/example/app/commit/{commit}",
            }
        ],
    }
    if withdrawn:
        record["withdrawn"] = withdrawn
    return record


def _inputs(tmp_path):
    commits = [f"{number:040x}" for number in range(1, 7)]
    records = [
        _record("CVE-2025-0001", "2025-12-01T00:00:00Z", commits[0]),
        _record(
            "GHSA-aaaa-bbbb-cccc",
            "2026-03-01T00:00:00Z",
            commits[1],
            aliases=("CVE-2026-0001",),
        ),
        _record(
            "CVE-2026-0001",
            "2026-03-02T00:00:00Z",
            commits[1],
            aliases=("GHSA-aaaa-bbbb-cccc",),
        ),
        _record("CVE-2026-0002", "2026-04-01T00:00:00Z", commits[2]),
        _record(
            "CVE-2026-0003",
            "2026-04-02T00:00:00Z",
            commits[3],
            withdrawn="2026-04-03T00:00:00Z",
        ),
        {
            "id": "CVE-2026-0004",
            "published": "2026-04-04T00:00:00Z",
            "summary": "SQL injection",
            "affected": [
                {"package": {"ecosystem": "PyPI", "name": "example-app"}}
            ],
        },
    ]

    raw_dir = tmp_path / "raw"
    raw_dir.mkdir()
    archive_path = raw_dir / "PyPI.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        for index, record in enumerate(records):
            archive.writestr(f"record-{index}.json", json.dumps(record))

    manifest_path = tmp_path / "osv_manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "generated_at": "2026-05-01T00:00:00Z",
                "sources": [
                    {
                        "path": archive_path.name,
                        "bytes": archive_path.stat().st_size,
                        "sha256": hashlib.sha256(
                            archive_path.read_bytes()
                        ).hexdigest(),
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    projects_path = tmp_path / "projects.json"
    projects_path.write_text(
        json.dumps(
            {
                "generated_at": "2026-05-01T00:00:00Z",
                "projects": [
                    {
                        "repository": "example/app",
                        "url": "https://github.com/example/app",
                        "description": "Self-hosted network application",
                        "stars": 100_000,
                        "forks": 10_000,
                        "license": "MIT",
                        "archived": False,
                        "created_at": "2015-01-01T00:00:00Z",
                        "pushed_at": "2026-04-30T00:00:00Z",
                        "topics": ["self-hosted"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return projects_path, raw_dir, manifest_path, archive_path


def _generate(inputs, cutoff=None):
    projects, raw_dir, manifest, _ = inputs
    return generate(
        projects_path=projects,
        raw_dir=raw_dir,
        manifest_path=manifest,
        cutoff_value=cutoff,
    )


def test_date_cutoff_is_optional_and_aliases_do_not_double_count(tmp_path):
    inputs = _inputs(tmp_path)

    unfiltered = _generate(inputs)
    filtered = _generate(inputs, "2026-02-16T23:59:59Z")

    assert unfiltered["date_cutoff"]["enabled"] is False
    assert len(unfiltered["projects"][0]["components"]) == 3
    assert filtered["date_cutoff"] == {
        "enabled": True,
        "published_after": "2026-02-16T23:59:59+00:00",
        "comparison": "earliest active OSV publication is strictly later",
    }
    assert [
        component["component_id"]
        for component in filtered["projects"][0]["components"]
    ] == ["CVE-2026-0001", "CVE-2026-0002"]
    assert filtered["summary"]["withdrawn_osv_records"] == 1
    assert filtered["summary"]["priority_projects"] == 1


def test_manifest_hash_mismatch_fails_closed(tmp_path):
    inputs = _inputs(tmp_path)
    inputs[3].write_bytes(inputs[3].read_bytes() + b"tampered")

    try:
        _generate(inputs)
    except InputError as error:
        assert "size mismatch" in str(error)
    else:
        raise AssertionError("tampered input was accepted")


def test_shortlist_rejects_inactive_projects(tmp_path):
    projects, raw_dir, manifest, _ = _inputs(tmp_path)
    payload = json.loads(projects.read_text(encoding="utf-8"))
    payload["projects"][0]["pushed_at"] = "2020-01-01T00:00:00Z"
    projects.write_text(json.dumps(payload), encoding="utf-8")

    result = generate(
        projects_path=projects,
        raw_dir=raw_dir,
        manifest_path=manifest,
        cutoff_value=None,
    )

    assert result["projects"] == []
    assert result["summary"]["hard_gate_exclusions"]["inactive_project"] == 3


def test_shortlist_rejects_components_without_behavioral_evidence(tmp_path):
    inputs = _inputs(tmp_path)
    projects, raw_dir, manifest, archive_path = inputs
    sparse = _record(
        "CVE-2026-0999",
        "2026-04-10T00:00:00Z",
        "9" * 40,
    )
    sparse["summary"] = ""
    with zipfile.ZipFile(archive_path, "a") as archive:
        archive.writestr("sparse.json", json.dumps(sparse))
    manifest_payload = json.loads(manifest.read_text(encoding="utf-8"))
    manifest_payload["sources"][0].update(
        {
            "bytes": archive_path.stat().st_size,
            "sha256": hashlib.sha256(archive_path.read_bytes()).hexdigest(),
        }
    )
    manifest.write_text(json.dumps(manifest_payload), encoding="utf-8")

    result = generate(
        projects_path=projects,
        raw_dir=raw_dir,
        manifest_path=manifest,
        cutoff_value=None,
    )

    assert result["summary"]["hard_gate_exclusions"] == {
        "no_behavioral_evidence": 1
    }
    assert "CVE-2026-0999" not in {
        item["component_id"] for item in result["projects"][0]["components"]
    }


def test_withdrawn_record_can_bridge_active_aliases_without_being_retained(tmp_path):
    projects, raw_dir, manifest, archive_path = _inputs(tmp_path)
    records = [
        _record(
            "CVE-2026-0101",
            "2026-04-10T00:00:00Z",
            "7" * 40,
            aliases=("BRIDGE-A",),
        ),
        {
            "id": "BRIDGE-A",
            "aliases": ["BRIDGE-B"],
            "published": "2026-04-10T00:00:00Z",
            "withdrawn": "2026-04-11T00:00:00Z",
        },
        _record(
            "CVE-2026-0102",
            "2026-04-12T00:00:00Z",
            "8" * 40,
            aliases=("BRIDGE-B",),
        ),
    ]
    with zipfile.ZipFile(archive_path, "a") as archive:
        for index, record in enumerate(records):
            archive.writestr(f"bridge-{index}.json", json.dumps(record))
    manifest_payload = json.loads(manifest.read_text(encoding="utf-8"))
    manifest_payload["sources"][0].update(
        {
            "bytes": archive_path.stat().st_size,
            "sha256": hashlib.sha256(archive_path.read_bytes()).hexdigest(),
        }
    )
    manifest.write_text(json.dumps(manifest_payload), encoding="utf-8")

    result = generate(
        projects_path=projects,
        raw_dir=raw_dir,
        manifest_path=manifest,
        cutoff_value="2026-02-16T23:59:59Z",
    )
    bridged = [
        item
        for item in result["projects"][0]["components"]
        if "CVE-2026-0101" in item["ids"] or "CVE-2026-0102" in item["ids"]
    ]

    assert len(bridged) == 1
    assert {"CVE-2026-0101", "CVE-2026-0102"}.issubset(bridged[0]["ids"])
    assert result["summary"]["withdrawn_osv_records"] == 2


def test_batch_overlap_uses_hard_gate_components_before_semantics(tmp_path):
    raw_dir = tmp_path / "raw"
    raw_dir.mkdir()
    records = [
        {
            "id": "CVE-2026-1001",
            "published": "2026-03-01T00:00:00Z",
            "summary": "First boundary",
            "affected": [
                {
                    "package": {"ecosystem": "PyPI", "name": "example-app"},
                    "versions": ["1.0", "1.1"],
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [{"introduced": "1.0"}, {"fixed": "1.2"}],
                        },
                        {
                            "type": "GIT",
                            "repo": "https://github.com/example/app",
                            "events": [
                                {"introduced": "a" * 40},
                                {"fixed": "b" * 40},
                            ],
                        }
                    ],
                }
            ],
        },
        {
            "id": "CVE-2026-1002",
            "published": "2026-03-02T00:00:00Z",
            "summary": "Second boundary",
            "affected": [
                {
                    "package": {"ecosystem": "PyPI", "name": "example-app"},
                    "versions": ["1.1"],
                }
            ],
        },
    ]
    with zipfile.ZipFile(raw_dir / "PyPI.zip", "w") as archive:
        for index, record in enumerate(records):
            archive.writestr(f"record-{index}.json", json.dumps(record))

    def component(identifier, priority):
        return {
            "component_id": identifier,
            "ids": [identifier],
            "earliest_osv_publication": "2026-03-01T00:00:00+00:00",
            "summaries": [identifier],
            "fixes": [
                {
                    "sha": f"{int(identifier[-1]):040x}",
                    "source": "reference_fix",
                    "url": "https://github.com/example/app/commit/" + "1" * 40,
                }
            ],
            "priority": priority,
        }

    candidates_path = tmp_path / "candidates.json"
    candidates_path.write_text(
        json.dumps(
            {
                "date_cutoff": {
                    "enabled": True,
                    "published_after": "2026-02-16T23:59:59+00:00",
                },
                "priority_projects": [],
                "projects": [
                    {
                        "repository": "example/app",
                        "project": {"description": "Example application"},
                        "components": [
                            component("CVE-2026-1001", False),
                            component("CVE-2026-1002", True),
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    result = generate_overlaps(candidates_path=candidates_path, raw_dir=raw_dir)
    project = result["projects"][0]
    lane = project["lanes"][0]

    assert result["component_count"] == 2
    assert project["project"] == {"description": "Example application"}
    assert lane["affected_unit"] == "PyPI:example-app"
    assert lane["selection"]["maximum_count"] == 2
    assert lane["selection"]["maximal_checkpoints"] == ["1.1"]
    assert lane["provisional_semantic_review_components"] == [
        "CVE-2026-1001",
        "CVE-2026-1002",
    ]
    assert lane["range_evaluation_required_at_maxima"] == []
    assert lane["components_with_unevaluated_ranges"] == ["CVE-2026-1001"]
    assert project["components"][0]["project_git_ranges"] == [
        {
            "repo": "https://github.com/example/app",
            "events": [{"introduced": "a" * 40}, {"fixed": "b" * 40}],
        }
    ]
    assert lane["maximal_component_groups"] == [
        {
            "component_ids": ["CVE-2026-1001", "CVE-2026-1002"],
            "checkpoint_count": 1,
            "checkpoints": ["1.1"],
        }
    ]

    candidates = json.loads(candidates_path.read_text(encoding="utf-8"))
    second = json.loads(json.dumps(candidates["projects"][0]))
    second["repository"] = "example/second"
    candidates["projects"].append(second)
    candidates_path.write_text(json.dumps(candidates), encoding="utf-8")

    scoped = generate_overlaps(
        candidates_path=candidates_path,
        raw_dir=raw_dir,
        repository="example/app",
    )
    assert [item["repository"] for item in scoped["projects"]] == ["example/app"]


def test_git_range_resolution_finds_immutable_maximum(tmp_path):
    repository = tmp_path / "repository"
    subprocess.run(["git", "init", "-q", str(repository)], check=True)
    subprocess.run(
        ["git", "-C", str(repository), "config", "user.email", "test@example.com"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(repository), "config", "user.name", "Test"],
        check=True,
    )

    commits = []
    for value in ("root", "vulnerable", "fix-a", "fix-b"):
        (repository / "state.txt").write_text(value, encoding="utf-8")
        subprocess.run(["git", "-C", str(repository), "add", "state.txt"], check=True)
        subprocess.run(
            ["git", "-C", str(repository), "commit", "-q", "-m", value],
            check=True,
        )
        commits.append(
            subprocess.run(
                ["git", "-C", str(repository), "rev-parse", "HEAD"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
        )

    def component(identifier, fixed):
        return {
            "component_id": identifier,
            "ids": [identifier],
            "summaries": [identifier],
            "fixes": [],
            "project_git_ranges": [
                {
                    "repo": "https://github.com/example/app",
                    "events": [{"introduced": "0"}, {"fixed": fixed}],
                }
            ],
        }

    result = resolve_project(
        {
            "repository": "example/app",
            "components": [
                component("CVE-2026-1001", commits[2]),
                component("CVE-2026-1002", commits[3]),
            ],
        },
        repository,
    )

    assert result["maximum_reported_overlap"] == 2
    assert [
        window["component_ids"] for window in result["candidate_windows"]
    ] == [
        ["CVE-2026-1001", "CVE-2026-1002"],
        ["CVE-2026-1002"],
    ]
    assert result["head_reference"]["snapshot_limited_no_known_applicable_issue"]

    output_dir = tmp_path / "output"
    write_outputs([result], output_dir)
    packet = json.loads(
        (output_dir / "semantic_packets" / "EXAMPLE__APP.json").read_text(
            encoding="utf-8"
        )
    )
    assert packet["schema_version"] == 2
    assert packet["ready_for_semantic_review"] is True
    assert len(packet["candidate_windows"]) == 2
    assert "checkpoints" not in packet["candidate_windows"][0]
    assert packet["source_result"]["sha256"] == hashlib.sha256(
        (output_dir / "EXAMPLE__APP.json").read_bytes()
    ).hexdigest()
    assert {item["component_id"] for item in packet["components"]} == {
        "CVE-2026-1001",
        "CVE-2026-1002",
    }


def test_repository_refresh_updates_the_recorded_default_branch(tmp_path):
    upstream = tmp_path / "upstream"
    subprocess.run(["git", "init", "-q", str(upstream)], check=True)
    subprocess.run(
        ["git", "-C", str(upstream), "config", "user.email", "test@example.com"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(upstream), "config", "user.name", "Test"], check=True
    )
    (upstream / "state.txt").write_text("one", encoding="utf-8")
    subprocess.run(["git", "-C", str(upstream), "add", "state.txt"], check=True)
    subprocess.run(["git", "-C", str(upstream), "commit", "-qm", "one"], check=True)

    cache = tmp_path / "cache.git"
    subprocess.run(["git", "clone", "-q", "--bare", str(upstream), str(cache)], check=True)
    (upstream / "state.txt").write_text("two", encoding="utf-8")
    subprocess.run(["git", "-C", str(upstream), "add", "state.txt"], check=True)
    subprocess.run(["git", "-C", str(upstream), "commit", "-qm", "two"], check=True)
    expected = subprocess.run(
        ["git", "-C", str(upstream), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()

    refreshed_ref = refresh_repository(cache)

    observed = subprocess.run(
        ["git", "-C", str(cache), "rev-parse", refreshed_ref],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    assert observed == expected


def test_git_resolver_rejects_unresolved_ranges(tmp_path):
    repository = tmp_path / "repository"
    subprocess.run(["git", "init", "-q", str(repository)], check=True)
    subprocess.run(
        ["git", "-C", str(repository), "config", "user.email", "test@example.com"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(repository), "config", "user.name", "Test"],
        check=True,
    )

    commits = []
    for content in ("vulnerable\n", "fixed\n", "after\n"):
        (repository / "state.txt").write_text(content, encoding="utf-8")
        subprocess.run(["git", "-C", str(repository), "add", "state.txt"], check=True)
        subprocess.run(
            ["git", "-C", str(repository), "commit", "-q", "-m", content.strip()],
            check=True,
        )
        commits.append(
            subprocess.run(
                ["git", "-C", str(repository), "rev-parse", "HEAD"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
        )

    def component(identifier, fixed):
        return {
            "component_id": identifier,
            "references": [],
            "project_git_ranges": [
                {
                    "repo": "https://github.com/example/app",
                    "events": [{"introduced": "0"}, {"fixed": fixed}],
                }
            ],
        }

    last_affected = {
        "component_id": "last-affected",
        "project_git_ranges": [
            {
                "repo": "https://github.com/example/app",
                "events": [
                    {"introduced": "0"},
                    {"fixed": commits[1]},
                    {"introduced": commits[1]},
                    {"last_affected": commits[1]},
                ],
            }
        ],
    }

    result = resolve_project(
        {
            "repository": "example/app",
            "components": [
                component("resolved", commits[1]),
                last_affected,
                {
                    "component_id": "invalid-topology",
                    "project_git_ranges": [
                        {
                            "repo": "https://github.com/example/app",
                            "events": [
                                {"introduced": commits[2]},
                                {"fixed": commits[1]},
                            ],
                        }
                    ],
                },
                component("missing", "f" * 40),
                {"component_id": "no-range", "project_git_ranges": []},
            ],
        },
        repository,
    )

    assert [item["component_id"] for item in result["components"]] == ["resolved"]
    assert result["rejected_component_count"] == 4
    assert {
        item["component_id"]: item["programmatic_details"]
        for item in result["excluded_components"]
    } == {
        "missing": ["missing_commit:" + "f" * 40],
        "no-range": ["no_project_git_range"],
        "last-affected": ["phase_without_fix_boundary"],
        "invalid-topology": ["introduction_not_ancestor_of_fix"],
    }
    assert result["fix_boundaries"] == [
        {
            "commit": commits[1],
            "committed_at": result["fix_boundaries"][0]["committed_at"],
            "parents": [commits[0]],
        }
    ]
    assert all(item["commit"] != commits[1] for item in result["checkpoints"])
