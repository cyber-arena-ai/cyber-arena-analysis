import hashlib
import json
import subprocess
import sys
import zipfile
from io import BytesIO
from pathlib import Path
from urllib.error import HTTPError


SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

import shortlist_candidates  # noqa: E402
from shortlist_candidates import InputError, generate  # noqa: E402
from osv_history import CorpusError  # noqa: E402
from compute_candidate_overlaps import (  # noqa: E402
    _repository_records,
    generate as generate_overlaps,
)
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
            {
                "package": {"ecosystem": "PyPI", "name": "example-app"},
                "ranges": [
                    {
                        "type": "GIT",
                        "repo": "https://github.com/example/app",
                        "events": [{"introduced": "0"}, {"fixed": commit}],
                    }
                ],
            }
        ],
        "references": [
            {
                "type": "PACKAGE",
                "url": "https://github.com/example/app",
            },
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

    return raw_dir, manifest_path, archive_path


def _project(repository="example/app", **overrides):
    project = {
        "repository": repository,
        "url": f"https://github.com/{repository}",
        "name": repository.split("/", 1)[1],
        "description": "Self-hosted network application",
        "stars": 100_000,
        "forks": 10_000,
        "license": "MIT",
        "archived": False,
        "pushed_at": "2026-04-30T00:00:00Z",
        "topics": ["self-hosted"],
        "default_branch": "main",
        "observed_at": "2026-05-01T00:00:00Z",
    }
    project.update(overrides)
    return project


def _refresh_source(manifest_path, archive_path, **source_fields):
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    source = next(
        (item for item in payload["sources"] if item["path"] == archive_path.name),
        None,
    )
    if source is None:
        source = {"path": archive_path.name}
        payload["sources"].append(source)
    source.update(
        {
            "bytes": archive_path.stat().st_size,
            "sha256": hashlib.sha256(archive_path.read_bytes()).hexdigest(),
            **source_fields,
        }
    )
    manifest_path.write_text(json.dumps(payload), encoding="utf-8")


def _generate(
    inputs,
    *,
    fetch_repository=None,
    duplicate_inventory=None,
    metadata_cache=None,
    stage1_5_evidence=None,
):
    raw_dir, manifest, _ = inputs
    return generate(
        raw_dir=raw_dir,
        manifest_path=manifest,
        duplicate_inventory_path=duplicate_inventory,
        metadata_cache_path=metadata_cache,
        stage1_5_evidence_path=stage1_5_evidence,
        fetch_repository=fetch_repository or (lambda repository: _project(repository)),
    )


def test_canonical_index_preserves_all_dates_and_aliases_do_not_double_count(tmp_path):
    inputs = _inputs(tmp_path)

    result = _generate(inputs)

    assert result["schema_version"] == 4
    assert "date_cutoff" not in result
    assert [
        component["component_id"]
        for component in result["projects"][0]["components"]
    ] == ["CVE-2025-0001", "CVE-2026-0001", "CVE-2026-0002"]
    assert result["projects"][0]["components"][0][
        "earliest_manifested_publication"
    ] == "2025-12-01T00:00:00+00:00"
    assert result["summary"]["withdrawn_advisory_records"] == 1
    assert result["summary"]["github_repositories_fetched"] == 1
    assert "priority_projects" not in result
    assert "popularity_score" not in result["projects"][0]
    assert result["projects"][0]["project"]["name"] == "app"
    assert result["projects"][0]["project"]["archived"] is False
    assert result["summary"]["component_dispositions"] == {
        "resolved": 3,
        "unresolved": 0,
        "rejected": 0,
    }
    matrix = {
        row["component_id"]: row for row in result["evidence_matrix"]["rows"]
    }
    assert result["evidence_matrix"]["asset_fields"] == [
        "advisory_text",
        "exploit_evidence",
        "cwe",
        "affected_package",
        "exact_git_repair",
        "fixed_release",
        "application_repository",
        "usable_application_git_range",
        "repository_metadata",
    ]
    assert matrix["CVE-2026-0001"]["disposition"] == "resolved"
    assert matrix["CVE-2026-0001"]["assets"] == {
        "advisory_text": True,
        "exploit_evidence": False,
        "cwe": False,
        "affected_package": True,
        "exact_git_repair": True,
        "fixed_release": False,
        "application_repository": True,
        "usable_application_git_range": True,
        "repository_metadata": True,
    }


def test_manifest_hash_mismatch_fails_closed(tmp_path):
    inputs = _inputs(tmp_path)
    inputs[2].write_bytes(inputs[2].read_bytes() + b"tampered")

    try:
        _generate(inputs)
    except (InputError, CorpusError) as error:
        assert "size mismatch" in str(error)
    else:
        raise AssertionError("tampered input was accepted")


def test_shortlist_rejects_inactive_projects(tmp_path):
    inputs = _inputs(tmp_path)
    result = _generate(
        inputs,
        fetch_repository=lambda repository: _project(
            repository, pushed_at="2020-01-01T00:00:00Z"
        ),
    )

    assert result["projects"] == []
    assert result["summary"]["exclusions"]["inactive_project"] == 3
    assert {
        row["disposition"] for row in result["evidence_matrix"]["rows"]
    } == {"rejected"}
    assert {
        row["reason"] for row in result["evidence_matrix"]["rows"]
    } == {"inactive_project"}
    assert all(
        row["assets"]["repository_metadata"]
        for row in result["evidence_matrix"]["rows"]
    )


def test_unresolved_project_gate_retains_observed_metadata(tmp_path):
    inputs = _inputs(tmp_path)
    result = _generate(
        inputs,
        fetch_repository=lambda repository: _project(repository, license=None),
    )

    assert result["projects"] == []
    unresolved = result["unresolved_candidates"][0]
    assert unresolved["reason"] == "acceptable_oss_license_not_established"
    assert unresolved["project"]["license"] is None
    assert unresolved["project"]["observed_at"] == "2026-05-01T00:00:00Z"
    assert unresolved["project"]["description"] == "Self-hosted network application"
    assert len(unresolved["component_publications"]) == 3


def test_service_metadata_heuristics_remain_unresolved(tmp_path):
    inputs = _inputs(tmp_path)
    library = _generate(
        inputs,
        fetch_repository=lambda repository: _project(
            repository,
            description="Dependency management library",
            topics=[],
        ),
    )
    conflicting = _generate(
        inputs,
        fetch_repository=lambda repository: _project(
            repository,
            description="Self-hosted server",
            topics=["library"],
        ),
    )
    client = _generate(
        inputs,
        fetch_repository=lambda repository: _project(
            repository,
            description="Python client for a database service",
            topics=[],
        ),
    )

    assert library["projects"] == []
    assert library["unresolved_candidates"][0]["reason"] == (
        "non_service_shape_indicated"
    )
    assert conflicting["projects"] == []
    assert conflicting["unresolved_candidates"][0]["reason"] == (
        "conflicting_service_metadata"
    )
    assert client["projects"] == []
    assert client["unresolved_candidates"][0]["reason"] == (
        "conflicting_service_metadata"
    )
    assert "non_service_shape_indicated" not in library["summary"]["exclusions"]


def test_stage1_5_evidence_promotes_only_scoped_components(tmp_path):
    inputs = _inputs(tmp_path)
    corrected = "7" * 40
    evidence_path = tmp_path / "stage1_5_evidence.json"
    evidence_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "resolutions": [
                    {
                        "component_id": "CVE-2026-0001",
                        "repository": "example/app",
                        "service_evidence": (
                            f"https://github.com/example/app/blob/{corrected}/README.md"
                        ),
                        "repair": {
                            "commits": [
                                {
                                    "sha": corrected,
                                    "affected_parent": "6" * 40,
                                    "url": (
                                        "https://github.com/example/app/commit/"
                                        + corrected
                                    ),
                                }
                            ],
                            "events": [
                                {"introduced": "0"},
                                {"fixed": corrected},
                            ],
                        },
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    result = _generate(
        inputs,
        stage1_5_evidence=evidence_path,
        fetch_repository=lambda repository: _project(
            repository,
            description="Dependency management library",
            topics=[],
        ),
    )

    project = result["projects"][0]
    assert [item["component_id"] for item in project["components"]] == [
        "CVE-2026-0001"
    ]
    component = project["components"][0]
    assert component["stage1_5_resolution"]["component_id"] == "CVE-2026-0001"
    assert component["fixes"] == [
        {
            "sha": corrected,
            "source": "stage1_5_direct_repair",
            "url": f"https://github.com/example/app/commit/{corrected}",
        }
    ]
    assert component["application_git_ranges"] == [
        {
            "repository": "example/app",
            "events": [{"introduced": "0"}, {"fixed": corrected}],
            "blockers": [],
        }
    ]
    unresolved_project = next(
        item
        for item in result["unresolved_candidates"]
        if item.get("repository") == "example/app"
    )
    assert unresolved_project["component_ids"] == [
        "CVE-2025-0001",
        "CVE-2026-0002",
    ]
    assert result["sources"]["stage1_5_evidence"]["sha256"] == hashlib.sha256(
        evidence_path.read_bytes()
    ).hexdigest()

    candidates_path = tmp_path / "candidates.json"
    candidates_path.write_text(json.dumps(result), encoding="utf-8")
    overlap = generate_overlaps(
        candidates_path=candidates_path,
        raw_dir=inputs[0],
        manifest_path=inputs[1],
    )
    overlap_component = overlap["projects"][0]["components"][0]
    assert overlap_component["project_git_ranges"] == [
        {
            "repo": "https://github.com/example/app",
            "events": [{"introduced": "0"}, {"fixed": corrected}],
        }
    ]


def test_stage1_5_evidence_rejects_unmatched_repair_boundaries(tmp_path):
    inputs = _inputs(tmp_path)
    evidence_path = tmp_path / "stage1_5_evidence.json"
    evidence_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "resolutions": [
                    {
                        "component_id": "CVE-2026-0001",
                        "repository": "example/app",
                        "service_evidence": (
                            "https://github.com/example/app/blob/"
                            + "7" * 40
                            + "/README.md"
                        ),
                        "repair": {
                            "commits": [
                                {
                                    "sha": "7" * 40,
                                    "affected_parent": "6" * 40,
                                    "url": (
                                        "https://github.com/example/app/commit/"
                                        + "7" * 40
                                    ),
                                }
                            ],
                            "events": [
                                {"introduced": "0"},
                                {"fixed": "8" * 40},
                            ],
                        },
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    try:
        _generate(inputs, stage1_5_evidence=evidence_path)
    except InputError as error:
        assert "invalid Stage 1.5 repair range" in str(error)
    else:
        raise AssertionError("inconsistent Stage 1.5 repair evidence was accepted")


def test_github_metadata_cache_resumes_after_a_late_failure(tmp_path):
    raw_dir, manifest, archive_path = _inputs(tmp_path)
    second = _record("CVE-2026-4000", "2026-04-20T00:00:00Z", "f" * 40)
    second["affected"][0]["package"]["name"] = "second"
    second["affected"][0]["ranges"][0]["repo"] = (
        "https://github.com/example/second"
    )
    for reference in second["references"]:
        reference["url"] = reference["url"].replace("example/app", "example/second")
    with zipfile.ZipFile(archive_path, "a") as archive:
        archive.writestr("second.json", json.dumps(second))
    _refresh_source(manifest, archive_path)
    cache = tmp_path / "github_repository_metadata.json"
    first_calls = []

    def interrupted_fetch(repository):
        first_calls.append(repository)
        if repository == "example/second":
            raise InputError("simulated rate limit")
        return _project(repository)

    try:
        _generate(
            (raw_dir, manifest, archive_path),
            fetch_repository=interrupted_fetch,
            metadata_cache=cache,
        )
    except InputError as error:
        assert "simulated rate limit" in str(error)
    else:
        raise AssertionError("late metadata failure was accepted")

    assert first_calls == ["example/app", "example/second"]
    cached = json.loads(cache.read_text(encoding="utf-8"))
    assert sorted(cached["repositories"]) == ["example/app"]

    resumed_calls = []
    result = _generate(
        (raw_dir, manifest, archive_path),
        fetch_repository=lambda repository: (
            resumed_calls.append(repository) or _project(repository)
        ),
        metadata_cache=cache,
    )

    assert resumed_calls == ["example/second"]
    assert [project["repository"] for project in result["projects"]] == [
        "example/app",
        "example/second",
    ]
    assert result["summary"]["github_repositories_fetched"] == 1
    assert result["sources"]["github_metadata_cache"]["sha256"] == hashlib.sha256(
        cache.read_bytes()
    ).hexdigest()


def test_github_metadata_retries_a_short_rate_limit(monkeypatch):
    payload = {
        "html_url": "https://github.com/example/app",
        "full_name": "example/app",
        "name": "app",
        "description": "Self-hosted service",
        "stargazers_count": 1,
        "forks_count": 1,
        "license": {"spdx_id": "MIT"},
        "archived": False,
        "pushed_at": "2026-04-30T00:00:00Z",
        "topics": ["self-hosted"],
        "default_branch": "main",
    }

    class Response(BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            self.close()

    responses = [
        HTTPError("https://api.github.com", 429, "rate limited", {"Retry-After": "0"}, None),
        Response(json.dumps(payload).encode()),
    ]
    sleeps = []

    def fake_urlopen(_request, timeout):
        assert timeout == 30
        response = responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response

    monkeypatch.setattr(shortlist_candidates, "urlopen", fake_urlopen)
    monkeypatch.setattr(shortlist_candidates.time, "sleep", sleeps.append)

    project = shortlist_candidates._github_repository("example/app")

    assert project["repository"] == "example/app"
    assert sleeps == [0.0]


def test_package_rename_records_expand_to_a_fixed_point():
    direct = {
        "source_archive": "test.zip",
        "source_member": "direct.json",
        "record": {
            "affected": [
                {
                    "package": {"ecosystem": "PyPI", "name": "old-name"},
                    "ranges": [
                        {
                            "type": "GIT",
                            "repo": "https://github.com/example/app",
                            "events": [{"introduced": "0"}, {"fixed": "a" * 40}],
                        }
                    ],
                }
            ]
        },
    }
    renamed = {
        "source_archive": "test.zip",
        "source_member": "renamed.json",
        "record": {
            "affected": [
                {
                    "package": {"ecosystem": "PyPI", "name": "new-name"},
                    "versions": ["2.0"],
                }
            ]
        },
    }
    bridge = {
        "source_archive": "test.zip",
        "source_member": "bridge.json",
        "record": {
            "affected": [
                {"package": {"ecosystem": "PyPI", "name": "old-name"}},
                {"package": {"ecosystem": "PyPI", "name": "new-name"}},
            ]
        },
    }

    selected = _repository_records(
        [direct, renamed, bridge], {"example/app"}, strict=True
    )

    assert [item["source_member"] for item in selected] == [
        "direct.json",
        "bridge.json",
        "renamed.json",
    ]
    assert selected[-1]["record"]["affected"][0]["versions"] == ["2.0"]


def test_shortlist_rejects_components_without_behavioral_evidence(tmp_path):
    inputs = _inputs(tmp_path)
    raw_dir, manifest, archive_path = inputs
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

    result = _generate(inputs)

    assert result["summary"]["exclusions"] == {
        "no_behavioral_evidence": 1,
        "no_repair_evidence": 1,
    }
    assert "CVE-2026-0999" not in {
        item["component_id"] for item in result["projects"][0]["components"]
    }
    rejected = next(
        row
        for row in result["evidence_matrix"]["rows"]
        if row["component_id"] == "CVE-2026-0999"
    )
    assert rejected["disposition"] == "rejected"
    assert rejected["reason"] == "no_behavioral_evidence"
    assert rejected["assets"]["advisory_text"] is False
    assert rejected["assets"]["exact_git_repair"] is True


def test_withdrawn_record_can_bridge_active_aliases_without_being_retained(tmp_path):
    raw_dir, manifest, archive_path = _inputs(tmp_path)
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

    result = _generate((raw_dir, manifest, archive_path))
    bridged = [
        item
        for item in result["projects"][0]["components"]
        if "CVE-2026-0101" in item["ids"] or "CVE-2026-0102" in item["ids"]
    ]

    assert len(bridged) == 1
    assert {"CVE-2026-0101", "CVE-2026-0102"}.issubset(bridged[0]["ids"])
    assert result["summary"]["withdrawn_advisory_records"] == 2


def test_application_repository_is_not_inferred_from_foreign_fix(tmp_path):
    raw_dir, manifest, archive_path = _inputs(tmp_path)
    record = {
        "id": "CVE-2026-2001",
        "published": "2026-04-15T00:00:00Z",
        "summary": "Authorization bypass exposes protected application data",
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "example-app"},
                "ranges": [
                    {
                        "type": "GIT",
                        "repo": "https://github.com/example/app",
                        "events": [{"introduced": "0"}, {"fixed": "a" * 40}],
                    }
                ],
            }
        ],
        "references": [
            {
                "type": "FIX",
                "url": "https://github.com/example/plugin/commit/" + "b" * 40,
            }
        ],
    }
    with zipfile.ZipFile(archive_path, "a") as archive:
        archive.writestr("foreign-fix.json", json.dumps(record))
    _refresh_source(manifest, archive_path)
    requests = []

    result = _generate(
        (raw_dir, manifest, archive_path),
        fetch_repository=lambda repository: (
            requests.append(repository) or _project(repository)
        ),
    )

    component = next(
        item
        for item in result["projects"][0]["components"]
        if item["component_id"] == "CVE-2026-2001"
    )
    assert requests == ["example/app"]
    assert component["application_repository"] == "example/app"
    assert component["fix_repositories"] == ["example/app", "example/plugin"]
    assert {item.get("repository") for item in component["repair_evidence"]} == {
        "example/app",
        "example/plugin",
    }


def test_fix_only_record_stays_unresolved_and_is_not_fetched(tmp_path):
    raw_dir, manifest, archive_path = _inputs(tmp_path)
    record = {
        "id": "CVE-2026-2002",
        "published": "2026-04-16T00:00:00Z",
        "summary": "Authentication bypass",
        "affected": [
            {"package": {"ecosystem": "PyPI", "name": "unknown-app"}}
        ],
        "references": [
            {
                "type": "FIX",
                "url": "https://github.com/example/repair/commit/" + "c" * 40,
            }
        ],
    }
    with zipfile.ZipFile(archive_path, "a") as archive:
        archive.writestr("fix-only.json", json.dumps(record))
    _refresh_source(manifest, archive_path)
    requests = []

    result = _generate(
        (raw_dir, manifest, archive_path),
        fetch_repository=lambda repository: (
            requests.append(repository) or _project(repository)
        ),
    )

    unresolved = next(
        item
        for item in result["unresolved_candidates"]
        if item.get("component_id") == "CVE-2026-2002"
    )
    assert unresolved["reason"] == "application_repository_not_established"
    assert unresolved["candidate_repositories"] == ["example/repair"]
    assert requests == ["example/app"]


def test_manifested_complementary_record_survives_stage_two(tmp_path):
    raw_dir, manifest, archive_path = _inputs(tmp_path)
    complement_path = raw_dir / "vendor.zip"
    record = {
        "id": "CVE-2026-2003",
        "published": "2026-04-17T00:00:00Z",
        "summary": "Protected workflow can be modified without authorization",
        "affected": [
            {
                "package": {"ecosystem": "Vendor", "name": "example-app"},
                "versions": ["2.0"],
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "2.0"}, {"fixed": "2.1"}],
                    },
                    {
                        "type": "GIT",
                        "repo": "https://github.com/example/app",
                        "events": [{"introduced": "0"}, {"fixed": "e" * 40}],
                    },
                ],
            }
        ],
        "references": [
            {"type": "PACKAGE", "url": "https://github.com/example/app"}
        ],
    }
    with zipfile.ZipFile(complement_path, "w") as archive:
        archive.writestr("vendor-record.json", json.dumps(record))
    _refresh_source(manifest, complement_path, source="vendor-advisory")

    candidates = _generate((raw_dir, manifest, archive_path))
    candidates_path = tmp_path / "candidates.json"
    candidates_path.write_text(json.dumps(candidates), encoding="utf-8")
    overlap = generate_overlaps(
        candidates_path=candidates_path,
        raw_dir=raw_dir,
        manifest_path=manifest,
    )

    component = next(
        item
        for item in overlap["projects"][0]["components"]
        if item["component_id"] == "CVE-2026-2003"
    )
    assert component["raw_record_count"] == 1
    assert component["affected_units"] == ["Vendor:example-app"]
    assert "CVE-2026-2003" not in overlap["projects"][0][
        "components_without_raw_records"
    ]


def test_fast_lane_selects_seeded_alias_closure_and_retains_seed_only_gaps(tmp_path):
    raw_dir, manifest, archive_path = _inputs(tmp_path)
    fast_lane = raw_dir / "cisa-kev.zip"
    records = [
        {
            "id": "CISA-KEV-CVE-2026-0002",
            "aliases": ["CVE-2026-0002"],
            "published": "2026-04-05T00:00:00Z",
            "summary": "Known exploited authorization bypass",
        },
        {
            "id": "CVE-2026-9000",
            "published": "2026-04-06T00:00:00Z",
            "summary": "Known exploited code injection",
            "references": [
                {
                    "type": "ADVISORY",
                    "url": (
                        "https://github.com/example/seed-only/security/advisories/"
                        "GHSA-1111-2222-3333"
                    ),
                }
            ],
        },
    ]
    with zipfile.ZipFile(fast_lane, "w") as archive:
        for index, record in enumerate(records):
            archive.writestr(f"seed-{index}.json", json.dumps(record))
    _refresh_source(
        manifest,
        fast_lane,
        source="CISA Known Exploited Vulnerabilities",
        role="fast_lane",
        lane="known_exploited",
        priority=1,
    )

    result = _generate((raw_dir, manifest, archive_path))

    assert result["selection"] == {
        "mode": "fast_lane",
        "active_lanes": [
            {
                "lane": "known_exploited",
                "priority": 1,
                "source": "CISA Known Exploited Vulnerabilities",
            }
        ],
        "seeded_components": 2,
        "coverage_components": 3,
        "selected_components": 2,
    }
    components = result["projects"][0]["components"]
    assert [component["component_id"] for component in components] == [
        "CVE-2026-0002"
    ]
    assert components[0]["fast_lane_memberships"] == [
        {
            "lane": "known_exploited",
            "priority": 1,
            "source": "CISA Known Exploited Vulnerabilities",
        }
    ]
    assert len(components[0]["sources"]) == 2
    unresolved = next(
        item
        for item in result["unresolved_candidates"]
        if item.get("component_id") == "CVE-2026-9000"
    )
    assert unresolved["reason"] == "exact_git_repair_not_established"
    assert unresolved["application_repository"] == "example/seed-only"
    assert unresolved["earliest_manifested_publication"] == (
        "2026-04-06T00:00:00+00:00"
    )
    assert unresolved["fast_lane_memberships"] == components[0][
        "fast_lane_memberships"
    ]
    matrix = next(
        row
        for row in result["evidence_matrix"]["rows"]
        if row["component_id"] == "CVE-2026-9000"
    )
    assert matrix["disposition"] == "unresolved"
    assert matrix["reason"] == "exact_git_repair_not_established"
    assert matrix["assets"]["advisory_text"] is True
    assert matrix["assets"]["exact_git_repair"] is False
    assert matrix["assets"]["application_repository"] is True
    assert matrix["assets"]["repository_metadata"] is False
    assert result["summary"]["candidate_projects"] == 1
    assert result["summary"]["unresolved_candidates"] == 1


def test_release_only_repair_stays_unresolved_before_git_reconstruction(tmp_path):
    raw_dir, manifest, archive_path = _inputs(tmp_path)
    record = {
        "id": "CVE-2026-2004",
        "published": "2026-04-18T00:00:00Z",
        "summary": "Authorization bypass",
        "affected": [
            {
                "package": {"ecosystem": "Vendor", "name": "example-app"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "2.0"}, {"fixed": "2.1"}],
                    }
                ],
            }
        ],
        "references": [
            {"type": "PACKAGE", "url": "https://github.com/example/release-only"}
        ],
    }
    with zipfile.ZipFile(archive_path, "a") as archive:
        archive.writestr("release-only.json", json.dumps(record))
    _refresh_source(manifest, archive_path)

    result = _generate((raw_dir, manifest, archive_path))

    unresolved = next(
        item
        for item in result["unresolved_candidates"]
        if item.get("component_id") == "CVE-2026-2004"
    )
    assert unresolved["reason"] == "exact_git_repair_not_established"
    assert unresolved["repair_evidence"] == [
        {"range_type": "ECOSYSTEM", "package": "Vendor:example-app", "fixed": "2.1"}
    ]
    matrix = next(
        row
        for row in result["evidence_matrix"]["rows"]
        if row["component_id"] == "CVE-2026-2004"
    )
    assert matrix["assets"]["exact_git_repair"] is False
    assert matrix["assets"]["fixed_release"] is True


def test_unmanifested_archive_is_ignored(tmp_path):
    raw_dir, manifest, archive_path = _inputs(tmp_path)
    unmanifested = raw_dir / "unmanifested.zip"
    with zipfile.ZipFile(unmanifested, "w") as archive:
        archive.writestr(
            "record.json",
            json.dumps(
                _record("CVE-2026-2999", "2026-04-18T00:00:00Z", "d" * 40)
            ),
        )

    result = _generate((raw_dir, manifest, archive_path))

    assert "CVE-2026-2999" not in {
        component["component_id"]
        for project in result["projects"]
        for component in project["components"]
    }


def test_duplicate_inventory_is_review_context_not_a_popularity_gate(tmp_path):
    inputs = _inputs(tmp_path)
    inventory = tmp_path / "inventory.json"
    inventory.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "repositories": ["example/app"],
                "advisory_ids": ["CVE-2026-0002"],
            }
        ),
        encoding="utf-8",
    )

    result = _generate(inputs, duplicate_inventory=inventory)

    assert result["projects"][0]["duplicate_matches"] == ["example/app"]
    component = next(
        item
        for item in result["projects"][0]["components"]
        if item["component_id"] == "CVE-2026-0002"
    )
    assert component["duplicate_matches"] == ["CVE-2026-0002"]


def test_stage_two_excludes_foreign_package_only_alias_records(tmp_path):
    raw_dir, manifest, archive_path = _inputs(tmp_path)
    foreign = {
        "id": "VENDOR-FOREIGN",
        "aliases": ["CVE-2026-0002"],
        "published": "2026-04-18T00:00:00Z",
        "summary": "Foreign package context",
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "foreign-package"},
                "versions": ["9.9"],
            }
        ],
    }
    with zipfile.ZipFile(archive_path, "a") as archive:
        archive.writestr("foreign-alias.json", json.dumps(foreign))
    _refresh_source(manifest, archive_path)
    candidates = _generate((raw_dir, manifest, archive_path))
    candidates_path = tmp_path / "candidates.json"
    candidates_path.write_text(json.dumps(candidates), encoding="utf-8")

    overlap = generate_overlaps(
        candidates_path=candidates_path,
        raw_dir=raw_dir,
        manifest_path=manifest,
    )

    component = next(
        item
        for item in overlap["projects"][0]["components"]
        if item["component_id"] == "CVE-2026-0002"
    )
    assert component["affected_units"] == ["PyPI:example-app"]
    assert component["raw_record_count"] == 1


def test_repository_redirect_preserves_advisory_identity(tmp_path):
    raw_dir, manifest, archive_path = _inputs(tmp_path)
    with zipfile.ZipFile(archive_path, "a") as archive:
        archive.writestr(
            "renamed.json",
            json.dumps(
                {
                    "id": "CVE-2026-3001",
                    "published": "2026-04-19T00:00:00Z",
                    "summary": "Authorization bypass",
                    "affected": [
                        {
                            "package": {
                                "ecosystem": "PyPI",
                                "name": "renamed-app",
                            },
                            "ranges": [
                                {
                                    "type": "GIT",
                                    "repo": "https://github.com/example/renamed",
                                    "events": [
                                        {"introduced": "0"},
                                        {"fixed": "f" * 40},
                                    ],
                                }
                            ],
                        }
                    ],
                    "references": [
                        {
                            "type": "PACKAGE",
                            "url": "https://github.com/example/renamed",
                        },
                        {
                            "type": "FIX",
                            "url": "https://github.com/example/renamed/commit/"
                            + "f" * 40,
                        },
                    ],
                }
            ),
        )
    _refresh_source(manifest, archive_path)

    result = _generate(
        (raw_dir, manifest, archive_path),
        fetch_repository=lambda repository: _project("example/renamed"),
    )

    assert len(result["projects"]) == 1
    assert result["projects"][0]["repository"] == "example/renamed"
    assert result["projects"][0]["repository_aliases"] == [
        "example/app",
        "example/renamed",
    ]
    assert result["projects"][0]["project"]["canonical_repository"] == (
        "example/renamed"
    )
    candidates_path = tmp_path / "candidates.json"
    candidates_path.write_text(json.dumps(result), encoding="utf-8")
    overlap = generate_overlaps(
        candidates_path=candidates_path,
        raw_dir=raw_dir,
        manifest_path=manifest,
    )
    assert overlap["projects"][0]["repository_aliases"] == [
        "example/app",
        "example/renamed",
    ]
    assert overlap["projects"][0]["components_without_raw_records"] == []


def test_stage_two_rejects_a_different_manifest(tmp_path):
    raw_dir, manifest, archive_path = _inputs(tmp_path)
    candidates = _generate((raw_dir, manifest, archive_path))
    candidates_path = tmp_path / "candidates.json"
    candidates_path.write_text(json.dumps(candidates), encoding="utf-8")
    manifest_payload = json.loads(manifest.read_text(encoding="utf-8"))
    manifest_payload["generated_at"] = "2026-05-02T00:00:00Z"
    manifest.write_text(json.dumps(manifest_payload), encoding="utf-8")

    try:
        generate_overlaps(
            candidates_path=candidates_path,
            raw_dir=raw_dir,
            manifest_path=manifest,
        )
    except ValueError as error:
        assert "manifest hash" in str(error)
    else:
        raise AssertionError("Stage 2 accepted a manifest different from Stage 1")


def test_generated_candidate_reaches_the_git_resolver(tmp_path):
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
    for value in ("vulnerable", "fixed", "after"):
        (repository / "state.txt").write_text(value, encoding="utf-8")
        subprocess.run(["git", "-C", str(repository), "add", "state.txt"], check=True)
        subprocess.run(
            ["git", "-C", str(repository), "commit", "-qm", value], check=True
        )
        commits.append(
            subprocess.run(
                ["git", "-C", str(repository), "rev-parse", "HEAD"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
        )

    raw_dir = tmp_path / "raw"
    raw_dir.mkdir()
    archive_path = raw_dir / "GIT.zip"
    record = {
        "id": "CVE-2026-4001",
        "published": "2026-04-20T00:00:00Z",
        "summary": "Authorization bypass",
        "affected": [
            {
                "package": {"ecosystem": "GIT", "name": "example/app"},
                "ranges": [
                    {
                        "type": "GIT",
                        "repo": "https://github.com/example/app",
                        "events": [{"introduced": "0"}, {"fixed": commits[1]}],
                    }
                ],
            }
        ],
        "references": [
            {"type": "PACKAGE", "url": "https://github.com/example/app"},
            {
                "type": "FIX",
                "url": f"https://github.com/example/app/commit/{commits[1]}",
            },
        ],
    }
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("record.json", json.dumps(record))
    manifest = tmp_path / "osv_manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "generated_at": "2026-05-01T00:00:00Z",
                "sources": [
                    {
                        "path": archive_path.name,
                        "bytes": archive_path.stat().st_size,
                        "sha256": hashlib.sha256(archive_path.read_bytes()).hexdigest(),
                        "ecosystem": "GIT",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    candidates = generate(
        raw_dir=raw_dir,
        manifest_path=manifest,
        fetch_repository=lambda requested: _project(requested),
    )
    candidates_path = tmp_path / "candidates.json"
    candidates_path.write_text(json.dumps(candidates), encoding="utf-8")
    overlap = generate_overlaps(
        candidates_path=candidates_path,
        raw_dir=raw_dir,
        manifest_path=manifest,
    )

    result = resolve_project(overlap["projects"][0], repository)

    assert result["component_count"] == 1
    assert result["rejected_component_count"] == 0
    assert result["candidate_window_count"] == 1


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
                    "ranges": [
                        {
                            "type": "GIT",
                            "repo": "https://github.com/example/app",
                            "events": [
                                {"introduced": "a" * 40},
                                {"fixed": "c" * 40},
                            ],
                        }
                    ],
                }
            ],
        },
    ]
    archive_path = raw_dir / "PyPI.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        for index, record in enumerate(records):
            archive.writestr(f"record-{index}.json", json.dumps(record))
    manifest = tmp_path / "osv_manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "sources": [
                    {
                        "path": archive_path.name,
                        "bytes": archive_path.stat().st_size,
                        "sha256": hashlib.sha256(archive_path.read_bytes()).hexdigest(),
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    def component(identifier, priority):
        return {
            "component_id": identifier,
            "ids": [identifier],
            "earliest_manifested_publication": "2026-03-01T00:00:00+00:00",
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
                "schema_version": 4,
                "sources": {
                    "advisory_manifest": {
                        "sha256": hashlib.sha256(manifest.read_bytes()).hexdigest()
                    }
                },
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
                "evidence_matrix": {"rows": []},
            }
        ),
        encoding="utf-8",
    )

    result = generate_overlaps(
        candidates_path=candidates_path,
        raw_dir=raw_dir,
        manifest_path=manifest,
    )
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
    assert lane["components_with_unevaluated_ranges"] == [
        "CVE-2026-1001",
        "CVE-2026-1002",
    ]
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
        manifest_path=manifest,
        repository="example/app",
    )
    assert [item["repository"] for item in scoped["projects"]] == ["example/app"]


def test_stage_two_rejects_legacy_candidate_schema(tmp_path):
    candidates_path = tmp_path / "candidates.json"
    candidates_path.write_text(json.dumps({"schema_version": 3}), encoding="utf-8")

    try:
        generate_overlaps(candidates_path=candidates_path, raw_dir=tmp_path)
    except ValueError as error:
        assert "requires candidate schema version 4" in str(error)
    else:
        raise AssertionError("Stage 2 accepted a legacy candidate schema")


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

    first = component("CVE-2026-1001", commits[2])
    first["stage1_5_resolution"] = {
        "component_id": "CVE-2026-1001",
        "repository": "example/app",
        "service_evidence": (
            f"https://github.com/example/app/blob/{commits[0]}/README.md"
        ),
        "repair": {
            "commits": [
                {
                    "sha": commits[2],
                    "affected_parent": commits[1],
                    "url": f"https://github.com/example/app/commit/{commits[2]}",
                }
            ],
            "events": [{"introduced": "0"}, {"fixed": commits[2]}],
        },
    }

    result = resolve_project(
        {
            "repository": "example/app",
            "components": [
                first,
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
    packet_component = next(
        item
        for item in packet["components"]
        if item["component_id"] == "CVE-2026-1001"
    )
    assert packet_component["stage1_5_resolution"] == first["stage1_5_resolution"]


def test_stage1_5_repair_rejects_merge_and_mismatched_parent(tmp_path):
    repository = tmp_path / "repository"
    subprocess.run(["git", "init", "-q", str(repository)], check=True)

    def git(*arguments):
        return subprocess.run(
            ["git", "-C", str(repository), *arguments],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()

    def commit(message):
        git("commit", "--allow-empty", "-qm", message)
        return git("rev-parse", "HEAD")

    git("config", "user.email", "test@example.com")
    git("config", "user.name", "Test")
    commit("root")
    default_branch = git("branch", "--show-current")
    git("checkout", "-qb", "repair")
    repair_parent = commit("repair")
    git("checkout", "-q", default_branch)
    commit("main")
    git("merge", "-q", "--no-ff", "repair", "-m", "merge")
    merge_commit = git("rev-parse", "HEAD")
    single_parent_commit = commit("after")

    def component(identifier, fixed, affected_parent):
        repair = {
            "commits": [
                {
                    "sha": fixed,
                    "affected_parent": affected_parent,
                    "url": f"https://github.com/example/app/commit/{fixed}",
                }
            ],
            "events": [{"introduced": "0"}, {"fixed": fixed}],
        }
        return {
            "component_id": identifier,
            "project_git_ranges": [
                {
                    "repo": "https://github.com/example/app",
                    "events": repair["events"],
                }
            ],
            "stage1_5_resolution": {"repair": repair},
        }

    result = resolve_project(
        {
            "repository": "example/app",
            "components": [
                component("merge", merge_commit, repair_parent),
                component("mismatch", single_parent_commit, repair_parent),
            ],
        },
        repository,
    )

    assert {
        item["component_id"]: item["programmatic_details"]
        for item in result["excluded_components"]
    } == {
        "merge": [f"stage1_5_repair_requires_single_parent:{merge_commit}"],
        "mismatch": [
            f"stage1_5_affected_parent_mismatch:{single_parent_commit}"
        ],
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
