import json
import sys
import zipfile
from pathlib import Path


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

from osv_history import (  # noqa: E402
    analyze_overlap,
    build_components,
    select_project_records,
)


def _record(identifier, *, aliases=(), package=None, versions=(), ranges=(), references=()):
    affected = {
        "ranges": list(ranges),
        "versions": list(versions),
    }
    if package:
        ecosystem, name = package.split(":", 1)
        affected["package"] = {"ecosystem": ecosystem, "name": name}
    return {
        "schema_version": "1.7.5",
        "id": identifier,
        "modified": "2026-01-01T00:00:00Z",
        "aliases": list(aliases),
        "affected": [affected],
        "references": list(references),
    }


def _write_archive(raw_dir, records):
    raw_dir.mkdir()
    with zipfile.ZipFile(raw_dir / "PyPI.zip", "w") as archive:
        for index, record in enumerate(records):
            archive.writestr(f"{index}.json", json.dumps(record))


def test_project_history_recovers_package_only_records_and_deduplicates_aliases(tmp_path):
    repository_reference = {
        "type": "PACKAGE",
        "url": "https://github.com/example/service",
    }
    records = [
        _record(
            "GHSA-aaaa-bbbb-cccc",
            aliases=["CVE-2026-1000"],
            package="PyPI:demo",
            versions=["1.0", "1.1"],
            references=[repository_reference],
        ),
        _record(
            "CVE-2026-1000",
            aliases=["GHSA-aaaa-bbbb-cccc"],
            package="PyPI:demo",
            versions=["1.0", "1.1"],
        ),
        _record(
            "GHSA-dddd-eeee-ffff",
            package="PyPI:demo",
            versions=["1.1", "1.2"],
        ),
        _record(
            "GHSA-gggg-hhhh-iiii",
            package="PyPI:demo",
            ranges=[
                {
                    "type": "ECOSYSTEM",
                    "events": [{"introduced": "0"}, {"fixed": "2.0"}],
                }
            ],
        ),
        _record(
            "GHSA-jjjj-kkkk-llll",
            package="PyPI:unrelated",
            versions=["1.1"],
        ),
    ]
    raw_dir = tmp_path / "raw"
    _write_archive(raw_dir, records)

    selected, packages, stats = select_project_records(
        raw_dir, "example/service"
    )
    components = build_components(selected)
    overlap = analyze_overlap(
        components,
        packages,
        [("v1.0", "1.0"), ("v1.1", "1.1"), ("v1.2", "1.2")],
    )

    assert packages == {"PyPI:demo"}
    assert stats["selected_record_count"] == 4
    assert len(components) == 3
    assert overlap["selection"] == {
        "metric": "maximum reported_present advisory-component count",
        "maximum_count": 2,
        "maximal_checkpoints": ["v1.1"],
        "earliest_maximal_checkpoint": "v1.1",
    }
    middle = overlap["checkpoints"][1]
    assert middle["reported_present"] == [
        "CVE-2026-1000",
        "GHSA-dddd-eeee-ffff",
    ]
    assert middle["range_evaluation_required_count"] == 1


def test_overlap_keeps_monorepo_packages_separate(tmp_path):
    reference = {"type": "PACKAGE", "url": "https://github.com/example/mono"}
    records = [
        _record(
            "CVE-2026-2000",
            package="PyPI:core",
            versions=["3.0"],
            references=[reference],
        ),
        _record(
            "CVE-2026-2001",
            package="PyPI:provider",
            versions=["3.0"],
            references=[reference],
        ),
    ]
    raw_dir = tmp_path / "raw"
    _write_archive(raw_dir, records)

    selected, _, _ = select_project_records(
        raw_dir, "example/mono", {"PyPI:core"}
    )
    overlap = analyze_overlap(
        build_components(selected),
        {"PyPI:core"},
        [("3.0", "3.0")],
    )

    checkpoint = overlap["checkpoints"][0]
    assert checkpoint["reported_present"] == ["CVE-2026-2000"]
    assert checkpoint["reported_present_count"] == 1


def test_multi_repository_git_versions_are_not_attributed_to_one_repo(tmp_path):
    ranges = [
        {
            "type": "GIT",
            "repo": "https://github.com/example/service",
            "events": [{"introduced": "a" * 40}, {"fixed": "b" * 40}],
        },
        {
            "type": "GIT",
            "repo": "https://github.com/example/plugin",
            "events": [{"introduced": "c" * 40}, {"fixed": "d" * 40}],
        },
    ]
    raw_dir = tmp_path / "raw"
    _write_archive(
        raw_dir,
        [_record("CVE-2026-3000", versions=["v1.0"], ranges=ranges)],
    )

    selected, _, _ = select_project_records(
        raw_dir, "example/service", {"GIT:example/service"}
    )
    overlap = analyze_overlap(
        build_components(selected),
        {"GIT:example/service"},
        [("v1.0", "v1.0")],
    )

    checkpoint = overlap["checkpoints"][0]
    assert checkpoint["reported_present_count"] == 0
    assert checkpoint["ambiguous_git_version_attribution_count"] == 1
