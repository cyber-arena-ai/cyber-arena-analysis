from scripts.challenge_research._lib import (
    _dedupe_advisories,
    extract_osv_record,
)


def test_extract_osv_record_keeps_fix_commits_repository_local():
    record = {
        "id": "CVE-2026-1000",
        "affected": [
            {
                "package": {"ecosystem": "Go", "name": "example.com/one"},
                "ranges": [
                    {
                        "type": "GIT",
                        "repo": "https://github.com/example/one",
                        "events": [{"introduced": "0"}, {"fixed": "a" * 40}],
                    }
                ],
            },
            {
                "package": {"ecosystem": "Go", "name": "example.com/two"},
                "ranges": [
                    {
                        "type": "GIT",
                        "repo": "https://github.com/example/two",
                        "events": [{"introduced": "0"}, {"fixed": "b" * 40}],
                    }
                ],
            },
        ],
    }

    evidence = {
        item["repository"]: item
        for item in extract_osv_record(record, source_ecosystem="GIT")
    }

    assert evidence["example/one"]["packages"] == ["Go:example.com/one"]
    assert evidence["example/one"]["fixed_commits"] == ["a" * 40]
    assert evidence["example/two"]["packages"] == ["Go:example.com/two"]
    assert evidence["example/two"]["fixed_commits"] == ["b" * 40]


def test_extract_osv_record_rejects_advisory_tracker_fallback():
    record = {
        "id": "CVE-2026-1001",
        "affected": [],
        "references": [
            {
                "type": "ADVISORY",
                "url": "https://github.com/CVEProject/cvelistV5/tree/main/cves/2026/1xxx/CVE-2026-1001.json",
            }
        ],
    }

    assert extract_osv_record(record, source_ecosystem="GIT") == []


def test_extract_osv_record_accepts_repository_security_advisory():
    record = {
        "id": "GHSA-aaaa-bbbb-cccc",
        "affected": [],
        "references": [
            {
                "type": "ADVISORY",
                "url": "https://github.com/example/service/security/advisories/GHSA-aaaa-bbbb-cccc",
            }
        ],
    }

    evidence = extract_osv_record(record, source_ecosystem="Go")

    assert [item["repository"] for item in evidence] == ["example/service"]


def test_dedupe_advisories_uses_transitive_alias_closure():
    records = [
        {
            "repository": "example/service",
            "repository_confidence": "strong_reference",
            "advisory_id": "GHSA-aaaa-bbbb-cccc",
            "aliases": ["CVE-2026-1002"],
            "summary": "",
            "packages": ["Go:example.com/service"],
            "cwes": ["CWE-284"],
            "fixed_commits": [],
            "references": ["https://example.test/advisory"],
            "source_ecosystem": "Go",
        },
        {
            "repository": "example/service",
            "repository_confidence": "affected_git_range",
            "advisory_id": "CVE-2026-1002",
            "aliases": ["OSV-2026-1"],
            "summary": "authorization bypass",
            "packages": [],
            "cwes": [],
            "fixed_commits": ["c" * 40],
            "references": ["https://example.test/fix"],
            "source_ecosystem": "GIT",
        },
        {
            "repository": "example/service",
            "repository_confidence": "strong_reference",
            "advisory_id": "OSV-2026-1",
            "aliases": [],
            "summary": "",
            "packages": [],
            "cwes": [],
            "fixed_commits": [],
            "references": [],
            "source_ecosystem": "GIT",
        },
    ]

    deduplicated = _dedupe_advisories(records)

    assert len(deduplicated) == 1
    component = deduplicated[0]
    assert component["advisory_id"] == "CVE-2026-1002"
    assert component["aliases"] == ["GHSA-aaaa-bbbb-cccc", "OSV-2026-1"]
    assert component["repository_confidence"] == "affected_git_range"
    assert component["packages"] == ["Go:example.com/service"]
    assert component["fixed_commits"] == ["c" * 40]
    assert component["source_ecosystems"] == ["GIT", "Go"]
