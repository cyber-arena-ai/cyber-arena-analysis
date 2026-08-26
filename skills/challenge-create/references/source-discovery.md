# Advisory-first source discovery

Resolve the directory containing `SKILL.md` as `<skill-root>`. Keep the current
source corpus at stable paths under `artifacts/sources/`; publish updates to the
designated Hugging Face dataset for durable history. Never commit the source
corpus to this repository.

Stage 1 answers a narrow question: which advisory-linked applications justify
the more expensive Git reconstruction and semantic work in Stage 2? It does
not prove exploitability or challenge suitability.

Read [advisory-source-roles.md](advisory-source-roles.md) for the maintained
division between the OSV base corpus, fast-lane selectors, and enrichment
sources. This document defines normalization and persistence; the role registry
defines which sources select work.

## 1. Refresh the advisory corpus

```bash
python3 <skill-root>/scripts/snapshot_osv.py \
  --output-dir artifacts/sources/osv \
  --refresh
```

The default OSV base corpus is `GIT`, `Go`, `Maven`, `Packagist`, `PyPI`,
`RubyGems`, `crates.io`, and `npm`. The first run can be large. Without
`--refresh`, the command reuses existing ZIPs and preserves matching fetch
provenance.

Complementary advisories may be added when they are already available or when
a later review finds missing upstream evidence. Normalize them as complete
OSV-shaped JSON records in a ZIP under `artifacts/sources/osv/raw/`. Preserve
IDs, aliases, withdrawal state, publication time, summary or details, affected
packages, versions and ranges, and typed references. Add the ZIP to
`osv_manifest.json` with these fields:

```json
{
  "path": "vendor.zip",
  "bytes": 1234,
  "sha256": "...",
  "source": "upstream vendor advisories",
  "role": "enrichment",
  "fetched_at": "2026-08-25T00:00:00+00:00"
}
```

Normalize a downloaded CISA KEV feed and register the priority-1 fast lane with:

```bash
python3 <skill-root>/scripts/snapshot_cisa_kev.py \
  --input /tmp/known_exploited_vulnerabilities.json \
  --output-dir artifacts/sources/osv
```

Normalize an official local Metasploit checkout and register the priority-2
fast lane with:

```bash
python3 <skill-root>/scripts/snapshot_metasploit.py \
  --repository /tmp/metasploit-framework \
  --output-dir artifacts/sources/osv
```

The snapshot step does not build a second normalized project or advisory
catalog. Fast-lane and enrichment records join the same union corpus. Stage 1
and Stage 2 read only complete manifest-listed archives; unlisted ZIPs are
ignored.

## 2. Optionally retain duplicate context

When a current challenge inventory is available, normalize only its mechanical
keys at `artifacts/sources/challenge-inventory.json`:

```json
{
  "schema_version": 1,
  "repositories": ["owner/project"],
  "advisory_ids": ["CVE-2026-0001"]
}
```

Repository or advisory matches are retained as `duplicate_matches`; they are
not automatic rejection because a challenge is an application boundary, not a
CVE exercise. Asset and boundary duplication remains a semantic judgment.

## 3. Build the persistent candidate index

If one or more manifest sources have `role: fast_lane`, the command evaluates
only their active seed components after transitive alias closure and draws
enrichment from every manifested archive. Without a fast-lane source it retains
the legacy full-corpus behavior.

```bash
python3 <skill-root>/scripts/shortlist_candidates.py \
  --raw-dir artifacts/sources/osv/raw \
  --manifest artifacts/sources/osv/osv_manifest.json \
  --duplicate-inventory artifacts/sources/challenge-inventory.json \
  --metadata-cache artifacts/sources/github_repository_metadata.json \
  --output artifacts/candidates.json
```

Omit `--duplicate-inventory` if the inventory was not gathered. Add
`--published-after <timezone-qualified timestamp>` only when the experiment
requires a model-knowledge cutoff.

The command deliberately works in this order:

1. Verify the manifest and every listed archive.
2. Join transitive IDs and aliases. Withdrawn records may bridge aliases but
   never contribute active evidence. When fast lanes are present, select alias
   components containing an active fast-lane record and retain the rest as the
   deferred coverage count.
3. Drop malicious-package records and candidates without behavioral or repair
   evidence. Repair may be an exact Git fix or an authoritative fixed release,
   but keep release-only candidates unresolved until an exact Git repair is
   established for the current Stage 2 resolver.
4. Resolve the application repository independently from repair repositories:
   affected Git range, then typed `PACKAGE` reference, then repository-local
   security advisory. Keep ambiguous and fix-only mappings unresolved. Require
   the selected application to have a structurally valid affected Git range
   whose every phase has an exact fixed commit; otherwise retain the component
   as unresolved before spending a GitHub metadata request.
5. Fetch current GitHub metadata once for each surviving application
   repository. Checkpoint each completed response in
   `github_repository_metadata.json`; bounded rate-limit retries may continue
   immediately, while a later failure can resume from the cache. Consolidate
   redirects under the current canonical slug while retaining every advisory
   slug as a repository alias for Stage 2 matching.
6. Exclude repositories only when archived or inactive status establishes the
   result. Accept only clear deployable-service metadata. Keep missing license
   or activity, apparent non-service shapes, and sparse or contradictory
   service evidence unresolved rather than guessing.

Do not filter by CWE, CVSS, attack-vector labels, summary keywords, advisory
count, or a popularity threshold. `stars` and `forks` are preserved only as
late tie-breakers after advisory evidence and project gates.

## Persistent result and resume boundary

`artifacts/candidates.json` ends Stage 1. It contains:

- `projects[]`: accepted application repositories, observed GitHub metadata,
  duplicate context, and advisory components;
- `unresolved_candidates[]`: application mappings or project facts requiring
  bounded evidence gathering;
- `summary.exclusions`: deterministic rejection counts;
- `selection`: active fast lanes plus seeded, coverage, and selected-component
  counts;
- `sources`: hashes for the advisory manifest and optional inventory.

The generated metadata cache uses schema version 1 and maps each requested
`owner/repository` to its completed GitHub response (or `null` for a completed
not-found response). It is a resumable Stage 1 input, and its hash is recorded
under `candidates.json.sources`. Remove or replace it when intentionally
refreshing mutable GitHub metadata.

Resume Stage 1 by refreshing or correcting a source, updating its manifest
entry, and rebuilding `candidates.json`. Continue to Stage 2 only with entries
under `projects[]`; never silently promote an unresolved candidate.
