# Source discovery

Resolve the directory containing `SKILL.md` as `<skill-root>`. Keep the current
source corpus at stable paths under `artifacts/sources/`; Git or Hugging Face
history records updates.

## Refresh the project catalog

```bash
python3 <skill-root>/scripts/discover_projects.py \
  --output artifacts/sources/projects.json
```

The config-driven GitHub discovery uses service-family and language queries
from `<skill-root>/scripts/discovery_queries.json`. Override that registry with
`--query-config`, the technical floor with `--min-stars`, or the per-query
result count with `--per-query`. The command requires network access and a
GitHub token when anonymous API limits are insufficient.

## Refresh OSV

```bash
python3 <skill-root>/scripts/snapshot_osv.py \
  --output-dir artifacts/sources/osv \
  --refresh
```

The default OSV set is `GIT`, `Go`, `Maven`, `Packagist`, `PyPI`, `RubyGems`,
`crates.io`, and `npm`. The first run can be large. The command writes raw ZIPs,
`osv_manifest.json`, and normalized repository-linked evidence. Without
`--refresh`, it reuses existing ZIPs and preserves matching fetch provenance.

## Build the candidate index

```bash
python3 <skill-root>/scripts/shortlist_candidates.py \
  --projects artifacts/sources/projects.json \
  --raw-dir artifacts/sources/osv/raw \
  --manifest artifacts/sources/osv/osv_manifest.json \
  --output artifacts/candidates.json
```

This offline step verifies source hashes and applies the production evidence,
application, license, maintenance, and popularity gates. Continue with Stage 2
in the main skill. Do not retain ad hoc rankings, Markdown summaries, or cache
directories as canonical pipeline artifacts.
