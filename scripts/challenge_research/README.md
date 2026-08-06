# Challenge Research Prototype

This stdlib-only pipeline creates a dated OSS application shortlist from
config-driven GitHub service-family and language discovery lanes plus
repository-linked OSV advisory records.

For the operational OSV-to-commit workflow, invoke
`$auto-curate-oss-challenges`. The commands below create its retained discovery
inputs. The skill uses one shortlist command followed by the overlap analyzer
and evidence-only semantic review.

```bash
OUT=docs/jt/oss_shortlist_prototype

python scripts/challenge_research/discover_projects.py \
  --output "$OUT/projects.json"

python scripts/challenge_research/snapshot_osv.py \
  --output-dir "$OUT"

python scripts/challenge_research/rank_shortlist.py \
  --projects "$OUT/projects.json" \
  --advisories "$OUT/osv_advisories.json" \
  --output-json "$OUT/shortlist.json" \
  --output-markdown docs/jt/OSS_SHORTLIST_PROTOTYPE.md \
  --min-popularity-score 75
```

The discovery defaults come from `discovery_queries.json`: 44 service-family
queries and 10 language sweeps, with 100 star-sorted results per query. Each
query records raw rows, unique additions, and overlap. Override the registry
with `--query-config`, the technical candidate floor with `--min-stars`, or the
per-query result count with `--per-query`.

The first two commands require network access. Ranking is offline and consumes
only the retained snapshots. Re-running `snapshot_osv.py` reuses existing ZIPs;
pass `--refresh` to replace them with a new dated upstream snapshot.
The default OSV set is `GIT`, `Go`, `Maven`, `Packagist`, `PyPI`, `RubyGems`,
`crates.io`, and `npm`. The `GIT` and `npm` archives are large, so allow extra
download time and disk space on the first run.

`snapshot_osv.py` writes the same normalized repository-linked evidence to
`osv_advisories.json` for the ranker and `osv_advisories.jsonl` for sharing.
The JSONL has one evidence object per line, sorted identically to the JSON
array. It intentionally retains GHSA and other OSV records without a `CVE-*`
alias because filtering them would remove source evidence for some candidates.
Pair it with `osv_manifest.json` when source ZIP hashes are required.

The ranker reports every discovered project and applies a configurable GitHub
popularity-proxy gate. `--min-popularity-score` sets the absolute threshold;
optional `--limit` caps the admitted set after ranking. Stars contribute up to
55 points, forks 25, recent maintenance 10, and repository longevity 10. CVEs,
application fit, licensing, and diversity do not affect popularity admission.
Every admitted application still needs manual upstream-advisory review,
source-history mapping, arena-feasibility work, and challenge-review evidence.

To snapshot and rank the positive test pool independently of discovery-query
recall:

```bash
python scripts/challenge_research/snapshot_project_pool.py \
  --pool docs/jt/oss_discovery_test_pool.json \
  --output docs/jt/oss_discovery_test_pool_projects.json

python scripts/challenge_research/rank_shortlist.py \
  --projects docs/jt/oss_discovery_test_pool_projects.json \
  --advisories "$OUT/osv_advisories.json" \
  --output-json docs/jt/oss_discovery_test_pool_popularity_ranking.json \
  --output-markdown docs/jt/OSS_DISCOVERY_TEST_POOL_POPULARITY_RANKING.md \
  --min-popularity-score 75
```

## Curated history pilot

After a project is shortlisted, exact advisory-to-commit mappings are curated in
`docs/jt/oss_candidate_history.json`. Rebuild the human-readable history ledger,
the global attack-scope registry, and the small Gitea example with:

```bash
python scripts/challenge_research/map_history.py
python scripts/challenge_research/map_history.py --check
```

The first command renders deterministic Markdown from the curated JSON and the
retained OSV snapshot. The second validates IDs, immutable commit links, attack
scope references, and that generated reports are current. This is research
bookkeeping only: a mapped commit is not admitted as a challenge until its
reachability, exploit depth, defense depth, and arena fit are reviewed.

## Positive-pool CVE coverage audit

Check whether the retained CVE-discovery evidence found anything for each
project in the curated positive test pool:

```bash
python scripts/challenge_research/audit_cve_coverage.py
python scripts/challenge_research/audit_cve_coverage.py --check
```

The audit uses exact GitHub repository matches and counts only `CVE-*`
identifiers. A miss is reported as a coverage gap rather than evidence that a
project has no vulnerabilities.

## Lossless affected-range and overlap analysis

The normalized advisory snapshot is intentionally small and repository-oriented;
it is not an affected-range database. After an application is shortlisted, read
the retained raw OSV archives and build a package-specific history:

```bash
python3 skills/auto-curate-oss-challenges/scripts/compute_candidate_overlaps.py \
  --candidates /tmp/oss-candidates.json \
  --raw-dir docs/jt/oss_shortlist_prototype/raw \
  --output-dir docs/jt/oss_candidates
```

This batch pass uses every hard-gated project and component; the priority queue
is annotation only. It does not consume semantic verdicts.

Resolve project Git ranges to immutable commits before semantic review:

```bash
python3 skills/auto-curate-oss-challenges/scripts/resolve_git_windows.py \
  --overlap-dir docs/jt/oss_candidates/overlap_data \
  --repo-cache /tmp/cyber-arena-git-cache \
  --output-dir docs/jt/oss_candidates/git_windows
```

This uses commit-only bare clones and evaluates OSV `introduced` and `fixed`
events with Git ancestry without fetching source trees or patch bodies.
Components with unresolved Git ranges or no valid fix parent are excluded
before overlap. The `semantic_packets/` output contains the surviving groups
and programmatic exclusion ledger. Fetch exact diffs only for selected groups
during semantic review.

For ordered checkpoint refinement of one affected unit:

```bash
python scripts/challenge_research/analyze_osv_overlap.py \
  --raw-dir "$OUT/raw" \
  --repository apache/airflow \
  --package PyPI:apache-airflow \
  --package PyPI:apache-airflow-core \
  --checkpoint 3.1.5 \
  --checkpoint 3.1.8 \
  --checkpoint 3.2.0 \
  --checkpoint 3.2.1 \
  --checkpoint 3.2.2 \
  --checkpoint 3.3.0 \
  --output /tmp/airflow-overlap.json
```

This stage selects records through repository and exact-package lanes, joins
transitive aliases without discarding source rows, isolates monorepo packages,
and constructs an advisory-by-checkpoint matrix. Its overlap count includes
only exact positive matches in OSV `affected.versions`. Native ecosystem or Git
ranges that still need evaluation remain visible instead of being treated as
proof that a checkpoint is safe.

Repeated `--checkpoint` values define release order and may use
`LABEL=OSV_VERSION`. The output reports every maximal checkpoint and the
earliest maximum in that supplied order. Without checkpoints, it inspects the
unordered union of explicit affected versions and deliberately does not claim
an earliest maximum.

The generated JSON contains raw advisory details and is maintainer-only.
Release tags still need immutable commit resolution, package/tag-namespace and
branch-ancestry checks, source inspection, scenario pruning, and exact-baseline
PoCs. See
`skills/auto-curate-oss-challenges/references/range-overlap.md`.
