---
name: auto-curate-oss-challenges
description: Run the OSS Cyber Arena auto-curation workflow from a retained OSV snapshot through evidence filtering, Git-range reconstruction, candidate-window prioritization, budgeted semantic scope review, and maintainer-only candidate dossiers. Use when discovering or assessing OSS applications and historical revisions before challenge implementation. Do not use for admission review of an implemented challenge.
---

# Auto-curate OSS challenges

Discover popular self-hosted network applications and historical Git windows
that may support Cyber Arena challenges. Treat early results as hypotheses, not
confirmed vulnerabilities or challenge admissions.

## Read first

1. Read `scripts/challenge_research/README.md` completely.
2. Read `docs/attack_scopes.json` before proposing capability scopes.
3. Read [range-overlap.md](references/range-overlap.md) before Git resolution.
4. Read [semantic-review.md](references/semantic-review.md) before Stage 3.
5. Read [dossier-template.md](references/dossier-template.md) before reporting.

Keep vulnerability, exploit, defense, and flag material maintainer-only.

## Stage 1: snapshot and shortlist

Use a retained project catalog, OSV archives, and hash manifest:

```bash
python3 skills/auto-curate-oss-challenges/scripts/shortlist_candidates.py \
  --projects docs/jt/oss_shortlist_prototype/projects.json \
  --raw-dir docs/jt/oss_shortlist_prototype/raw \
  --manifest docs/jt/oss_shortlist_prototype/osv_manifest.json \
  --output /tmp/oss-candidates.json
```

Optionally add a timezone-qualified cutoff:

```bash
  --published-after 2026-02-16T23:59:59Z
```

The command verifies snapshot hashes, joins transitive aliases, drops withdrawn
records, requires behavioral and exact repair evidence, and applies project
license, activity, application-signal, and popularity gates. It preserves
descriptions, references, severity context, package identities, CWEs, source
databases, fix commits, and exclusion context.

`projects` is the production discovery universe. `priority_projects` is only a
cheap review-order hint; never use it as an allowlist. Never reject a retained
component solely for class, CWE, CVSS, `AV:N`, apparent simplicity, advisory
count, or lack of particular keywords.

The cutoff compares the earliest active OSV publication strictly after the
supplied timestamp. It is an experimental model-knowledge control, not an
authoritative disclosure-date claim.

If fresh data is required, use `scripts/challenge_research/discover_projects.py`
and `snapshot_osv.py` to create a new dated snapshot. Do not overwrite retained
inputs.

## Stage 2: reconstruct candidate windows

First retain the exact-version audit context for every hard-gated project:

```bash
python3 skills/auto-curate-oss-challenges/scripts/compute_candidate_overlaps.py \
  --candidates /tmp/oss-candidates.json \
  --raw-dir docs/jt/oss_shortlist_prototype/raw \
  --output-dir /tmp/oss-overlap
```

Then resolve affected Git ranges against cached commit graphs:

```bash
python3 skills/auto-curate-oss-challenges/scripts/resolve_git_windows.py \
  --overlap-dir /tmp/oss-overlap/overlap_data \
  --repo-cache /tmp/cyber-arena-git-cache \
  --output-dir /tmp/oss-git-windows
```

Use a fresh output directory for each retained run. The resolver rejects
components whose Git range, disjoint phase, fix, or fix parent cannot be
resolved. It evaluates fix-parent event points, separates incomparable
lineages, records the complete chronology, and retains up to five windows per
application using widest-overlap then marginal component-set diversity. It
refreshes the cached upstream refs and evaluates current `HEAD` separately.
Use `--offline-cache` only for a bounded test; the packet will mark HEAD
freshness as unverified.

`semantic_packets/*.json` is the Stage 3 handoff. A packet is ready when it has
at least one non-empty, commit-resolved, evidence-complete historical window.
This does not establish self-hostability, feature presence, reachability,
scope, exploitability, or challenge depth. A non-clean HEAD assessment does not
invalidate historical windows, but it blocks the snapshot-limited
mostly-secure-HEAD claim until reviewed.

When the requested stop boundary is programmatic discovery, stop here and
report the retained applications, selected windows, exclusions, and HEAD
caveats.

## Stage 3: budgeted semantic scope review

Read [semantic-review.md](references/semantic-review.md). Review application fit
once, then cluster the selected advisories and inspect only enough public
evidence to characterize plausible scenarios and registered capability scopes.
Reuse one advisory assessment across every window containing it.

Use upstream documentation, advisory text, PoC or regression descriptions,
fix/PR context, and minimal patch summaries. Do not build the application,
inspect the full source tree, execute a PoC, prove path independence, or infer
AwD quality.

Return `promising`, `uncertain`, or `low_potential`. Budget exhaustion is
`uncertain`, not rejection. Permanently exclude only an application mismatch or
a failed operational hard gate. Record unsupported steps and exact checks
deferred to implementation.

Validate a completed review batch:

```bash
python3 skills/auto-curate-oss-challenges/scripts/validate_semantic_reviews.py \
  --packet-dir /tmp/oss-git-windows/semantic_packets \
  --review-dir /tmp/oss-semantic-reviews \
  --scope-registry docs/attack_scopes.json
```

## Report

After semantic review, produce one maintainer-only
`docs/jt/oss_candidates/POTENTIAL_CHALLENGE_<PROJECT>.md` dossier per retained
application. Follow [dossier-template.md](references/dossier-template.md) and
include:

- project fit and source provenance;
- complete programmatic chronology and the three to five prioritized windows;
- scenario and scope hypotheses with confidence;
- behavioral and repair evidence;
- assumptions, exclusions, and HEAD caveats; and
- exact implementation checks still required.

Candidate scopes remain unconfirmed until an exact-checkpoint in-band
reproduction reaches an independent witness. After a challenge is implemented
and registered, hand it off to `$challenge-review` in `cyber-arena-orche`.

Validate completed dossiers with:

```bash
python3 skills/auto-curate-oss-challenges/scripts/validate_dossiers.py \
  --scope-registry docs/attack_scopes.json \
  <dossier.md> [<dossier.md> ...]
```
