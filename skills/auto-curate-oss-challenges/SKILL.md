---
name: auto-curate-oss-challenges
description: Run the OSS Cyber Arena auto-curation workflow from a retained OSV snapshot through evidence filtering, Git-window reconstruction, semantic triage, and a focused Docker feasibility study, or prepare a concise challenge PR report from completed curation and authoring evidence. Use when discovering and validating historical OSS revisions or documenting a challenge for submission. Do not use for implementing or admission-reviewing a complete challenge.
---

# Auto-curate OSS challenges

Discover popular self-hosted network applications and historical Git windows
that may support Cyber Arena challenges. Treat early results as hypotheses, not
confirmed vulnerabilities or challenge admissions.

## Read first

1. Read `scripts/challenge_research/README.md` completely.
2. Read `docs/attack_scopes.json` before proposing capability scopes. Treat
   advisory CWE weakness labels as root-cause evidence, not as the Technical
   Impact proved by a flag.
3. Read [range-overlap.md](references/range-overlap.md) before Git resolution.
4. Read [semantic-review.md](references/semantic-review.md) before semantic
   triage in Stage 2.
5. Read [stage3-study.md](references/stage3-study.md) before runtime study.
6. Read [dossier-template.md](references/dossier-template.md) when maintaining a
   research-shortlist dossier.

Keep vulnerability, exploit, defense, and flag material maintainer-only.

## Retained artifacts

Choose one retained work directory for the discovery run before starting. Use
`/tmp` only for caches, clones, and failed experiments. One run may contain many
applications; do not copy batch artifacts into each application's directory.

Keep only this discovery chain:

```text
<run>/candidates.json
<run>/overlaps/overlap_data/OWNER__PROJECT.json
<run>/git-windows/OWNER__PROJECT.json
<run>/git-windows/semantic_packets/OWNER__PROJECT.json
<run>/semantic-reviews/OWNER__PROJECT.json
```

Also retain the project catalog, OSV manifest, and raw archives named by the
manifest in one shared snapshot location. Large archives may live outside Git,
but the paths or artifact references recorded in `candidates.json` must remain
retrievable. Git caches, source worktrees, generated overlap Markdown, and
human dossiers are not required pipeline artifacts.

## Stage 1: snapshot and shortlist

Use a retained project catalog, OSV archives, and hash manifest:

```bash
python3 skills/auto-curate-oss-challenges/scripts/shortlist_candidates.py \
  --projects docs/jt/oss_shortlist_prototype/projects.json \
  --raw-dir docs/jt/oss_shortlist_prototype/raw \
  --manifest docs/jt/oss_shortlist_prototype/osv_manifest.json \
  --output <run>/candidates.json
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

## Stage 2: reconstruct and triage candidate windows

First retain the exact-version audit context for every hard-gated project:

```bash
python3 skills/auto-curate-oss-challenges/scripts/compute_candidate_overlaps.py \
  --candidates <run>/candidates.json \
  --raw-dir docs/jt/oss_shortlist_prototype/raw \
  --output-dir <run>/overlaps
```

Then resolve affected Git ranges against cached commit graphs:

```bash
python3 skills/auto-curate-oss-challenges/scripts/resolve_git_windows.py \
  --overlap-dir <run>/overlaps/overlap_data \
  --repo-cache /tmp/cyber-arena-git-cache \
  --output-dir <run>/git-windows
```

Use a fresh output directory for each retained run. The resolver rejects
components whose Git range, disjoint phase, fix, or fix parent cannot be
resolved. It evaluates fix-parent event points, separates incomparable
lineages, records the complete chronology, and retains up to five windows per
application using widest-overlap then marginal component-set diversity. It
refreshes the cached upstream refs and evaluates current `HEAD` separately.
Use `--offline-cache` only for a bounded test; the packet will mark HEAD
freshness as unverified.

`semantic_packets/*.json` is the semantic-triage input. A packet is ready when
it has at least one non-empty, commit-resolved, evidence-complete historical window.
This does not establish self-hostability, feature presence, reachability,
scope, exploitability, or challenge depth. A non-clean HEAD assessment does not
invalidate historical windows, but it blocks the snapshot-limited
mostly-secure-HEAD claim until reviewed.

When the requested stop boundary is programmatic discovery, stop here and
report the retained applications, selected windows, exclusions, and HEAD
caveats.

### Semantic triage

First read [semantic-review.md](references/semantic-review.md). Review
application fit once, cluster the selected advisories, and inspect only enough
public evidence to select one promising historical window and the vulnerability
primitives worth testing. Reuse one advisory assessment across every window
containing it.

Use upstream documentation, advisory text, PoC or regression descriptions,
fix/PR context, and minimal patch summaries. This pass prioritizes work; it does
not establish runtime facts.

Use an existing registered scope when it fits. If none fits, define one
`custom.<challenge_id>.*` scope inline with exactly one registered CWE Technical
Impact parent, a concrete target and boundary, and an independent proof
requirement. Do not add a near-duplicate global category during curation.

Return `promising`, `uncertain`, or `low_potential`. Budget exhaustion is
`uncertain`, not rejection. Record unsupported steps for the runnable study.
The semantic review is the Stage 2 report: for every window it must repeat the
exact checkpoint and complete component set from the packet, then state the
scenario, candidate scopes, witness hypothesis, and deferred runtime facts.

Validate a completed review batch:

```bash
python3 skills/auto-curate-oss-challenges/scripts/validate_semantic_reviews.py \
  --packet-dir <run>/git-windows/semantic_packets \
  --review-dir <run>/semantic-reviews \
  --scope-registry docs/attack_scopes.json
```

The packet and its matching semantic review are the Stage 3 input. Do not begin
runtime study from the packet alone.

## Stage 3: runnable feasibility study

Read [stage3-study.md](references/stage3-study.md) and study one proposed
challenge kernel from one selected window in a disposable Docker environment.
Runtime artifacts belong with the verification work in `cyber-arena-orche`, not
in this discovery repository. Establish the four proof obligations in that
reference: exact target, reproduced primitive and fixed comparison, understood
attack chain and affected features, and a natural trial witness without an
obvious dominant shortcut. Confirm every proposed scope by mapping its live
witness to the scope's registered CWE Technical Impact. Local flag tiers express
progression or partial credit, not universal severity.

Validate only the study's mechanical linkage and artifact presence:

```bash
python3 skills/auto-curate-oss-challenges/scripts/validate_stage3_study.py \
  --packet <run>/git-windows/semantic_packets/OWNER__PROJECT.json \
  --study-dir <cyber-arena-orche-stage3-study-dir>
```

Only `ready_for_authoring` studies proceed to Stage 4. `needs_study` names one
decisive unresolved fact; `rejected` records why authoring would measure the
wrong capability or admit an obvious shortcut.

## Optional human dossier

Do not create a separate dossier during routine batch curation; it duplicates
the resolved result and semantic review. If a maintainer explicitly requests a
standalone narrative, read [dossier-template.md](references/dossier-template.md)
and validate it with:

```bash
python3 skills/auto-curate-oss-challenges/scripts/validate_dossiers.py \
  --scope-registry docs/attack_scopes.json \
  <dossier.md> [<dossier.md> ...]
```

Candidate scopes remain unconfirmed until the runnable study reaches an
independent witness. A `ready_for_authoring` Stage 3 study is the input to the
Stage 4 authoring workflow in `cyber-arena-orche`; a completed and registered
challenge is then handed to `$challenge-review`.

## Challenge PR report

After Stage 4 is complete, write one standalone `pr-report.md` in the retained
per-challenge work directory. Keep it concise and use exactly four headings:

- **Source and service:** name the discovery database and advisory, link the
  upstream repository, identify the exact vulnerable revision and service, say
  who realistically uses it, and give its GitHub star count with observation
  date.
- **Vulnerability and patch:** explain each demonstrated upstream vulnerability
  that reaches a flag, its root cause and affected feature, whether it is
  patched, and how the cited fix commit or release closes it.
- **PoC:** summarize attacker prerequisites, the public attack path, the
  vulnerable operation, and the observed result; cite the retained runnable
  evidence instead of copying a large payload.
- **Flags and capabilities:** name every planted store, where the flag is placed,
  and the registered attacker capability and CWE Technical Impact that
  recovering it proves. One PoC may prove flags on an overlapping attack chain;
  materially independent paths need independent PoCs.

Reuse Stage 1–4 evidence and current upstream facts. Cite repository paths or
direct links, date mutable popularity data, state unknowns instead of guessing,
and never include a live flag value or secret. This is the PR handoff, not a new
review or another feasibility dossier.
