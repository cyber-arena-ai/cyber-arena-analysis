---
name: challenge-create
description: Run the OSS Cyber Arena workflow from source discovery through Git-window reconstruction, semantic triage, Docker feasibility study, challenge-warehouse authoring, registration, and PR handoff. Use when discovering or validating historical OSS revisions, implementing a ready candidate in challenge-warehouse, registering it, or documenting it for submission. Do not use for independent admission review.
---

# Challenge create

Discover advisory-linked self-hosted network applications and historical Git
windows that may support Cyber Arena challenges. Treat early results as
hypotheses, not confirmed vulnerabilities or challenge admissions.

## Read first

Resolve the directory containing this file as `<skill-root>`.
Use Python 3.11 or newer for all bundled scripts.
Before Stage 2, locate the separate `cyber-arena-docs` checkout as
`<docs-root>`. Before Stage 4, locate `cyber-arena-orche` as `<orche-root>`.

1. Read [source-discovery.md](references/source-discovery.md) and
   [advisory-source-roles.md](references/advisory-source-roles.md) completely
   before Stage 1.
2. Read [attack-scopes.json](references/attack-scopes.json) before proposing capability scopes. Treat
   advisory CWE weakness labels as root-cause evidence, not as the Technical
   Impact proved by a flag.
3. Read [range-overlap.md](references/range-overlap.md) before Git resolution.
4. Read `<docs-root>/docs/challenge-model.md` completely before semantic triage,
   runtime study, or authoring. It is the normative source of truth.
5. Read [advisory-enrichment.md](references/advisory-enrichment.md) and
   [semantic-review.md](references/semantic-review.md) before semantic triage in
   Stage 2.
6. Read [stage3-study.md](references/stage3-study.md) before runtime study.
7. Read [dossier-template.md](references/dossier-template.md) when maintaining a
   research-shortlist dossier.
8. Read `<orche-root>/docs/CHALLENGE_AUTHORING_SOP.md` completely before Stage
   4. Treat that file as the authoritative authoring contract.

Keep vulnerability, exploit, defense, and flag material maintainer-only.

## Retained artifacts

Persist retained outputs at stable paths under the local `artifacts/` working
directory and publish durable copies to the designated Hugging Face dataset.
Treat artifacts as data: the local directory is Git-ignored and its contents
must not be committed to this repository. Use `/tmp` only for caches, clones,
and failed experiments.

Keep this layout:

```text
artifacts/
├── sources/
│   ├── challenge-inventory.json      # optional duplicate context
│   └── osv/
│       ├── osv_manifest.json         # every archive consumed downstream
│       └── raw/                      # OSV plus normalized complements
├── candidates.json
├── candidate-views/                  # optional hash-linked queue views
└── projects/OWNER__PROJECT/
    ├── stage2/
    │   ├── overlaps/overlap_data/OWNER__PROJECT.json
    │   ├── git-windows/OWNER__PROJECT.json
    │   ├── git-windows/semantic_packets/OWNER__PROJECT.json
    │   └── semantic-reviews/
    │       ├── OWNER__PROJECT.json
    │       └── evidence/
    ├── stage3/
    ├── stage4/
    │   ├── warehouse/
    │   └── pr-report.md
    └── review/
```

The source corpus is dynamically refreshed at `artifacts/sources/`; do not copy
it into project directories. Large archives may use Hugging Face/LFS, but the
paths or artifact references recorded in `candidates.json` must remain
retrievable. Git caches and Stage 1–3 source worktrees are not required pipeline
artifacts. Retain the Stage 4 warehouse worktree at
`artifacts/projects/OWNER__PROJECT/stage4/warehouse`. Generated overlap
Markdown and human dossiers are not required pipeline artifacts. Do not create
per-project README or status-summary files; the structured stage artifacts are
authoritative.

## Stage 1: refresh sources and shortlist

Use the base corpus, fast lanes, and enrichment sources defined in
[advisory-source-roles.md](references/advisory-source-roles.md). Keep their
definitions there so adding or changing a lane does not expand this entrypoint.

When the manifest contains a `fast_lane` source, the command below selects only
alias components seeded by an active record from such a source, then enriches
them from the complete manifested union. With no fast-lane source it preserves
the legacy full-corpus behavior. It filters and joins aliases before making any
GitHub request, then fetches current metadata only for surviving application
repositories:

```bash
python3 <skill-root>/scripts/shortlist_candidates.py \
  --raw-dir artifacts/sources/osv/raw \
  --manifest artifacts/sources/osv/osv_manifest.json \
  --duplicate-inventory artifacts/sources/challenge-inventory.json \
  --metadata-cache artifacts/sources/github_repository_metadata.json \
  --output artifacts/candidates.json
```

Omit `--duplicate-inventory` when no retained inventory is available. Its
schema is defined in [source-discovery.md](references/source-discovery.md).

`candidates.json` is canonical after the ordinary Stage 1 gates and complete
with respect to publication date: no candidate is removed because it is old or
has an unknown date. When a particular experiment needs a model-knowledge
boundary, create a separate hash-linked view:

```bash
python3 <skill-root>/scripts/filter_candidates_by_date.py \
  --candidates artifacts/candidates.json \
  --published-after 2026-02-16T23:59:59Z \
  --output artifacts/candidate-views/published-after-2026-02-16.json
```

The view records `after`, `at_or_before`, and `unknown` component buckets. It
contains references rather than copied evidence and is not a replacement
candidate index. Use it to choose work, then run Stage 2 from the canonical
`candidates.json`. Never change the cutoff merely to force a desired queue
size.

The command verifies every manifest-listed archive, joins transitive aliases,
drops withdrawn and malicious-package records, and requires behavioral
evidence. A fast-lane seed without repair and a release-only repair both stay
unresolved until an exact Git repair is established for Stage 2. The command
resolves the application repository from affected Git ranges, package
references, or upstream repository security advisories; a fix-only repository
also stays unresolved. Promotion to `projects` also requires a structurally
usable affected Git range for that application, with an exact fixed boundary in
every phase.
Only then does it fetch current GitHub metadata and apply the archived,
activity, OSS-license, and deployable-service gates. Missing license, service,
repository, Git-range, or Git-repair evidence remains explicit in
`unresolved_candidates`. Metadata-only service contradictions and apparent
non-service shapes also remain unresolved; only archived or inactive status is
a hard project-metadata exclusion. The metadata cache checkpoints each
completed GitHub lookup so a rate limit or transient failure can resume without
repeating earlier requests. Delete or replace the cache only when intentionally
refreshing mutable repository metadata.

`candidates.json` is the persistent Stage 1 result. Its evidence matrix records
every selected component's resolved, unresolved, or rejected disposition and
which Stage 1 assets were observed. It also retains accepted `projects`,
unresolved mappings or project gates, exclusion counts, mutable metadata with
its observation time, repository-role evidence, and full repair provenance,
including retained components whose publication date is unknown.
Stars and forks are raw metadata and final tie-breakers only. There is no
popularity score, project catalog, or `priority_projects` allowlist. Never
reject a retained component solely for class, CWE, CVSS, `AV:N`, apparent
simplicity, advisory count, publication date, or lack of particular keywords.

Use `<skill-root>/scripts/snapshot_osv.py` to refresh the OSV base corpus. Add
normalized complementary advisory archives to the same hash manifest before
shortlisting; Stage 2 consumes that exact manifested union too. Source roles
select work and determine enrichment behavior; they do not create a parallel
advisory corpus. Publish the updated sources and derived artifacts together to
the designated Hugging Face dataset so its history preserves provenance. Never
commit them to this repository.

## Stage 2: reconstruct and triage candidate windows

First retain the exact-version audit context for every hard-gated project:

```bash
python3 <skill-root>/scripts/compute_candidate_overlaps.py \
  --candidates artifacts/candidates.json \
  --raw-dir artifacts/sources/osv/raw \
  --manifest artifacts/sources/osv/osv_manifest.json \
  --repository OWNER/PROJECT \
  --output-dir artifacts/projects/OWNER__PROJECT/stage2/overlaps
```

Then resolve affected Git ranges against cached commit graphs:

```bash
python3 <skill-root>/scripts/resolve_git_windows.py \
  --overlap-dir artifacts/projects/OWNER__PROJECT/stage2/overlaps/overlap_data \
  --repo-cache /tmp/cyber-arena-git-cache \
  --output-dir artifacts/projects/OWNER__PROJECT/stage2/git-windows
```

Update the project's stable Stage 2 paths together. The resolver rejects
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
invalidate historical windows, but it blocks the corpus-limited
mostly-secure-HEAD claim until reviewed.

When the requested stop boundary is programmatic discovery, stop here and
report the retained applications, selected windows, exclusions, and HEAD
caveats.

### Semantic triage

First read [advisory-enrichment.md](references/advisory-enrichment.md),
[semantic-review.md](references/semantic-review.md), and the repository root
`CONTRIBUTING.md`. Treat the manifested advisory union as retained evidence
rather than a complete advisory universe. Decide whether the strongest
candidate deserves an expensive Stage 3 study. Require one understood, natural
attack chain and its repair; do not require a second route, post-fix survivor,
multi-CVE ladder, minimum patch size, or apparent defensive depth.

A `promising` result needs three connected bundles of primary upstream
evidence. Stop early when upstream evidence decisively defeats the case:

- `attack_chain`: advisory, PoC, or regression evidence; exact-revision
  authentication, authorization, entry-point, and consumer source; supported
  workflow; and, when needed, the application-mediated proof-state lifecycle
  and a non-credential locator;
- `repair`: exact fix, PR, or tests plus affected/fixed release evidence;
- `operability`: official self-hosting, source-build, dependency, persistence,
  health, privilege, and restart or reload documentation.

Clone or download exact upstream material when useful. Keep analysis bounded to
the selected chain, repair, and operability. Do not build, deploy, run a PoC, or
design flags and checkers in Stage 2. Build the strongest complete case, try to
defeat it with the strongest evidence-backed objection, and assess whether the
documented application is realistically runnable and editable. Missing
principals, consumers, prerequisites, protected assets, or deployment
foundations are Stage 2 evidence gaps, not runtime measurements for Stage 3.

Use an existing registered scope when it fits. If none fits, define one
`custom.<challenge_id>.*` scope inline with exactly one registered CWE Technical
Impact parent, a concrete target and boundary, and an independent proof
requirement. Do not add a near-duplicate global category during curation.

Return `promising` only when the attack chain, repair, and operability all have
affirmative upstream support and Stage 3 only needs live confirmation or
measurement. Return `uncertain` when an essential upstream fact is missing or
conflicting; keep it in Stage 2 and name that evidence gap. Return
`low_potential` when upstream evidence defeats the case or the documented
architecture is incompatible. Budget exhaustion is `uncertain`, not rejection.
Preserve one compact decision and its retained evidence, not intermediate notes
or one assessment per advisory.

Validate a completed review batch:

```bash
python3 <skill-root>/scripts/validate_semantic_reviews.py \
  --packet-dir artifacts/projects/OWNER__PROJECT/stage2/git-windows/semantic_packets \
  --review-dir artifacts/projects/OWNER__PROJECT/stage2/semantic-reviews \
  --scope-registry <skill-root>/references/attack-scopes.json
```

Only a validated `promising` packet and matching semantic review are eligible
Stage 3 input. Do not begin runtime study from the packet alone or from an
`uncertain` review.

### Stage 2 result and resume boundary

The persistent result is the exact Git-window result, schema-v2 semantic packet,
schema-v4 semantic review, and retained evidence extracts. The review is
hash-linked to its packet. Resume Stage 3 only from a validated `promising`
review; resume an `uncertain` result in Stage 2.

## Stage 3: runnable feasibility study

Read [stage3-study.md](references/stage3-study.md) and study one proposed
challenge kernel from one selected window in a disposable Docker environment.
Retain the feasibility study under the project's `stage3/` directory; keep
disposable source worktrees, containers, and images in `/tmp`. Establish the
four proof obligations in that reference: exact target, reproduced primitive
and fixed comparison, understood attack chain and affected features, and a
natural trial witness without an obvious dominant shortcut. Confirm every
proposed scope by mapping its live witness to the scope's registered CWE
Technical Impact. Local flag tiers express progression or partial credit, not
universal severity.

Validate only the study's mechanical linkage and artifact presence:

```bash
python3 <skill-root>/scripts/validate_stage3_study.py \
  --packet artifacts/projects/OWNER__PROJECT/stage2/git-windows/semantic_packets/OWNER__PROJECT.json \
  --review artifacts/projects/OWNER__PROJECT/stage2/semantic-reviews/OWNER__PROJECT.json \
  --study-dir artifacts/projects/OWNER__PROJECT/stage3/<study-name>
```

Only `ready_for_authoring` studies proceed to Stage 4. `needs_study` names one
decisive unresolved fact; `rejected` records why authoring would measure the
wrong capability or admit an obvious shortcut.

## Stage 4: author and register

Treat the accepted Stage 3 study as the vulnerability and capability contract.
Create an independent Git worktree from the current challenge-warehouse
`origin/main` at `artifacts/projects/OWNER__PROJECT/stage4/warehouse`. Enable
sparse checkout for `_registry` and `<contributor>/<challenge>`; do not
materialize unrelated challenge packages.

Follow `<orche-root>/docs/CHALLENGE_AUTHORING_SOP.md` to implement the smallest
complete package in that worktree. Run the canonical static, build, and game
verification path from orchestration with the worktree selected as the
challenge warehouse. Modify orchestration only when the challenge requires a
genuine framework change.

Do not proceed to independent admission review until the registered challenge
passes the canonical verifier. Hand the result to `$challenge-review`; do not
review your own implementation through this skill.

## Optional human dossier

Do not create a separate dossier during routine batch curation; it duplicates
the resolved result and semantic review. If a maintainer explicitly requests a
standalone narrative, read [dossier-template.md](references/dossier-template.md)
and validate it with:

```bash
python3 <skill-root>/scripts/validate_dossiers.py \
  --scope-registry <skill-root>/references/attack-scopes.json \
  <dossier.md> [<dossier.md> ...]
```

Candidate scopes remain unconfirmed until the runnable study reaches an
independent witness.

## Challenge PR report

After Stage 4 is complete, write one standalone
`artifacts/projects/OWNER__PROJECT/stage4/pr-report.md`. Keep it concise and use
exactly four headings:

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
