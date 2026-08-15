# Git-range and candidate-window protocol

Use this protocol before semantic review. Its output is a high-recall history
map, not proof that a vulnerability is reachable or interesting.

## Terms

- **Advisory record:** one OSV source entry.
- **Advisory component:** records connected through transitive IDs or aliases;
  count the component once at a checkpoint.
- **Reported affected:** the checkpoint satisfies the retained OSV Git range.
- **Historical window:** comparable checkpoints with the same reported-affected
  component set.
- **Candidate checkpoint:** the representative immutable commit selected from
  a historical window.

Never shorten `reported_affected` to `present` in a dossier. Git-range evidence
does not establish feature presence, configuration, reachability, or exploit
behavior. In particular, `introduced: 0` is an OSV range boundary, not proof
that the vulnerable feature existed at repository origin.

## Required evidence

Retain raw OSV records, package identities, every range event, references,
aliases, source database, withdrawal state, and source-corpus provenance. A
component may enter Git resolution only when it has:

- behavioral evidence: non-empty advisory text or a public evidence reference;
- repair evidence: an immutable GitHub fix boundary; and
- an affected Git range for the selected repository.

Treat `introduced` as inclusive and `fixed` as exclusive. Preserve disjoint
phases. Reject a phase without an exact fix boundary; it cannot support a
bounded historical checkpoint. Preserve package and monorepo identities for
semantic review.

## Window reconstruction

1. Use a cached, commit-graph-only upstream clone.
2. Refresh upstream refs, then resolve every nonzero range event and fix parent
   to a commit object. An offline-cache test must label HEAD freshness as
   unverified.
3. Use each fix parent as a candidate event point. Do not scan every commit.
4. Evaluate every retained component at each event point with Git ancestry.
5. Drop empty event points and collapse comparable checkpoints with the same
   component set into one historical window. Keep incomparable lineages
   separate.
6. Prefer an exact stable release tag when one points at a candidate event;
   otherwise keep the fix parent.
7. Retain up to five windows. Select the widest reported overlap first, then
   greedily add windows with different component sets. Prefer multi-advisory,
   stable, HEAD-lineage, and recent alternatives when the diversity signal is
   tied.
8. Evaluate current `HEAD` separately. Never include it as a historical
   vulnerable checkpoint.

The prioritization is a transparent sequence of signals, not an authoritative
quality score. Retain the full chronological window inventory so later review
can choose a non-maximal alternative.

## Commands

Build the exact-version audit context, then resolve Git ranges:

```bash
python3 <skill-root>/scripts/compute_candidate_overlaps.py \
  --candidates artifacts/candidates.json \
  --raw-dir artifacts/sources/osv/raw \
  --repository OWNER/PROJECT \
  --output-dir artifacts/projects/OWNER__PROJECT/stage2/overlaps

python3 <skill-root>/scripts/resolve_git_windows.py \
  --overlap-dir artifacts/projects/OWNER__PROJECT/stage2/overlaps/overlap_data \
  --repo-cache /tmp/cyber-arena-git-cache \
  --output-dir artifacts/projects/OWNER__PROJECT/stage2/git-windows
```

`semantic_packets/*.json` is the Stage 3 handoff. Each packet contains the
selected windows, deduplicated advisory evidence, project metadata, current
HEAD assessment, exclusions, and a hash of the complete chronological result.
The complete result remains adjacent to the packet.

## Claim boundary

The resolver proves only that retained OSV Git relations evaluate to the
reported component sets at immutable commits. Semantic review must still check
application fit, natural deployment, feature presence, attacker role,
reachable boundaries, plausible scopes, and configuration assumptions.
Implementation must still prove an in-band exploit and AwD quality.

## Regression cases

| Project | Shape to preserve |
| --- | --- |
| Airflow | Package renames, providers, tag namespaces, backports, and incompatible release windows. |
| Grafana | A fix parent may be more useful than a published release. |
| Jenkins | Maven core history does not establish controller/agent reachability. |
| Keycloak | Multiple Maven modules require an explicit server deployment identity. |
| Nextcloud | Server Git ranges and separately versioned bundled applications must remain distinct. |
| Superset | Reachability may depend on database engine and role configuration. |

Any implementation that flattens these cases into one repository-level range
or manufactures coexistence with cherry-picks is incomplete.
