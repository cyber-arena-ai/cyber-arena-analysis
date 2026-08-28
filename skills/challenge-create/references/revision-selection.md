# Revision-candidate protocol

Use this protocol before semantic review. Its output identifies bounded trial
revisions; it does not prove that a vulnerability reproduces.

## Terms

- **Advisory record:** one manifested upstream entry.
- **Deduplicated vulnerability:** records connected through transitive IDs or
  aliases. CVE and GHSA records for the same issue are one vulnerability.
- **Repair claim:** one source-linked assertion that an exact commit repairs the
  vulnerability.
- **Range claim:** one source-linked affected Git range. Claims remain
  independent even when their aliases match.
- **Revision candidate:** the sole parent of one claimed repair commit.

Deduplication prevents duplicate review. It does not authorize merging affected
ranges, computing coexistence across vulnerabilities, or treating any advisory
range as verified affected truth.

## Required evidence

A deduplicated vulnerability may enter Git resolution only when it has:

- behavioral evidence: non-empty advisory text or a public evidence reference;
- an exact repair claim for the selected application repository; and
- at least one structurally valid range claim for that repository.

Every repair and range claim records its archive, member, database, record IDs,
and exact affected item or reference position. Preserve disjoint range phases.
Reject a phase without an exact fix boundary because it cannot bound fallback
search. Do not discard a valid claim merely because another source disagrees.

## Candidate resolution

1. Use a cached commit-graph-only upstream clone and refresh its refs.
2. Resolve every nonzero range boundary and repair claim to a commit object.
3. Require a repair candidate to have exactly one Git parent. The parent is the
   primary trial commit; merge repairs must be traced to their underlying
   single-parent repair first.
4. Validate every range claim independently, including each disjoint phase and
   introduced-to-fixed ancestry. Do not union claims.
5. Link the repair candidate to range claims from the same source record or
   with the same fixed boundary. When neither link exists, retain the other
   valid claims for that deduplicated vulnerability as explicit alternatives.
6. Emit every valid repair-parent candidate independently. Do not select a
   commit that maximizes the number of reported vulnerabilities.

Stage 2 semantic review chooses one repair candidate and one fallback range
claim. It may select additional vulnerability components only when primary
evidence shows that they form the same coherent attack chain; mechanical Git
overlap is neither required nor computed.

## Commands

```bash
python3 <skill-root>/scripts/prepare_revision_claims.py \
  --candidates artifacts/candidates.json \
  --manifest artifacts/sources/osv/osv_manifest.json \
  --repository OWNER/PROJECT \
  --output-dir artifacts/projects/OWNER__PROJECT/stage2/revision-claims

python3 <skill-root>/scripts/resolve_revision_candidates.py \
  --claim-dir artifacts/projects/OWNER__PROJECT/stage2/revision-claims/revision_data \
  --repo-cache /tmp/cyber-arena-git-cache \
  --output-dir artifacts/projects/OWNER__PROJECT/stage2/revision-candidates
```

`semantic_packets/*.json` is the mechanical half of the Stage 3 handoff. Each
packet contains independent revision candidates, deduplicated advisory
evidence, complete source-linked repair and range claims, project metadata,
programmatic exclusions, and a hash of the complete resolver result.

## Stage 3 fallback search

Stage 3 tries the selected repair parent first. If it does not reproduce the
documented vulnerability, use the selected range claim to perform a bounded
binary subdivision of its Git ancestry. Test one midpoint at a time and retain
only the final reproduced commit. Treat disjoint phases independently. Stop and
return to Stage 2 if the selected claim cannot bound a coherent ancestry path or
if reproduction requires a different repair, vulnerability, application
boundary, or attack chain.

The search finds one reproducibly vulnerable commit; it does not validate every
commit in the advisory range.

## Claim boundary

The resolver proves only Git object identity, single-parent repair topology,
and structurally coherent source-linked bounds. Semantic review must establish
application fit, natural deployment, feature presence, attacker role, reachable
boundaries, plausible scopes, and configuration assumptions. Stage 3 must still
reproduce the primitive in-band and confirm the fixed comparison.
