# Optional Stage 1.5 evidence resolution

Use this stage only on maintainer request to spend bounded agent effort on
high-ranked candidates that did not satisfy the mechanical Stage 2 admission
predicate. It increases coverage; it is not part of the default path and does
not relax any Stage 2 requirement.

## Declare the allocation before delegation

Use a ranked view whose source hash matches the current `candidates.json`.
Before spawning any subagent, tell the maintainer:

- the view and bucket being used;
- the exact unresolved rank interval and candidate IDs or repositories;
- the total number of candidates;
- the total number of subagents, counting nested agents;
- each agent's non-overlapping candidate allocation; and
- the stopping condition for this pass.

If the maintainer did not provide both the range and agent count, propose
concrete bounds and wait for confirmation. Do not let subagents widen their
allocation, recursively delegate beyond the declared total, replace rejected
candidates with later ranks, or begin another pass without a new declaration.
Available concurrency may reduce simultaneous execution, but it must not
increase the declared number of agents or candidates.

For example, an allocation may cover unresolved ranks 1 through 20 with four
subagents, five named candidates per agent, for one primary-evidence pass. The
numbers are an example, not a default.

## Resolve evidence, not verdicts

Drive work from the matrix's missing assets and retained reason. Treat both as
lookup guidance: a false bit means evidence was not present in the manifested
inputs, not that the asset is absent upstream.

Use primary upstream advisories, repository history, exact patches, pull
requests, regression tests, release tags, license files, and official
deployment documentation. Cloning or downloading exact source is allowed.
Do not build, deploy, execute a PoC, conduct semantic triage, or design a
challenge in Stage 1.5.

An agent may establish or disprove only the missing mechanical facts, such as:

- an unambiguous application repository;
- an exact application-repository repair commit and its affected parent;
- a structurally usable affected Git phase;
- authoritative OSS-license evidence;
- official self-hosted network-service evidence; or
- current repository activity and canonical identity.

Add established evidence through a supported Stage 1 input: correct or add a
complete normalized complementary record, update its manifest entry, or
intentionally refresh the GitHub metadata cache. Do not edit
`candidates.json`, a date view, or a ranked view by hand. If affirmative
upstream evidence cannot be represented by those sources, record only the
maintainer-approved candidates in
`artifacts/sources/stage1_5_evidence.json`. This hash-linked input carries two
facts that ordinary sources cannot express reliably: immutable official service
documentation and, when necessary, a direct repair with replacement application
Git events. Keep each entry component-scoped so a bounded pass cannot promote
other advisories from the same repository. Use schema version 1:

```json
{
  "schema_version": 1,
  "resolutions": [
    {
      "component_id": "CVE-2026-0001",
      "repository": "owner/project",
      "service_evidence": "https://github.com/owner/project/blob/0123456789abcdef0123456789abcdef01234567/README.md",
      "repair": {
        "commits": [{
          "sha": "123456789abcdef0123456789abcdef012345678",
          "affected_parent": "0123456789abcdef0123456789abcdef01234567",
          "url": "https://github.com/owner/project/commit/123456789abcdef0123456789abcdef012345678"
        }],
        "events": [
          {"introduced": "0"},
          {"fixed": "123456789abcdef0123456789abcdef012345678"}
        ]
      }
    }
  ]
}
```

Service evidence must be an immutable official GitHub blob URL. Repair URLs,
commits, affected parents, and every range boundary must be exact. The fixed
boundaries must equal the listed direct repairs. Omit `repair` when the
manifested direct repair and Git range are already correct. This file has no
verdict or promotion field: the shortlist validates the evidence and applies
the ordinary mechanical gates.

## Recompute and stop

After integrating the bounded evidence pass, rerun Stage 1 from the manifested
union with the additional input:

```bash
python3 <skill-root>/scripts/shortlist_candidates.py \
  --raw-dir artifacts/sources/osv/raw \
  --manifest artifacts/sources/osv/osv_manifest.json \
  --duplicate-inventory artifacts/sources/challenge-inventory.json \
  --metadata-cache artifacts/sources/github_repository_metadata.json \
  --stage1-5-evidence artifacts/sources/stage1_5_evidence.json \
  --output artifacts/candidates.json
```

Recreate any requested date view and rerank it. The persistent Stage 1.5 result
is the hash-linked evidence input, refreshed source provenance, regenerated
`candidates.json`, and ranked view.

Report, within the declared candidate range:

- candidates newly materialized under `projects[]`;
- candidates decisively hard-excluded and the upstream evidence;
- candidates still missing evidence and the exact asset or plumbing gap; and
- agent and candidate counts actually used.

Only the first group may enter Stage 2. Stopping with fewer resolved candidates
than requested is correct; do not consume later ranks or launch more agents to
force a target count.
