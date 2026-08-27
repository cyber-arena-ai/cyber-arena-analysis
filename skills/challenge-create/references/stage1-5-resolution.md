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
upstream evidence exists but the current Stage 1 schema cannot express or
consume it, report a plumbing gap; do not manufacture readiness.

## Recompute and stop

After integrating the bounded evidence pass, rerun Stage 1 from the manifested
union, recreate any requested date view, and rerank it. The persistent Stage
1.5 result is the refreshed source provenance, regenerated `candidates.json`,
and hash-linked ranked view.

Report, within the declared candidate range:

- candidates newly materialized under `projects[]`;
- candidates decisively hard-excluded and the upstream evidence;
- candidates still missing evidence and the exact asset or plumbing gap; and
- agent and candidate counts actually used.

Only the first group may enter Stage 2. Stopping with fewer resolved candidates
than requested is correct; do not consume later ranks or launch more agents to
force a target count.
