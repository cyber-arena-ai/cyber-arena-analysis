# EXPAND contract

The root copies the dispatch below. EXPAND reads this file, the shared
authoring procedure and the graph schema; it does not receive the root
contracts or corpus notes.

EXPAND is a black-box function. It either produces its whole output or produces
none of it, and rejects an incomplete input rather than proceeding with a
default. Its progress file is a trace, not part of the atomic output.

| | |
|---|---|
| **Consumes** | `<study>`, `<registry>`, `<target>`, `<scripts>`, `<run>/seed.json`, `<run>/seed-analysis.json`, and the materials below |
| **Materials** | [expand.md](expand.md), [authoring.md](authoring.md), [graph-schema.md](graph-schema.md) |
| **Produces** | `<run>/expand.json` — always, carrying no route when you found none — and the response below |
| **May** | read `<study>` and SEED's inputs; send requests to `<target>` as that build's `auth_header`; write `<run>/expand.json` |
| **May not** | start, stop or build a container; run a reproducer; use host Docker; write anything under `<study>`; introduce an `entry` SEED does not declare |
| **Asserts on receipt** | every input above present and readable. A missing one is returned as `REJECT: <what is missing>`, not worked around. |
| **Must ensure** | the fragment passes the validation command in the dispatch; `<run>/expand.progress` carries a UTC-timestamped line per step; every unsettled claim carries `Blocked by`; `Needs study` names a search, never a missing citation |

## Fragment ownership

Copy SEED's entry rather than drafting one. Redeclare a shared node under
SEED's exact id and `symbol`; `title` and `evidence` may differ, and SEED's are
kept. Narrow its `predecessors` to the ones your routes use; the merge unions
them. Declare any objective you reach on the target.

## Expanding

1. **Name the fault.** Read what `STAGE3_STUDY.md` says is defective, then
   establish it against the running target. Never substitute a min-cut for the
   fault: a min-cut is arithmetic over the recorded routes and claims nothing
   about what is defective.

2. **Expand from the fault.** It is one named thing in the application, so this
   is bounded:

   - other routes that reach the same fault;
   - other objectives the same fault exposes — **declare them**, with a scope
     from the registry, when you reached one on the target. Nothing at Stage 3
     declares the objective; both roles reconstruct it, so yours stands beside
     SEED's. You may not introduce an `entry` SEED does not declare: that is
     the identity the challenge grants, and a second one lowers every cut.

3. **Then, only where the study's own evidence suggests a second defect,** look
   for a route that avoids the nodes the routes you have already share.
   Secondary and speculative. Do not go looking for ways around functions that
   work.

4. **Run it, then record it.** Run the check with `probe.py`, or with a client
   that can send it and then `probe.py --record`, and carry what it prints into
   the graph as the observation itself.

5. **Score what you did.** Do not assert a new `mincut_all`; the root re-runs
   the analyzer.

Root cause stays out of the IR: it lives in your response as a stated reading,
and never as a field.

## Dispatch

```text
Inputs — replace each name with an absolute path before sending:
  study     = <study>
  registry  = <registry>
  scripts   = <scripts>
  target    = <run>/target.json
  seed      = <run>/seed.json
  analysis  = <run>/seed-analysis.json
  fragment  = <run>/expand.json                     (write your fragment here)
  materials = <skill-root>/references/expand.md, authoring.md,
              graph-schema.md

You are the EXPAND role for the challenge graph over Stage 3 study <study>. Read the three materials listed above, in full, before anything else. You are given SEED's fragment and its analysis; you are blind to nothing. Name the fault the study reproduced, find further routes that reach it, and declare any further objective you reached, with a scope from the registry. The live target is described in <run>/target.json: use each build's base_url and auth_header, and read seeded to recognise the protected value. Run what you can against it using probe.py, as specified in authoring.md, recording what it prints as the observation; where probe.py cannot send the request, use a client that can and record the exchange with probe.py --record, so that every observation you cite matches a record in <run>/probes.log. Redeclare any node SEED declared under its exact id and symbol, narrowing only its predecessors. You may add function nodes, routes, and an objective you reached on the target; you may not introduce an entry SEED does not declare. Append one UTC-timestamped line to <run>/expand.progress as you begin each step of your procedure — reading, probing, authoring, validating, returning — so a dispatcher can tell you apart from a dead agent. Assert every input on receipt and return REJECT if one is missing. Gate your fragment with `python3 <scripts>/graph_validate.py <run>/expand.json --scope-registry <registry>` before returning, write your fault and unsettled claims for the root, and return only the EXPAND response.
```

## Response

```text
Role: EXPAND
Fault: <one sentence>
Fragment: <absolute path — always written, even carrying no route>
Routes added: <path ids, or none>
Unsettled:
- Claim: <the route, or the objective, the fault suggests>
  Reaches the fault by: <one sentence>
  Check: <the one command or request that would settle it>
  Blocked by: <the wall that stopped you running it>
Needs study: <when no route was found: the fault, and the search that failed>
```

**`Needs study` is a claim about a search**: you looked, and the fault reached
nothing further you could find. It is never "I found a route and could not
record it" — you can run the target, so run it, write the output to record it
as a probe observation. A hypothesis you *could* have run is not an unsettled
claim; it is unfinished work.

## Failure

Return a validation rejection to the root; do not weaken or work around the
check.
