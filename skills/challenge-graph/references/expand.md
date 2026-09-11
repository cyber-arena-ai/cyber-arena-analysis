# EXPAND contract

EXPAND reads this file, the shared authoring procedure and the graph schema; it
does not receive the root workflow or SEED's contract. The root's invocation
supplies the concrete input bindings and SEED artifacts.

Assert those inputs first, then read both materials below in full before
probing or authoring.

EXPAND is a black-box function. It either produces its whole output or produces
none of it, and rejects an incomplete input rather than proceeding with a
default. Its progress file is a trace, not part of the atomic output.

| | |
|---|---|
| **Consumes** | `<study>`, `<registry>`, `<target>`, `<scripts>`, `<run>`, `<fragment>`, `<fault>`, `<seed>`, `<analysis>`, and the materials below |
| **Materials** | [authoring.md](authoring.md), [graph-schema.md](graph-schema.md) |
| **Produces** | On success, `<fragment>` (`<run>/expand.json`) — always, carrying no route when you found none — and the response below |
| **May** | read `<study>` and SEED's inputs; inspect and use already-provisioned Docker resources to run attacker clients; use `<target>` with its declared entry credentials; write `<fragment>`, `<run>/expand.progress`, and role-owned scratch under `<run>/expand/`; append `<run>/probes.log` |
| **May not** | build, create, start, stop, replace, reconfigure, or tear down Docker resources; run the stand-up command; discover, create, or change the declared entry credentials; write anything under `<study>`; introduce an `entry` SEED does not declare |
| **Asserts on receipt** | `<study>`, `<registry>`, `<target>`, `<scripts>`, `<seed>`, and `<analysis>` are present and readable; `<run>` is writable; `<fragment>` is exactly `<run>/expand.json`; `<fault>` is populated. A failed assertion is returned as `REJECT: input — <what is missing>`, not worked around. |
| **Must ensure** | the fragment passes the validation command below; `<run>/expand.progress` carries a UTC-timestamped line as you begin reading, probing, authoring, validating and returning; every unsettled claim carries `Blocked by` |

## Fragment ownership

Copy SEED's `target` object and entry rather than drafting either. Redeclare a
shared node under SEED's exact id and `symbol`; `title` and `evidence` may
differ, and SEED's are kept. Narrow its `predecessors` to the ones your routes
use; the merge unions them. Declare any objective you reach on the target.
When you find no additional route, copy SEED's validated fragment, set `paths`
to `[]`, and remove `advisory_cut`; this is the complete default fragment for
that successful outcome.

## Expanding

1. **Start from SEED.** Treat `<fault>` as the established pivot and SEED's
   validated fragment as the known route to it. Use SEED's analysis to see the
   recorded coverage and its fragment to locate shared nodes. Do not rename the
   fault or repeat SEED's route merely to establish it again.

2. **Expand from the fault.** It is one named thing in the application, so this
   is bounded:

   - other routes that reach the same fault;
   - other objectives the same fault exposes — **declare them**, with a scope
     from the registry, when you reached one on the target. Nothing at Stage 3
     declares the objective; both roles reconstruct it, so yours stands beside
   SEED's. You may not introduce an `entry` SEED does not declare: that is
   the identity the challenge grants, and a second one changes the starting
   authority.

3. **Then, only where the study's own evidence suggests a second defect,** look
   for a route that avoids the nodes the routes you have already share.
   Secondary and speculative. Do not go looking for ways around functions that
   work.

4. **Run additions, then record them.** Run every proposed additional route with
   `probe.py`, or with a client that can send it and then `probe.py --record`,
   and carry what it prints into the graph as the observation itself.

`<fault>` stays out of the IR. It is an input anchor, never a graph field.

## Correction

Accept a `Correction` only with the original bindings unchanged and `output`
set to `fragment` or `response`. Correct only its exact `finding`. For
`fragment`, replace `<fragment>` as a complete document and rerun Validate; for
`response`, leave the validated fragment unchanged. Then return the complete
Response below, or a defined Failure if the correction cannot be completed.

## Validate

```text
python3 <scripts>/graph_validate.py <run>/expand.json \
  --scope-registry <registry>
```

## Response

Return only:

```text
Role: EXPAND
Fragment: <absolute path — always written, even carrying no route>
Routes added: <path ids, or none>
Unsettled:
- Claim: <the route, or the objective, the fault suggests>
  Reaches the fault by: <one sentence>
  Check: <the one command or request that would settle it>
  Blocked by: <the wall that stopped you running it>
```

Write `Unsettled: none` when no claim remains. A hypothesis you could have run
is unfinished work, not an unsettled claim: run it before returning.

## Failure

Write no fragment and return exactly one rejection:

- `REJECT: input — <what is missing>` when an input assertion fails;
- `REJECT: execution — <failed check>` when a required live check cannot finish;
- `REJECT: validation — <the validator message>` when the fragment is rejected.

Do not weaken or work around a failed check.
