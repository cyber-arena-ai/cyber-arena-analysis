# SEED contract

The root copies the dispatch below. SEED reads this file, the shared authoring
procedure and the graph schema; it does not receive the root contracts or
corpus notes.

SEED is a black-box function. It either produces its whole output or produces
none of it, and rejects an incomplete input rather than proceeding with a
default. Its progress file is a trace, not part of the atomic output.

| | |
|---|---|
| **Consumes** | `<study>`, `<registry>`, `<target>`, `<scripts>`, and the materials below |
| **Materials** | [seed.md](seed.md), [authoring.md](authoring.md), [graph-schema.md](graph-schema.md) |
| **Produces** | `<run>/seed.json`, and the response below |
| **May** | read `<study>`; send requests to `<target>` as that build's `auth_header`; write `<run>/seed.json` |
| **May not** | start, stop or build a container; run a reproducer; use host Docker; write anything under `<study>` |
| **Asserts on receipt** | every input above present and readable. A missing one is returned as `REJECT: <what is missing>`, not worked around. |
| **Must ensure** | the fragment passes the validation command in the dispatch before returning; `<run>/seed.progress` carries a UTC-timestamped line per step |
| **Owns** | the `entry`, and at least one route. Objectives are not yours alone: EXPAND declares any it reaches. |

## Fragment ownership

Declare one `entry` for the identity and access the challenge grants the
attacker. Authentication sits behind it because the challenge grants its
credential; model authentication only when the attack turns on that function
itself. Declare the terminals and routes the advisory describes.

## Dispatch

```text
Inputs — replace each name with an absolute path before sending:
  study     = <study>
  registry  = <registry>
  scripts   = <scripts>
  target    = <run>/target.json
  fragment  = <run>/seed.json                       (write your fragment here)
  materials = <skill-root>/references/seed.md, authoring.md,
              graph-schema.md

You are the SEED role for the challenge graph over Stage 3 study <study>. Read the three materials listed above, in full, before anything else. Author the terminals and the routes the advisory describes, as one fragment at <run>/seed.json. You own the entry node, which no later role may add to. Declare every objective you reach; a later role may declare others it reaches. The live target is described in <run>/target.json: use each build's base_url and auth_header, and read seeded to recognise the protected value. Reach it with probe.py, as specified in authoring.md, and record what it prints as the observation on the node or route it establishes. probe.py is your fast path, not your only one: where it cannot send the request, use a client that can and bring the exchange back with probe.py --record. Every observation you cite must match a record in <run>/probes.log. Append one UTC-timestamped line to <run>/seed.progress as you begin each step of your procedure — reading, probing, authoring, validating, returning — so a dispatcher can tell you apart from a dead agent. Assert every input above on receipt and return REJECT if one is missing. Gate your fragment with `python3 <scripts>/graph_validate.py <run>/seed.json --scope-registry <registry>` before returning, and return only the SEED response.
```

## Response

```text
Role: SEED
Fragment: <absolute path>
Revision: <commit> (from <reproduced_commit|commit|vulnerable_commit>)
Entry: <the identity and access the challenge grants, one sentence>
Objectives:
- <node id> — <store> · <scope>
Routes:
- <path id> — <advisories, or none> — <witness count>
```

## Failure

Return a validation rejection to the root; do not weaken or work around the
check.
