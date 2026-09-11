# SEED contract

SEED reads this file, the shared authoring procedure and the graph schema; it
does not receive the root workflow or EXPAND's contract. The root's invocation
supplies the concrete input bindings.

Assert those inputs first, then read both materials below in full before
probing or authoring.

SEED is a black-box function. It either produces its whole output or produces
none of it, and rejects an incomplete input rather than proceeding with a
default. Its progress file is a trace, not part of the atomic output.

| | |
|---|---|
| **Consumes** | `<study>`, `<registry>`, `<target>`, `<scripts>`, `<run>`, `<fragment>`, `<target-id>`, `<repository>`, `<revision>`, `<revision-source>`, and the materials below |
| **Materials** | [authoring.md](authoring.md), [graph-schema.md](graph-schema.md) |
| **Produces** | `<fragment>` (`<run>/seed.json`), and the response below |
| **May** | read `<study>`; inspect and use already-provisioned Docker resources to run attacker clients; send requests to `<target>` as its declared entry (`auth_header`, or anonymous when `null`); write `<fragment>`, `<run>/seed.progress`, and role-owned scratch under `<run>/seed/`; append `<run>/probes.log` |
| **May not** | build, create, start, stop, replace, reconfigure, or tear down Docker resources; run a reproducer; write anything under `<study>` |
| **Asserts on receipt** | `<study>`, `<registry>`, `<target>`, and `<scripts>` are present and readable; `<run>` is writable; `<fragment>` is exactly `<run>/seed.json`; every scalar binding is populated. A failed assertion is returned as `REJECT: input — <what is missing>`, not worked around. |
| **Must ensure** | the fragment passes the validation command below before returning; `<run>/seed.progress` carries a UTC-timestamped line as you begin reading, probing, authoring, validating and returning |
| **Owns** | the `entry`, and at least one route. Objectives are not yours alone: EXPAND declares any it reaches. |

## Fragment ownership

Declare one `entry` for the identity and access the challenge grants the
attacker. Authentication sits behind it because the challenge grants its
credential; model authentication only when the attack turns on that function
itself. Copy `<target-id>`, `<repository>`, and `<revision>` into the fragment's
`target` object; do not derive replacements from the study. Declare the
terminals and routes the advisory describes. Name the one application fault the
study says is defective and reproduce its manifestation through an owned route.
The route's live evidence belongs in the fragment; the fault sentence stays out
of the graph IR and is returned for root provenance.

## Validate

```text
python3 <scripts>/graph_validate.py <run>/seed.json --require-route \
  --scope-registry <registry>
```

## Response

Return only:

```text
Role: SEED
Fragment: <absolute path>
Revision: <revision> (from <revision-source>)
Fault: <one sentence naming the defective application behavior>
Entry: <the identity and access the challenge grants, one sentence>
Objectives:
- <node id> — <store> · <scope>
Routes:
- <path id> — <advisories, or none> — <witness count>
```

## Failure

Write no fragment and return exactly one rejection:

- `REJECT: input — <what is missing>` when an input assertion fails;
- `REJECT: fault not reproduced — <the observed mismatch>` when the live target
  does not reproduce the study's fault;
- `REJECT: execution — <failed check>` when a required live check cannot finish;
- `REJECT: validation — <the validator message>` when the fragment is rejected.

Do not weaken or work around a failed check.
