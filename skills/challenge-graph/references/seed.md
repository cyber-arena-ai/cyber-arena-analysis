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
| **Consumes** | `<study>`, `<registry>`, `<target>`, `<scripts>`, `<target-id>`, `<repository>`, `<revision>`, `<revision-source>`, and the materials below |
| **Materials** | [authoring.md](authoring.md), [graph-schema.md](graph-schema.md) |
| **Produces** | `<run>/seed.json`, and the response below |
| **May** | read `<study>`; send requests to `<target>` as that build's `auth_header`; write `<run>/seed.json` |
| **May not** | start, stop or build a container; run a reproducer; use host Docker; write anything under `<study>` |
| **Asserts on receipt** | every path input above is present and readable, and every scalar binding is populated. A missing input is returned as `REJECT: <what is missing>`, not worked around. |
| **Must ensure** | the fragment passes the validation command below before returning; `<run>/seed.progress` carries a UTC-timestamped line as you begin reading, probing, authoring, validating and returning |
| **Owns** | the `entry`, and at least one route. Objectives are not yours alone: EXPAND declares any it reaches. |

## Fragment ownership

Declare one `entry` for the identity and access the challenge grants the
attacker. Authentication sits behind it because the challenge grants its
credential; model authentication only when the attack turns on that function
itself. Copy `<target-id>`, `<repository>`, and `<revision>` into the fragment's
`target` object; do not derive replacements from the study. Declare the
terminals and routes the advisory describes.

## Validate

```text
python3 <scripts>/graph_validate.py <run>/seed.json \
  --scope-registry <registry>
```

## Response

Return only:

```text
Role: SEED
Fragment: <absolute path>
Revision: <revision> (from <revision-source>)
Entry: <the identity and access the challenge grants, one sentence>
Objectives:
- <node id> — <store> · <scope>
Routes:
- <path id> — <advisories, or none> — <witness count>
```

## Failure

Return a validation rejection to the root; do not weaken or work around the
check.
