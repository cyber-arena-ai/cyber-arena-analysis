---
name: challenge-graph
description: "Build the attack-graph intermediate representation for one completed Cyber Arena Stage 3 study, then compute its geometry and objective coverage and render a diagram. Stands up the study's own bundle and probes the running target, so it starts containers and sends attacker traffic. Use when analyzing or visualizing what a challenge's reproduced attack structure is. Do not use to promote, reject, or review a challenge."
---

# Challenge graph

Turn one completed Stage 3 study into a graph of the attack structure it
reproduced, compute its geometry and objective coverage, and draw it.

You are the **root**: the executor. You call functions — scripts and subagents —
and own every deliverable. You do not author the graph you adjudicate.

## Workflow

| # | Step | Consumes | Produces |
|---|---|---|---|
| 1 | Read instructions | this skill | root and shared contracts |
| 2 | Bind | the invocation | `<study>`, `<out>`, `<run>`, tools |
| 3 | Inspect inputs | the Stage 3 bundle | verified semantic and runtime inputs |
| 4 | Provision | the verified bundle | `<target>` |
| 5 | SEED | `<target>`, role materials | `<run>/seed.json`, `<run>/seed-analysis.json`, `<fault>` |
| 6 | EXPAND | SEED's fault, fragment, and analysis | `<run>/expand.json`, the EXPAND response |
| 7 | Merge | both fragments | `graph.json`, `<run>/merge.json` |
| 8 | Adjudicate | `graph.json`, `<study>`, `<target>` | repaired fragments, or nothing |
| 9 | Derive | `graph.json` | `analysis.json` |
| 10 | Finalize | everything above | `provenance.json`, `graph.md`, `findings.md` |

### 1. Read instructions

Resolve the directory holding this file as `<skill-root>`. Read
[graph-schema.md](references/graph-schema.md) in full; it is the shared output
contract the root later adjudicates.

`references/seed.md` and `references/expand.md` are opaque role contracts. Do
not read, copy, or restate them. Start each role with no inherited conversation
or agent history (`fork_turns="none"` when using `spawn_agent`) and send only
the bootstrap in its dispatch step. Neither role receives root-only
instructions or the other role's contract. End each bootstrap
with: *Read the role contract in full, then only the instruction materials it
names. Follow it with these input bindings and return its specified response.*

### 2. Bind

The invocation is exactly one `<absolute-study-dir>`. Bind it as `<study>` and
reject extra arguments. Resolve the enclosing Git checkout as
`<analysis-root>` only when its origin identifies `cyber-arena-analysis`;
otherwise ask the user which checkout to use. Use Python 3.11 or newer.

Bind the fixed tool paths, then derive the two writable locations without
creating them yet:

```text
<registry> = <analysis-root>/skills/challenge-create/references/attack-scopes.json
<scripts>  = <skill-root>/scripts/
```

```text
<out> = <analysis-root>/artifacts/projects/<PROJECT>/graph/<study-name>/
```

Copy `<PROJECT>` and `<study-name>` verbatim from the study's own path — a
study at `artifacts/projects/<PROJECT>/stage3/...` writes to
`artifacts/projects/<PROJECT>/graph/...`. A study that *is* `stage3/`, with no
subdirectory under it, takes `stage3` as its `<study-name>`. Do not derive them
from `result.json`.

```text
<run> = /tmp/challenge-graph/<study-name>-<run-id>/
```

Use a fresh `<run-id>` for each run. `<run>` holds only intermediates; `<out>`
holds only the final deliverable.

### 3. Inspect inputs

Treat `<study>` as read-only. Before creating `<run>` or `<out>`, resolve every
item below. Use only the defaults stated here.

| Input | Source | Required or default |
|---|---|---|
| Semantic study | `<study>/STAGE3_STUDY.md`, read in full | Required. It must identify the attacker identity and public entrypoint, attack chain, vulnerable outcome, trial witness, and authoring consequences. |
| Graph identity | `target.id`; `repository`; and the exact reproduced revision | `target.id` defaults from `<study-name>` by the rule below, unless the semantic study names a short kebab-case challenge or study id. `repository` and revision are required from populated fields in `result.json`, otherwise from the semantic study. For the revision use `reproduced_commit`, then the legacy `commit` or `vulnerable_commit`; never substitute `primary_commit` or `repair_commit`. |
| Runnable reproduction | The study's own reproduction command and every environment or reproduction artifact it names | Required. It must start the studied target from a disposable copy. No runnable bundle is a terminal failure; do not dispatch the roles. |
| Retained observations | Vulnerable, repaired, lifecycle, or shortcut evidence named by the bundle | Every named file is required and remains read-only. It guides the rerun but is not evidence for the new graph. |
| Repaired case | The bundle's repaired build and comparison, when supplied | Default: absent. Omit `advisory_cut` when the study supplies no repaired case. |
| Stage 3 result | `<study>/result.json` | Default: absent. When present it is metadata and an artifact manifest; its `outcome` never gates this skill. |
| Scope registry | `<registry>` | Required external input; it is not part of the bundle. |

For the default `target.id`, lowercase `<study-name>`, replace each run of
characters outside `a-z0-9` with `-`, and trim leading or trailing `-`.

Reject an incomplete bundle. Otherwise bind `<target-id>`, `<repository>`,
`<revision>`, and `<revision-source>`, then create `<run>` and `<out>`. SEED
receives those resolved values; EXPAND inherits them from SEED's validated
fragment. Neither role repairs, discovers, or defaults the bundle inputs.

### 4. Provision

**You alone own Docker lifecycle and deployment mutation.** Roles may inspect
and use the already-provisioned Docker environment to run attacker clients, but
only you build, create, start, stop, replace, reconfigure, or tear down its
resources.

```text
python3 <scripts>/graph_provision.py <study> --run <run> \
  --reproducer "<the study's own command>"
```

This copies the bundle to `<run>/env/`, runs the reproducer there, and records
what came up in `<run>/target.json`. It writes that file before later checks so
the run remains tearable down. A non-zero exit is a terminal provisioning
failure; do not dispatch a role.

Complete `target.json` in place without removing its teardown record:

```json
{"reproducer": {"compose_projects": ["..."]},
 "builds": {"<name>": {"base_url": "http://127.0.0.1:<port>",
                          "auth_header": null}},
 "seeded": "<what the facility planted and how to recognise it>"}
```

Resolve any ambiguous `base_url` used for HTTP. An internal-only build keeps
`base_url` null and names its provisioned containers. Set `auth_header` to the
entry principal's `<header name>: <value>` and nothing more, or explicitly to
`null` when the study declares anonymous entry. Make the seeded value
recognisable.

For a credentialed entry, create the principal declared by the study; do not
reuse an identity the reproducer created. Use the facility credentials printed
by `graph_provision.py` when needed and record only the entry principal in
`auth_header`. For anonymous entry, do not invent a principal or credential.
Verify the declared baseline before dispatching either form.

`probe.py` sends HTTP, and it is the roles' fast path rather than their only
one. A study whose attack is a broker protocol, a WebSocket or a `git` transport
is still in scope: the roles reach it with a client that speaks it and record the
exchange with `probe.py --record`. What you owe them is a target they can reach —
if the bundle publishes no host port, or the attack needs the study's own
attacker container, say so in `seeded` so a role is not left guessing.

### 5. SEED

Dispatch SEED with only this bootstrap, after resolving every binding:

```text
Role contract: <skill-root>/references/seed.md
Inputs:
  study           = <study>
  registry        = <registry>
  scripts         = <scripts>
  run             = <run>
  target          = <run>/target.json
  fragment        = <run>/seed.json
  target_id       = <target-id>
  repository      = <repository>
  revision        = <revision>
  revision_source = <revision-source>
```

Handle a SEED rejection before reading its success response: `REJECT: validation`
returns to SEED for correction; `REJECT: input`, `REJECT: execution`, or
`REJECT: fault not reproduced` is terminal and delivers nothing. Otherwise
assert the response contains one non-empty `Fault` sentence and bind it exactly
as `<fault>`; return a missing sentence to SEED rather than inferring or
rewriting it. While SEED runs, `<run>/seed.progress` is where you look: the age
of its last line is how you tell a working role from a dead one. Then gate and
analyze:

```text
python3 <scripts>/graph_validate.py <run>/seed.json --require-route \
  --scope-registry <registry>
python3 <scripts>/graph_analyze.py <run>/seed.json \
  --out <run>/seed-analysis.json --scope-registry <registry>
```

The validator writes nothing; the analyzer writes geometry and objective
coverage. Do not dispatch EXPAND unless both succeed. On rejection, return the
message to SEED; never repair its fragment by hand.

### 6. EXPAND

After SEED returns, dispatch EXPAND with only this bootstrap, after resolving
every binding:

```text
Role contract: <skill-root>/references/expand.md
Inputs:
  study    = <study>
  registry = <registry>
  scripts  = <scripts>
  run      = <run>
  target   = <run>/target.json
  seed     = <run>/seed.json
  analysis = <run>/seed-analysis.json
  fault    = <fault>
  fragment = <run>/expand.json
```

The two roles never overlap. They do share one
instance, and SEED's probing mutates it, so **EXPAND inherits whatever state
SEED left**. A route EXPAND reaches only because of that state is not a route
the attacker can reach from the entry: check any route whose precondition SEED
created. Give it SEED's fragment and analysis alongside its own contract.

Handle an EXPAND rejection before reading its success response:
`REJECT: validation` returns to EXPAND for correction; `REJECT: input` is
terminal and delivers nothing, as is `REJECT: execution`. Otherwise
`<run>/expand.progress` is where you look while it runs. Assert its response:
every unsettled claim carries `Blocked by`. A claim whose check EXPAND could
have run is unfinished work — send it back.

### 7. Merge

```text
python3 <scripts>/graph_merge.py <run>/seed.json \
  --expand <run>/expand.json \
  --out <out>/graph.json --record <run>/merge.json \
  --scope-registry <registry>
```

EXPAND's fragment is required even when its `paths` is empty. The merger
validates both fragments and their union, assigns final route ids in
SEED-then-EXPAND order, and records attribution in `merge.json`. Never assemble
`graph.json` yourself or drop a route; a route leaves only through Adjudicate
re-dispatching its author.

### 8. Adjudicate

Inspect every evidence object and its matching record in `<run>/probes.log`.
Judge each fragment from its persisted artifact and recorded evidence, not from
an unstated argument by its author. This is the judgment no script can make.
Check the **entry** set because it defines the granted starting authority; the
**node boundaries** because they define the geometry; and the **evidence
claims** because containment alone cannot show that an excerpt supports its
claim. Evidence whose `source` says `attested` rests on a client other than
`probe.py` and deserves the closest check.

Route a rejection to the owner of its input: root corrects root-owned inputs;
SEED or EXPAND corrects a fragment named in the error; an error created by the
union is adjudicated here. Never repair a role artifact or merged graph by hand.

A correction to a root-owned input already dispatched invalidates every role
output that consumed it and everything downstream; return to the earliest
dependent step. Correcting `target.json` or graph identity returns to Step 5
and reruns both roles.

A correction to SEED's fragment returns to Step 5: validate the replacement,
recompute `seed-analysis.json`, and re-dispatch EXPAND because its output
derives from those inputs. A correction to EXPAND's fragment returns to Step 6,
then Merge. At most two adjudication passes; then abort.

### 9. Derive

```text
python3 <scripts>/graph_analyze.py <out>/graph.json \
  --out <out>/analysis.json --scope-registry <registry>
```

The analyzer writes only facts over the recorded routes:

| Field | Meaning |
|---|---|
| `objective_coverage` | Each objective's scope and route count. |
| `geometry` | Shape labels: `fan_out` when one function reaches multiple objectives, `fan_in` when multiple routes to one objective share a function, and `disjoint` when no function lies on every route. No label is also valid. |

Geometry names the recorded shape; it is not a verdict.

### 10. Finalize

Write `<out>/provenance.json`; `unsettled` defaults to an empty list:

```json
{"fault": {"statement": "<fault>"},
 "unsettled": [{"claim": "...", "reaches_fault_by": "...",
                 "check": "...", "blocked_by": "..."}]
}
```

Carry EXPAND's `Reaches the fault by` text into `reaches_fault_by`.
Attribution is not yours to write: Merge established it. Then run:

```text
python3 <scripts>/graph_finalize.py <out> \
  --merge-record <run>/merge.json --scope-registry <registry>
```

This rejects a partial, invalid, stale, or unattributed deliverable and writes
`graph.md` and `findings.md`. **Do not write either yourself.** Attribution
comes from `merge.json`; refusals come from `graph.json`'s `advisory_cut`.

```text
python3 <scripts>/graph_provision.py --run <run> --down
```

This removes only the containers, volumes, networks, and locally built images
that Provision recorded. Leave `<run>` itself: `/tmp` retains the intermediates
from successful and failed work.

## Deliverable

```text
artifacts/projects/<PROJECT>/graph/<study-name>/
├── graph.json        the IR
├── analysis.json     geometry and objective coverage
├── graph.md          the diagram and summary tables, written by graph_finalize.py
├── provenance.json   the record: fault and unsettled claims
└── findings.md       rendered from it by graph_finalize.py, never by hand
```

Nothing is named for the role that produced it: attribution reaches
`findings.md` from the merge's own record. Nothing intermediate is here, and
nothing here points outside itself — the deliverable is readable with the study
gone.

Report the study and revision, geometry, which routes the advisory's own fix
left open, SEED's fault, and what EXPAND left unsettled.

## Boundaries

- The graph never promotes or rejects a challenge, and no skill may treat a
  graph property as an admission criterion.
- Root cause never becomes a node or a field.
- The graph is a complete exploit map for the routes it holds, and every
  observation was produced by a request executed in this pass. It stays in the
  Git-ignored `artifacts/` tree; the fragments under `<run>` are the same map in
  pieces, so `/tmp` is as far as they go. Neither reaches an agent-visible
  surface.
