---
name: challenge-graph
description: "Build the attack-graph intermediate representation for one completed Cyber Arena Stage 3 study, then compute its cuts, geometry, and coverage and render a diagram. Stands up the study's own bundle and probes the running target, so it starts containers and sends attacker traffic. Use when analyzing or visualizing what a challenge's reproduced attack structure is, or when checking whether a study's recorded decision matches its own evidence. Do not use to promote, reject, or review a challenge."
---

# Challenge graph

Turn one completed Stage 3 study into a graph of the attack structure it
reproduced, compute cuts and geometry over it, and draw it.

You are the **root**: the executor. You call functions — scripts and subagents —
and own every deliverable. You do not author the graph you adjudicate.

## Read first

Resolve the directory holding this file as `<skill-root>`. Resolve the enclosing
Git checkout as `<analysis-root>`, only when its origin identifies
`cyber-arena-analysis`; otherwise stop and ask the user which checkout that is.
Python 3.11 or newer.

**Instruction** — [contracts.md](references/contracts.md) is every function's
inputs, assertions and outputs, and the only place an invocation is written,
dispatch prompts included. Copy from it; never restate a signature in your own
words. [authoring.md](references/authoring.md) is the procedure the roles
follow; you do not author, but you review what it produces.

**Material** — [graph-schema.md](references/graph-schema.md) and
[corpus.md](references/corpus.md), which is yours: it is provisioning knowledge
the roles are forbidden to act on. Read both before dispatching anything.

## Input

```text
<absolute-study-dir>
```

Reject extra arguments.

## Workflow

| # | Step | Consumes | Produces |
|---|---|---|---|
| 0 | Bind | the argument | `<out>`, `<run>` |
| 1 | Read | `<study>` | revision, the study reading |
| 2 | Provision | `<study>` | `<target>` |
| 3 | SEED | `<target>`, materials | `<run>/seed.json`, `<run>/seed-analysis.json` |
| 4 | EXPAND | SEED's fragment and analysis | `<run>/expand.json`, the EXPAND response |
| 5 | Merge | both fragments | `graph.json`, `<run>/merge.json` |
| 6 | Review | `graph.json`, `<study>`, `<target>` | repairs, or nothing |
| 7 | Derive | `graph.json` | `analysis.json` |
| 8 | Finalize | everything above | `provenance.json`, `graph.md`, `findings.md` |

### 0. Bind

Assert `<study>/STAGE3_STUDY.md` exists and the scope registry exists. Nothing
below may discover a missing input.

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

What `<run>` holds is in contracts.md's Paths table. Nothing there is a
dependency of the deliverable. `<run-id>` is fresh per run and namespaces
`<run>` alone: the study's own reproducer names its containers after an id it
mints itself, which is why step 2 records that id and step 8 tears down by it.

Create `<out>` and `<run>` now, unconditionally. `<out>` holds only what
ships.

### 1. Read

Read `result.json` if present and say which field gave you the revision. Read
`STAGE3_STUDY.md` whole; the attack chain and the witness and authoring
consequences are the semantic source. Steps 6 and 8 consume this reading.

### 2. Provision

**You are the only frame that touches Docker.**

```text
graph_provision.py <study> --run <run> --reproducer "..."   ... (contracts.md)
```

It copies the bundle to `<run>/env/`, runs the reproducer *there*, and writes
`<run>/target.json` from what came up. Read the study for the reproducer's own
command; the bundle shapes differ (corpus.md).

Then finish `target.json` yourself, because the script cannot: each build's
`auth_header` — the **entry principal and nothing more** — and what the facility
seeded.

**You provision that principal; you do not go looking for one.** The reproducer
mints its own and keeps the tokens in memory, so there is nothing to recover —
and borrowing a principal it created would be taking an identity rather than
issuing one. You are the facility: you started the application, and the credentials it was
configured with are in its containers — `graph_provision.py` prints which ones it
found and writes none of them to `target.json`, because that file goes to the
roles. Read their values yourself, create an entry principal with the access the
challenge grants, and record only that in `auth_header`. How to create a user is
per-study work, and some studies configure no such credential at all. Verify the study's own baseline before dispatching anything. A study with no runnable bundle has no reproducer to run: skip
`graph_provision.py` altogether, write `<run>/target.json` yourself with
`none: true`, and the roles read it there. The script requires a reproducer and
treats discovering no build as a failure, because for every other study it is
one.

### 3. SEED

Dispatch it with the contract in contracts.md. While it runs, `<run>/seed.progress`
is where you look: the age of its last line is how you tell a working role from a
dead one. Then gate and analyze:

```text
graph_validate.py <run>/seed.json                              ... (contracts.md)
graph_analyze.py  <run>/seed.json --out <run>/seed-analysis.json  ... (contracts.md)
```

A fragment whose evidence does not hold up does not get to spend the second
dispatch. On rejection, re-dispatch SEED with the message; never repair a
fragment by hand.

### 4. EXPAND

Dispatch it after SEED returns; the two roles never overlap. They do share one
instance, and SEED's probing mutates it, so **EXPAND inherits whatever state
SEED left**. A route EXPAND reaches only because of that state is not a route
the attacker can walk from the entry: check any route whose precondition SEED
created. Give it SEED's fragment and analysis alongside its own contract.

`<run>/expand.progress` is where you look while it runs. Assert its response:
every unsettled claim carries `Blocked by`, and `Needs study`, when EXPAND found
no route, names a search. A claim whose check EXPAND could have run is
unfinished work — send it back.

### 5. Merge

```text
graph_merge.py <run>/seed.json --expand <run>/expand.json  ... (contracts.md)
```

Never assemble `graph.json` yourself, and never drop a route here: a route
leaves the graph only by re-dispatching the role that wrote it, at step 6.

### 6. Review

Re-read every cited construct in full. You saw SEED's reasoning as its
dispatcher, so the artifact and its evidence are what you check, not the
argument for it. This is the judgment no script can make. Check the **entry**
set, because a node declared `entry` leaves every cut; the **node boundaries**,
because they set every number in the graph; and the **citations**, the one place
the validator's containment check says nothing — an excerpt can carry the quoted
string and still not support the claim.

Review writes no record of itself — you would be attesting to your own
diligence, and a run that reviewed nothing could write the same words. What it
leaves behind is the change it caused, in `graph.json`.

Repair a `Repair` finding by re-dispatching the role that wrote the subject.
**Changing SEED's node set invalidates EXPAND's fragment** — its routes name ids
and symbols that no longer exist — so re-dispatch EXPAND too and return to
step 4. Otherwise return to step 5. At most two passes; then abort.

### 7. Derive

```text
graph_analyze.py <out>/graph.json --out <out>/analysis.json   ... (contracts.md)
```

### 8. Finalize

Reconcile the analysis against the study's own recorded decision — `geometry`,
`mincut_all`. Raise a `NOTE` for exactly these disagreements and no others:

- the study reports the advisory's fix closing the attack but `advisory_cut`
  records a surviving route, or the reverse;
- EXPAND's fault and the study's own account of it disagree;
- the graph records a route the study does not describe, or omits one it does —
  a run found a third route that moved `mincut_all` from 1 to 2 and had nowhere
  to say so.

**Never adjust the graph to make it agree** — the disagreement is the finding.

Write `<out>/provenance.json` to the shape in contracts.md — the fault, the
unsettled claims (each with the `Reaches the fault by` line EXPAND returned) and
the NOTEs. Attribution is not yours to write: the merge established it. Then:

```text
graph_finalize.py <out> --merge-record <run>/merge.json   ... (contracts.md)
```

It checks the deliverable and writes both derived files, `graph.md` and `findings.md`. **Do not write either yourself.** Attribution comes from `merge.json`, and the refusals come from `graph.json`'s
own `advisory_cut` — neither from anything you retype.

```text
graph_provision.py --run <run> --down   ... (contracts.md)
```

That removes exactly what step 2 started, by the compose projects it recorded —
they carry the id the study's reproducer minted, not `<run-id>`. Leave `<run>`
itself: `/tmp` is where the intermediates stay, and they are the only record of
a run that failed.

## Deliverable

```text
artifacts/projects/<PROJECT>/graph/<study-name>/
├── graph.json        the IR
├── analysis.json     cuts, geometry, coverage
├── graph.md          the diagram and summary tables, written by graph_finalize.py
├── provenance.json   the record: fault, unsettled claims, NOTEs
└── findings.md       rendered from it by graph_finalize.py, never by hand
```

Nothing is named for the role that produced it: attribution reaches
`findings.md` from the merge's own record. Nothing intermediate is here, and
nothing here points outside itself — the deliverable is readable with the study
gone.

Report the study and revision, geometry and `mincut_all`, which routes the
advisory's own fix left open, every `NOTE`, EXPAND's fault, and what it left
unsettled.

## Boundaries

- The graph never promotes or rejects a challenge, and no skill may treat a
  graph property as an admission criterion.
- Never report a min-cut as proof that no other attack path exists.
- Root cause never becomes a node or a field.
- The graph is a complete exploit map for the routes it holds, and an
  observation this pass ran carries a working request verbatim. It stays in the
  Git-ignored `artifacts/` tree; the fragments under `<run>` are the same map
  in pieces, so `/tmp` is as far as they go. Neither reaches an agent-visible
  surface.
