# Contracts

Every function this skill calls, with its inputs, what it asserts, and what it
produces. This file is the only place an invocation is written down. A caller
copies from here; nothing restates a signature in its own words.

Two kinds of function:

- **script** — fixed, deterministic, white box. Same inputs, same outputs.
- **subagent** — black box. Its contract is what it is given, what it must
  assert on receipt, and what it must return.

Both kinds are **atomic**: a function either produces its whole output or
produces none of it, and one that receives an incomplete input rejects it rather
than proceeding with a default. `graph_provision.py` is the one exception — it
writes `target.json` before the checks that can fail, so whatever came up is
always tearable down, and its exit status says whether provisioning succeeded.

Atomicity governs the deliverable, not the trace: each subagent appends to its
own `<run>/<role>.progress`, one UTC-timestamped line per step, which is how a
dispatcher tells it from a dead agent.

## Paths

| Name | What |
|---|---|
| `<study>` | the Stage 3 study directory. **Read-only, always.** |
| `<out>` | `<analysis-root>/artifacts/projects/<PROJECT>/graph/<study-name>/` |
| `<run>` | `/tmp/challenge-graph/<study-name>-<run-id>/` — every intermediate: the bundle copy, the fragments, `target.json`, `probes.log`, `reproduce.log`, the roles' progress files, `seed-analysis.json`, `merge.json`. The *finished* deliverable depends on none of it; step 8 reads `merge.json` while building it. |
| `<registry>` | `<analysis-root>/skills/challenge-create/references/attack-scopes.json` |
| `<skill-root>` | the directory holding `SKILL.md`; this file is at `<skill-root>/references/` |
| `<scripts>` | `<skill-root>/scripts/` |

## Scripts

Every script that reads a graph takes `--scope-registry`, required, and
revalidates what it read. That is the only path those open: a graph is checked
against itself and a fixed list of scopes, never against the study it came from.
`graph_provision.py` and `probe.py` handle the target instead and take neither.

```text
python3 <scripts>/graph_validate.py <graph> \
  --scope-registry <registry>
```
Checks the graph whole: shape, node identity, route walks, cuts, scopes, and
that every observation quotes text that is in its own excerpt. Writes nothing.
Exit 0, or exit 1 with one message per fault; argparse exits 2 for a missing flag.

```text
python3 <scripts>/graph_analyze.py <graph> --out <path> \
  --scope-registry <registry>
```
Produces cuts, geometry, and objective coverage.


```text
python3 <scripts>/graph_merge.py <run>/seed.json \
  --expand <run>/expand.json \
  --out <out>/graph.json --record <run>/merge.json \
  --scope-registry <registry>
```
Unions two fragments. **`--expand` is required**: EXPAND finding nothing is a
fragment carrying no route, and the fragment existing is what says EXPAND ran.
No flag lets the root assert that on a role's behalf, because a role that never
ran and a role that found nothing are not the same run. Writes both files or
neither. The union is mechanical.

```text
python3 <scripts>/graph_finalize.py <out> \
  --merge-record <run>/merge.json \
  --scope-registry <registry>
```
Checks the finished deliverable and writes both derived files, `<out>/graph.md`
and `<out>/findings.md`. The last step
has no downstream consumer, so this is what rejects a partial or malformed tree
instead of it being read as finished: every artifact present, the graph valid,
the graph recording at least one route, `analysis.json` being
derivable from *this* `graph.json` rather than an earlier one, every route
attributed, the fault stated, every unsettled claim naming what blocked it. Attribution is read
from the merge's own record rather than from anything the root retyped; the
refusals reach `graph.md` from `graph.json`'s own `advisory_cut`. `findings.md` is *derived*, so it cannot drift from what it reports.

```text
python3 <scripts>/graph_provision.py <study> --run <run> \
  --reproducer "<the study's own command>"
python3 <scripts>/graph_provision.py --run <run> --down
```
Copies the bundle into `<run>/env/`, runs the reproducer *there*, and writes
`<run>/target.json` from what actually came up — it diffs Docker's own state
rather than reading the reproducer's prose, because that prose differs per
study. It hashes `<study>` before and after and fails if anything changed.
`--reproducer` is required and is yours to supply. So is each build's
`auth_header`, which the script leaves `null`: no bundle emits one the same way.
When one compose project publishes more than one port it will not guess which
service is the application — `base_url` stays `null` and the candidates are
written down for you to settle. It also **prints** the names of any facility
credentials it found in each project's containers, and writes none of them to
`target.json`: that file goes to the roles, and they get the entry principal and
nothing more. `target.json` is written **before** anything
below it can fail, so whatever came up is always tearable down.

`--down` takes no study and removes the containers, volumes, networks and
locally built images of every compose project the provisioning recorded. One
project failing does not strand the rest.

```text
python3 <scripts>/probe.py --target <run>/target.json --build <name> \
  --path </path> [--method GET] [--param NAME=VALUE]... [--header "NAME: VALUE"]... \
  [--data '<json body>' | --form NAME=VALUE... | --data-file <path>] \
  [--note "<what this is for>"] [--observed "<the string carrying the claim>"]
```
Sends one request as that build's entry principal, appends it to
`<run>/probes.log` with the effective extra headers, the request body it sent, the
response's own headers and a UTC timestamp, and prints it. A request has one body: `--data` is JSON,
`--form` is form-encoded, `--data-file` is bytes, for a payload that is not text.
Binary bodies are retained as `base64:<encoded bytes>` in the log's `sent` field
and the evidence `source`, so neither depends on the original file. The record
grows with the file size.
`--header` adds a header; it may not replace the entry principal's, though a
cookie is merged into it, the granted one winning. Extra headers are recorded
after cookie merging and case-insensitive request-header normalization, then
named in the evidence `source`, so a route opened by a second header is not read
as one the entry principal walked alone. **One invocation is one request**:
redirects are not followed, and a 302 is returned as the result it is, with its
`Location` among the response headers. With `--observed`, it
prints the graph evidence for it — and refuses when the response does not
contain that string, which is the one thing hand-assembled evidence cannot check
about itself; when the claim lands deeper than the excerpt the log keeps, the
evidence excerpt follows the match rather than the start, and a claim carried by
a response header rather than the body is quotable too. A 403 is a result, not
a failure; a request that never arrived is logged too, and exits 1. A rejected
`--observed` also exits 1, after logging and printing the completed exchange
without an evidence claim.

```text
python3 <scripts>/probe.py --target <run>/target.json --build <name> --record \
  --request "<the request you sent, verbatim>" --response-file <path> \
  --status <code> [--note "..."] [--observed "<the string carrying the claim>"]
```
Records an exchange **you** performed, for a request this script cannot send —
another protocol, a client the study ships, a chain it cannot hold. It runs the
same containment check and writes the same log line, and its evidence `source`
says `attested`, so a reader can see which claims rest on a client other than
this one.

`probe.py` sends HTTP. It is the fast path and not a fence: what the graph rests
on is that **every observation it cites matches a record in `probes.log`**, not
which client obtained it.

## provenance.json

What the root writes at step 8. Everything the deliverable rests on that the
graph itself does not carry.

```json
{"fault":  {"statement": "..."},
 "unsettled": [{"claim": "...", "reaches_fault_by": "...",
                "check": "...", "blocked_by": "..."}],
 "notes":  ["<each NOTE from the reconciliation>"]}
```

Only what the root alone knows. Which roles ran is not among it: both always do,
since `--expand` is required. Which role found each route is a fact the merge
established — `graph_finalize.py` reads it from `<run>/merge.json`, so there is
nothing here to mistype.

## target.json

What `graph_provision.py` writes and the roles read. `probe.py` needs exactly
two fields per build; everything else the root adds is for the roles to read.

```json
{"builds": {"<name>": {"base_url": "http://127.0.0.1:<port>",
                       "auth_header": "<header name>: <value>"}},
 "seeded": "<what the facility planted, and how a role recognises it>"}
```

`seeded` is the root's, and step 2 requires it: a role that cannot recognise the
protected value cannot tell a disclosure from an error message.

`auth_header` is the **entry principal and nothing more** — the identity the
challenge grants. `none: true` is a study with no runnable bundle, and `probe.py`
refuses it rather than reaching for something else.

## Evidence

Every node, witness and cut entry carries one observation. The shape, the rules
and why they are what they are live in [graph-schema.md](graph-schema.md)
§Evidence — read it there, and do not restate it.

What matters to a dispatch: every observation is a response this run received,
and the build belongs in `source`, because two runs against different builds are
otherwise the same record.

## SEED — subagent

| | |
|---|---|
| **Consumes** | `<study>`, `<registry>`, `<target>` (see root step 2), `<scripts>`, and the materials below |
| **Materials** | [contracts.md](contracts.md), [authoring.md](authoring.md), [graph-schema.md](graph-schema.md) |
| **Produces** | `<run>/seed.json`, and the response below |
| **May** | read `<study>`; send requests to `<target>` as that build's `auth_header`; write `<run>/seed.json` |
| **May not** | start, stop or build a container; run a reproducer; use host Docker; write anything under `<study>` |
| **Asserts on receipt** | every input above present and readable. A missing one is returned as `REJECT: <what is missing>`, not worked around. |
| **Must ensure** | the fragment passes `graph_validate.py` exactly as written above, before returning; and that `<run>/<role>.progress` carries a UTC-timestamped line per step of your procedure |
| **Owns** | the `entry`, and at least one route. Objectives are not yours alone: EXPAND declares any it reaches. |

### Dispatch

```text
Inputs — replace each name with an absolute path before sending:
  study     = <study>
  registry  = <registry>
  scripts   = <scripts>
  target    = <run>/target.json
  fragment  = <run>/seed.json                       (write your fragment here)
  materials = <skill-root>/references/contracts.md, authoring.md,
              graph-schema.md

You are the SEED role for the challenge graph over Stage 3 study <study>. Read the three materials listed above, in full, before anything else. Author the terminals and the routes the advisory describes, as one fragment at <run>/seed.json. You own the entry node, which no later role may add to. Declare every objective you reach; a later role may declare others it reaches. The live target is described in <run>/target.json: reach it with probe.py, as specified in contracts.md, and record what it prints as the observation on the node or route it establishes. probe.py is your fast path, not your only one: where it cannot send the request, use a client that can and bring the exchange back with probe.py --record. Every observation you cite must match a record in <run>/probes.log. Append one UTC-timestamped line to <run>/seed.progress as you begin each step of your procedure — reading, probing, authoring, validating, returning — so a dispatcher can tell you apart from a dead agent. Assert every input above on receipt and return REJECT if one is missing. Gate your own fragment with the graph_validate.py invocation in contracts.md before returning, and return only the SEED response.
```

### Response

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

## EXPAND — subagent

| | |
|---|---|
| **Consumes** | everything SEED consumes, plus `<run>/seed.json` and `<run>/seed-analysis.json` |
| **Produces** | `<run>/expand.json` — always, carrying no route when you found none — and the response below |
| **May / may not** | as SEED, and may not declare an `entry`; an objective you reached on the target is yours to declare |
| **Asserts on receipt** | as SEED |
| **Must ensure** | the fragment passes `graph_validate.py` on its own; `<run>/<role>.progress` carries a UTC-timestamped line per step of your procedure; every unsettled claim carries `Blocked by`; `Needs study` names a search, never a missing citation |

### Dispatch

```text
Inputs — replace each name with an absolute path before sending:
  study     = <study>
  registry  = <registry>
  scripts   = <scripts>
  target    = <run>/target.json
  seed      = <run>/seed.json
  analysis  = <run>/seed-analysis.json
  fragment  = <run>/expand.json                     (write your fragment here)
  materials = <skill-root>/references/contracts.md, authoring.md,
              graph-schema.md

You are the EXPAND role for the challenge graph over Stage 3 study <study>. Read the three materials listed above, in full, before anything else. You are given SEED's fragment and its analysis; you are blind to nothing. Name the fault the study reproduced, find further routes that reach it, and declare any further objective you reached, with a scope from the registry. Run what you can against the target described in <run>/target.json using probe.py, as specified in contracts.md, recording what it prints as the observation; where probe.py cannot send the request, use a client that can and record the exchange with probe.py --record, so that every observation you cite matches a record in <run>/probes.log. Redeclare any node SEED declared under its exact id and symbol, narrowing only its predecessors. You may add function nodes, routes, and an objective you reached on the target; you may not add an entry. Append one UTC-timestamped line to <run>/expand.progress as you begin each step of your procedure — reading, probing, authoring, validating, returning — so a dispatcher can tell you apart from a dead agent. Assert every input on receipt and return REJECT if one is missing. Gate your fragment with the graph_validate.py invocation in contracts.md, write your fault and unsettled claims for the root, and return only the EXPAND response.
```

### Response

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
record it" — you can run the target, so run it, write the output to
record it as a probe observation. A hypothesis you *could* have run is not a
unsettled claim; it is unfinished work.

## Failure

A script is deterministic, so a script rejection is always a fault in whoever
produced that input: re-dispatch that role with the message, never repair its
artifact. SKILL.md step 6 bounds the retries.
