# Contracts

Every deterministic function the root calls, with its inputs, assertions and
outputs. This is the only place the root's script invocations are written. Copy
them from here; do not restate a signature.

Scripts are fixed, deterministic and **atomic**: a function either produces
its whole output or produces none of it. `graph_provision.py` is the one
exception — it writes `target.json` before the checks that can fail, so whatever
came up is always tearable down, and its exit status says whether provisioning
succeeded.

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
`graph_provision.py` handles the target instead and takes neither.

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
Unions two fragments and assigns their routes the final ids `PATH-1`,
`PATH-2`, and so on, in SEED-then-EXPAND document order. It rewrites every
advisory-cut and attribution reference to those ids. **`--expand` is required**:
EXPAND finding nothing is a
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

## Failure

A script is deterministic, so a script rejection is always a fault in whoever
produced that input: re-dispatch that role with the message, never repair its
artifact. SKILL.md step 6 bounds the retries.
