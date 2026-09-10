# Challenge graph schema (version 2)

One `graph.json` per challenge. It records the attack structure that was
*reproduced*, never the complete attack surface.

The model is written from the defender's side. A **node** is something that
exists in the application: an entry point the attacker starts from, a function
or route they use, or the objective they reach. An **edge is abstract** — it
says one node leads to the next and carries no claim of its own. A defender
guards or disables a function, so the node is what a defense targets and a
**cut is a set of nodes**.

The graph never says which cuts are *allowed*. That needs the functionality
checker and belongs to challenge authoring.

[example-graph.json](example-graph.json) is a complete, minimal instance whose
conventions are the ones to copy.

## Document

| Field | Contract |
|---|---|
| `schema_version` | `2` |
| `target.id` | Challenge or study identifier, short kebab-case |
| `target.repository` | `owner/project` |
| `target.revision` | The reproduced commit, 40 lowercase hex characters |
| `nodes` | Non-empty list of nodes |
| `advisory_cut` | What the advisory's own fix did to each recorded route; optional |
| `paths` | Reproduced routes. A finished graph has at least one; a *fragment* may carry none, which is what a role finding no further route looks like |

A schema-1 document is rejected by version. A document declaring version 2
while still carrying `states` or `operations` is rejected with a message naming
the change; a real schema-1 file never reaches it, because the version check
returns first. The five schema-1 graphs already in `artifacts/` are unreadable
by this tooling and are not migrated.

## Nodes

```json
{"id": "N-resolve-share", "role": "function",
 "title": "GET /s/{token} resolves a token without re-checking ownership",
 "symbol": "ShareController.resolve",
 "predecessors": ["N-create-share"],
 "evidence": {"source": "vulnerable build · GET /s/7f2a · 200",
              "excerpt": "200 OK owner_check=skipped share=7f2a",
              "observed": "200 OK owner_check=skipped"}}
```

`role` is `entry`, `function`, or `objective`. A graph needs at least one of
each terminal role.

- **`entry`** — the identity and access the challenge grants the attacker, as
  the scenario states it: *"the attacker begins as `[role]` and can use
  `[public feature]`."* It declares `title` and must not `require` anything.
- **`function`** — an application function, route, or handler. It declares
  `title`, `predecessors`, `evidence`, and `symbol` — the code symbol or endpoint it
  names. If you cannot name it, it is not a node.

  `symbol` is unique across the document, because it is what says two nodes are
  one node. Two ids for one function make two routes look like they share
  nothing, so the min-cut halves and the geometry reads `disjoint` when it is
  `fan_in`. **The mirror mistake is quieter: one node over two separately
  guardable functions understates what the defense costs** — before merging two
  call sites into one node, check that a fix guarding one really guards the
  other. Two *different* names for one function still pass; that is a judgment,
  and it belongs to whoever adjudicates the graph.
- **`objective`** — the protected asset reached. It declares `store`, `scope`,
  and `predecessors` — the functions that reach it — instead of a title. Before
  Stage 4 there is no declared store, so `store` names the study's trial
  witness in one short snake_case token,
  because the renderer prints it inside the node beside the scope. The scope is
  a registered id from `attack-scopes.json` or a fully defined
  `custom.<challenge_id>.*` scope.

### Reaching a node

`predecessors` lists the nodes this one is reached from. It is **OR by
default**: a route arrives through one of them. Set `conjunctive: true` for a
node that genuinely needs all of them — a request needing both an authenticated
session and state a previous call stored.

That flag is the model's one departure from a plain DAG: this is an **AND-OR
graph**, and `conjunctive` marks the AND-nodes. The field was called `requires`
with a `requires_all` companion, which was a live authoring hazard — *requires
A, B* reads as "needs both", so an author meaning AND wrote the OR form and got
it silently. OR **widens** reachability, which opens shortcuts, makes routes
look droppable, and lowers `mincut_all`: the graph then reports a cheaper
defense than the application permits, and nothing catches it, because both
readings are structurally valid. `predecessors` makes no claim about how they
combine, so only `conjunctive` votes.

The attacker's observation of the result is not a node. It is the objective,
reached from the function that crosses the boundary. Reconnaissance and proof
submission are not nodes either: if you cannot name the application function or
route, it does not belong in the graph.

The analysis excludes the terminals, which is Menger's vertex form: the entry
is the identity the challenge granted, so severing it is not a defense of this
boundary. That makes the entry set the one remaining place where an author's choice moves
the numbers. Declaring a node `entry` removes it from every cut, so check that
it really is the granted starting identity.

## Paths

A path is one **route**: an ordered walk from an entry node to an objective,
over distinct nodes.

**Naming.** `PATH-<the node it enters through>-<the node that reaches the
objective>`, using those two nodes' ids with the `N-` dropped. Both are the
route's own interior endpoints, so a role can name its routes without knowing
what any other role found — which is why nothing cleverer will work here: SEED
names its routes before EXPAND exists. Where it enters is the attack surface;
what finally executes is what crosses the boundary. The nodes between are
plumbing, and are read off `nodes`.

A name is the author's choice and so can never be what says two routes differ.
**Two routes over the same walk are one route recorded twice** and are rejected,
however they are named — otherwise a duplicate inflates the route count and can
manufacture a `fan_in` reading out of a single way in.

```json
{"id": "PATH-create-share-resolve-share", "objective": "N-obj-report",
 "nodes": ["N-entry", "N-create-share", "N-resolve-share", "N-obj-report"],
 "advisories": ["CVE-2026-11111"],
 "witnesses": [{"source": "vulnerable build · GET /reports/9 · 200",
                "excerpt": "recovered victim report body CYBERARENA{...}",
                "observed": "recovered victim report body"}]}
```

`nodes` starts at an `entry`, ends at the path's `objective`, and every node in
between is a `function`. Each node must be reached after its predecessors: at
least one of them for a disjunction, all of them when `conjunctive`.

Then one rule does the real work: **a route may carry no node it could reach
the objective without.** If dropping a node still leaves the objective
derivable from the rest, the route is rejected and the message names that node.

A node the route does not depend on enlarges its node set in the cut
computation, which **shrinks** the reported min-cut — understating how many
places a defender must touch. It is
deliberately not an adjacency check: a `conjunctive` node's branches are
parallel branches.

The consequence worth knowing when authoring: if a function is genuinely
reachable both directly and after an earlier step, the *shorter* route is the
one to record. The longer one is rejected, because cutting the step it skips
would not stop the attacker. If the longer route is the only real one, say so
by narrowing that node's `predecessors`.

`advisories` lists the advisory identifiers this route reproduces, and may be
empty. It is documentation and affects nothing. A chained attack legitimately
names several; a boolean could not record that.

`witnesses` is a non-empty list of observations that the route reached its
objective. A study that re-ran its chain retained better evidence for one route,
not a second route; recording the replay as a second path would manufacture
geometry out of one.

## The advisory cut

What the advisory's own fix did to the routes recorded here, established by
running the repaired build.

```json
{"advisory_cut": {
   "advisory": "CVE-2026-11111",
   "nodes": ["N-resolve-share"],
   "refused":  [{"path": "PATH-create-share-resolve-share",
                 "tried": "the study's payload, a direct object id, a re-signed token",
                 "source": "fixed build · GET /s/7f2a · 403",
                 "excerpt": "403 Forbidden owner_check=enforced",
                 "observed": "403 Forbidden owner_check=enforced"}],
   "survived": [{"path": "PATH-upload-template-render-template",
                 "source": "fixed build · GET /reports/9/export · 200",
                 "excerpt": "200 {\"body\": \"recovered victim report body\"}",
                 "observed": "recovered victim report body"}]}}
```

**One advisory, one cut** — which is why it has no id and no `reference`. The
earlier model allowed several, and a defense split across two ids read as
terminal under the id holding only the refused routes, for a defense a recorded
route demonstrably escaped.

**`survived` is decisive; `refused` is not.** One request reaching the objective
proves the route open; no number of refusals proves it closed. So `refused` says
only what this run sent and was refused, never that the route is severed, and
each entry carries **`tried`** — the payload shapes it attempted — so a reader
can see what was not. [authoring.md](authoring.md) step 6 is how to fill it.

A route may not appear on both sides, and a cut recording nothing at all is left
out rather than written empty. Either side alone is legal: `survived` alone is
the interesting case, and it is all an EXPAND fragment carrying one surviving
route has to say.

`advisory` names it: the CVE, or — for a fix that shipped without one — the
upstream commit. The cut is named for the advisory, so leaving it anonymous
would make the exemplar untraceable.

**`nodes` is the point.** It is the one cut in the graph whose admissibility is
known: upstream guarded these nodes, shipped it, and the project kept working.
Every other cut this tool reports is a candidate nobody has judged — and the
cheapest is routinely a shared executor every legitimate request needs, so
severing it would be feature amputation. So this is the exemplar a challenge
author has to work from. They are `function` nodes: a fix that removed the entry
or the asset is not a defense of this boundary and is not what upstream shipped.

`refused` and `survived` are what that accepted cut *achieved* over the recorded
routes. An accepted cut that leaves a route open is exactly what this makes
sayable — which is the reason to record the fix rather than trust it.

## Evidence

Every node, witness and cut entry carries one observation, and they all have the
same shape:

```json
{"source":   "<the request that was sent>",
 "excerpt":  "<what came back>",
 "observed": "<at least 8 characters of that response, carrying the claim>"}
```

**Every observation is a response this run received.** There is no field saying
where the text came from, because there is only one place it may come from: the
study says where to look and never what to record. `source` does say how it was
obtained — `probe.py` sent it, or a role attested an exchange it ran itself —
and either way `<run>/probes.log` holds the matching record. A line copied out of the
study's prose or its retained `evidence/` files is not a fact this run
established, and no label could make it one.

The only check is that `observed` appears in `excerpt`. Nothing is resolved
against the filesystem, and that is deliberate: **the deliverable depends on no
file outside itself.** A graph that cited `evidence/vulnerable.txt#L29` stopped
meaning what it meant the moment that file moved, was regenerated, or had a line
inserted above — and the failure is silent when the new line at #L29 happens to
contain the same string. A citation that still resolves but resolves to
something else reads as checked, which is worse than not checking.

So the response travels with the claim, and `source` records the request that
produced it. Together they are the whole fact, and it depends on nothing.

What this costs: an excerpt can be typed rather than copied, and no check at
this level can tell. Its integrity comes from how the run was conducted —
`probe.py` builds all three fields from the response and refuses a claim the
response does not contain — not from anything the file can prove about itself.

## Validation

Every script runs the same validation, so a fabricated graph cannot be
rendered, analyzed, merged or finalized even if the validator was skipped. The
only input besides the graph is `--scope-registry`, which is required.

Validation fails when ids are not unique or references do not resolve; a
required field is missing or malformed; evidence is missing, malformed, or
quotes text that is not in its own excerpt; a route does not start at an entry, does not
satisfy a node's requirements, carries an unused node, or does not end at its
objective, or lists one node twice; a path records no witness; a cut records no
path at all or lists one twice; or the graph is cyclic.

A malformed document produces an error, never a traceback.

## Fragments

Under [multi-role authoring](../SKILL.md) each role writes a **fragment** and
`graph_merge.py` unions them into `graph.json`. Two consequences belong here.

**Validity is not compositional.** Unioning a node's `predecessors` can open a
shortcut that leaves a route carrying a node it no longer needs, so two
fragments that each validate can merge into a graph that does not. The merge
revalidates and writes nothing when that happens.

## Analysis

`graph_analyze.py` computes, and no agent authors:

| Output | Meaning |
|---|---|
| `mincut_all` | The size of the cheapest defense over every recorded route |
| `objective_coverage` | Per objective: its `scope`, its routes, and their mincut |
| `geometry` | `fan_in`, `fan_out`, `disjoint`, or none at all. Names for the shape the routes make; a route's length is read off `paths`, not labelled here |

Cuts are computed over recorded routes rather than graph reachability, so every
result is a statement about what was reproduced. Adding routes can only raise the min-cut *size*, so a large `mincut_all` is
sound while a small one may only mean no further route has been recorded yet.
No individual cut is stable that way, minimum ones included: a route added
later can miss a listed cut entirely, and the set that was cheapest stops being
a cut at all. The analyzer never emits an accept or reject.
