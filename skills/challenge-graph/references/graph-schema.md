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
| `evidence_root` | Optional. A directory inside the study that every locator must stay within |
| `nodes` | Non-empty list of nodes |
| `paths` | Non-empty list of reproduced routes |
| `observed_cuts` | Cuts that were actually run; may be empty |

A schema-1 document is rejected by version, and a document still carrying
`states` or `operations` is rejected with a message naming the change.

## Nodes

```json
{"id": "N-resolve-share", "role": "function",
 "title": "GET /s/{token} resolves a token without re-checking ownership",
 "symbol": "ShareController.resolve",
 "requires": ["N-create-share"],
 "evidence": {"locator": "evidence/vulnerable.txt#L9",
              "observed": "200 OK owner_check=skipped"}}
```

`role` is `entry`, `function`, or `objective`. A graph needs at least one of
each terminal role.

- **`entry`** — the identity and access the challenge grants the attacker, as
  the scenario states it: *"the attacker begins as `[role]` and can use
  `[public feature]`."* It declares `title` and must not `require` anything.
- **`function`** — an application function, route, or handler. It declares
  `title`, `requires`, `evidence`, and `symbol` — the code symbol or endpoint it
  names. If you cannot name it, it is not a node.

  `symbol` is unique across the document, because it is what says two nodes are
  one node. One application function under two ids reads as two routes sharing
  nothing, which halves the min-cut and manufactures a `disjoint` reading — a
  false contestable result. Two *different* names for one function still pass;
  that is a judgment, and it belongs to whoever adjudicates the graph.
- **`objective`** — the protected asset reached. It declares `store`, `scope`,
  and `requires` — the functions that reach it — instead of a title. Before
  Stage 4 there is no declared store, so `store` names the study's trial
  witness in one short snake_case token,
  because the renderer prints it inside the node beside the scope. The scope is
  a registered id from `attack-scopes.json` or a fully defined
  `custom.<challenge_id>.*` scope.

### Reaching a node

`requires` lists the predecessors a node is reached through, and is **OR by
default**: a route uses one of them. Set `requires_all: true` for a genuine
conjunction — a request that needs both an authenticated session and state a
previous call stored.

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

A path is one **route**: an ordered walk from an entry node to an objective.

```json
{"id": "PATH-pov", "objective": "N-obj-report",
 "nodes": ["N-entry", "N-create-share", "N-resolve-share", "N-obj-report"],
 "advisories": ["CVE-2026-11111"],
 "witnesses": [{"locator": "evidence/vulnerable.txt#L12",
                "observed": "recovered victim report body"}]}
```

`nodes` starts at an `entry`, ends at the path's `objective`, and every node in
between is a `function`. Each node must be reached after its predecessors: at
least one of them for a disjunction, all of them for `requires_all`.

Then one rule does the real work: **a route may carry no node it could reach
the objective without.** If dropping a node still leaves the objective
derivable from the rest, the route is rejected and the message names that node.

A node the route does not depend on enlarges its node set in the cut
computation, which **shrinks** the reported min-cut and lands in
`minimum_cuts_all` as a defense that would not stop the attacker. It is
deliberately not an adjacency check: a `requires_all` node's conjuncts are
parallel branches.

The consequence worth knowing when authoring: if a function is genuinely
reachable both directly and after an earlier step, the *shorter* route is the
one to record. The longer one is rejected, because cutting the step it skips
would not stop the attacker. If the longer route is the only real one, say so
by narrowing that node's `requires`.

`advisories` lists the advisory identifiers this route reproduces, and may be
empty. It is documentation and affects nothing. A chained attack legitimately
names several; a boolean could not record that.

`witnesses` is a non-empty list of observations that the route reached its
objective. A study that re-ran its chain retained better evidence for one route,
not a second route; recording the replay as a second path would manufacture
geometry out of one.

## Observed cuts

Only cuts that were actually applied and re-run. At Stage 3 that is the
upstream-fixed deployment, whose feature preservation is inherited from
upstream rather than measured.

```json
{"id": "CUT-upstream", "reference": "upstream_fix",
 "blocked":  [{"path": "PATH-pov", "locator": "evidence/fixed.txt#L9",
               "observed": "403 Forbidden owner_check=enforced"}],
 "survived": [{"path": "PATH-alt", "locator": "evidence/fixed-alt.txt#L2",
               "observed": "recovered victim report body"}]}
```

`reference` names the defense that was applied. It is the defense's identity,
so **one defense gets one cut id**: recording the blocked routes under one id
and the survivors under another leaves the first reading terminal for a defense
a recorded route demonstrably escaped. Two cuts sharing a `reference` are
rejected.

A cut must record at least one path, in either list. `survived` may be empty;
that is how a terminal result over the recorded subgraph is written down.
`blocked` may be empty too — "the defense was applied and did not stop these
routes" is exactly the contestability signal, and it is all an EXPAND fragment
carrying only its surviving route has to say. A path may not appear in both
lists of one cut. Candidate cuts are computed and belong in the analysis
output, never here.

## Evidence

```json
{"locator": "<path>#L<line>", "observed": "<exact text on that line>"}
```

A citation has no `kind`: the same Stage 3 agent wrote both `reproduce.py` and
`STAGE3_STUDY.md`, so labelling one of them stronger asserted a provenance
boundary that does not exist. A citation carrying `kind` is rejected.

What the locator does enforce is that the *graph's* author — a later agent
reading the study — cited something already written down, at an exact line,
quoting at least 8 characters that are actually on it. Fabricating an edge
means fabricating a line in a file that already exists.

`locator` resolves against the study directory and, when `evidence_root` is
declared, must stay inside it after symlink resolution. Some studies retained
no evidence directory at all; those graphs omit `evidence_root` and cite the
study document, which is legitimate and reported rather than hidden —
`citation_sources` counts how many citations land inside `evidence_root` and
how many elsewhere.

## Validation

All four scripts run the same validation, so a fabricated graph cannot be
rendered, analyzed, or merged even if the validator was skipped. Each takes
`--study-dir`, which must hold `STAGE3_STUDY.md`: a scratch directory of
hand-made evidence is not a study and is rejected. Each also accepts
`--scope-registry`.

Validation fails when ids are not unique or references do not resolve; a
required field is missing or malformed; evidence is missing, malformed, or does
not resolve to its cited line; a route does not start at an entry, does not
satisfy a node's requirements, carries an unused node, or does not end at its
objective; a path records no witness; a cut records no path at all or lists one
twice; or the graph is cyclic.

A malformed document produces an error, never a traceback.

## Fragments

Under [multi-role authoring](../SKILL.md) each role writes a **fragment** and
`graph_merge.py` unions them into `graph.json`. Two consequences belong here.

**Validity is not compositional.** Unioning a node's `requires` can open a
shortcut that leaves a route carrying a node it no longer needs, so two
fragments that each validate can merge into a graph that does not. The merge
revalidates and writes nothing when that happens.

**A cut recording only survivors asserts a defense was applied, and nothing
checks that.** Survivor citations are exempt from the discriminator, so such a
cut rests entirely on the author having read the fixed build.

Shallowness is **not** a validation error, deliberately. A one-node route is
recorded and labelled `shallow` by the analyzer, so a graph over a rejected
study still shows why it was rejected. Whether shallowness rejects a
*challenge* is issue 17's decision, not the graph's. Because a trivial route
still participates in cut computation, read `mincut_nontrivial` alongside
`mincut_all` whenever `shallow` appears.

## Analysis

`graph_analyze.py` computes, and no agent authors:

| Output | Meaning |
|---|---|
| `mincut_all` | The size of the cheapest defense over every recorded route |
| `minimum_cuts_all` | Every cut of that size, capped at 32. Each is a set of nodes whose removal disconnects the entry from an objective, admissibility not judged |
| `mincut_nontrivial` | The cheapest defenses over nontrivial routes only, so a reproduced one-node shortcut cannot inflate the headline number. `null` when no route is nontrivial |
| `cuts_truncated` | More minimum cuts exist than the listing cap, or the search space exceeded the work cap |
| `objective_coverage` | Per objective: its `scope`, its routes, and their mincut |
| `geometry` | `fan_in`, `fan_out`, `disjoint`, `single_path`, or `shallow`. `shallow` is exclusive: a one-node route is the whole reading, and suppressing the others stops it manufacturing `disjoint` |
| `nontrivial_paths` | Per route, whether it has two or more interior nodes |
| `observed_cuts[].implicated_nodes` | The extensional root cause: interior nodes common to every blocked route and absent from every survivor |
| `observed_cuts[].reading` | `contestable_observed` or `terminal_over_recorded_subgraph` |
| `frontier` | The open questions: objectives with no recorded route, and routes no cut has been run against |
| `citation_sources` | How many citations resolve inside `evidence_root`, and how many elsewhere in the study |
| `warnings` | A route's witness whose text also appears in the fixed-build evidence, so it cannot show the objective was reached. Survived routes are exempt: reproducing on the repaired build is what surviving means |

Cuts are computed over recorded routes rather than graph reachability, so every
result is a statement about what was reproduced. Adding routes can only raise a
min-cut, so a large `mincut_all` is sound while a small one may only mean no
further route has been recorded yet. The analyzer never emits an accept or
reject.
