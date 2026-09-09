# Roles

Two dispatched roles and a root. Attach this file unchanged to both roles.

| | Owns | Reads |
|---|---|---|
| **SEED** | the terminals and the advisory-backed routes | study, evidence, advisory |
| **EXPAND** | further routes to the objectives SEED declared | SEED's graph and analysis, study, evidence |
| **root** | setup, dispatch, adjudication, every deliverable | everything |

## Both roles

- **Neither role writes `graph.json`.** Each writes its own fragment under
  `<out>/roles/` and the root merges them with `graph_merge.py`.
- **A fragment is a whole graph.** It carries the entry, the objectives it
  touches, its own function nodes, and at least one route, and it must pass
  `graph_validate.py` on its own before the role returns.
- **Redeclare a shared node under SEED's exact id and `symbol`.** One
  application function under two ids makes two routes look like they share
  nothing, which halves the min-cut and manufactures a `disjoint` reading.
  `symbol` is required on every function node and never repeats; `title` and
  `evidence` may differ, and SEED's are kept.
- Everything in a fragment was reproduced. A route with no citable line is not
  a route.
- Neither role edits the study directory, and neither starts a container,
  network request, or game instance.

## Authoring procedure

SEED follows this in full. EXPAND authors nodes too, so the severability test
binds it equally — but it copies SEED's entry and objectives rather than
drafting them, and adds no objective of its own (CH-4). It produces one
fragment, not `graph.json`.

1. Draft nodes. One `entry` for the identity and access the challenge grants
   the attacker, one `objective` per confirmed witness and scope, and a
   `function` for each application function or route the route passes through.

   **Every function node must be something you can point at in the
   application** — a route, a handler, a named function. Record it in `symbol`.
   If you cannot name it, it is not a node: reconnaissance, retries, encoding,
   and proof submission have no application artifact behind them, and the
   attacker's observation of the result is the objective, not a node.

   Authentication is normally *behind* the entry, because the challenge grants
   the attacker its credential. Model it as a node only when the attack turns
   on the authentication function itself.

2. Decide granularity with the severability test, not by how verbosely the
   evidence file happened to log:

   > **Name a mitigation that stops this link and not its neighbour.**
   > If you cannot, they are one node.

   Two steps a single fix covers are one node. This is the decision that sets
   every number, so make it against the application, not against
   `reproduce.py`'s output format.

3. Wire each node's `requires`. Predecessors are **OR by default** — a route
   uses one of them. Set `requires_all: true` only for a genuine conjunction.

   **Open each evidence file and cite a real line plus a string that is
   actually on it.** Do not write a node from the study's prose alone when the
   study retained output that witnesses it. Where the study retained nothing
   else, citing `STAGE3_STUDY.md` is legitimate; the analysis reports how many
   citations land where, so it is visible rather than hidden.

4. Draft routes. Each is one walk from the entry to an objective, listing every
   node it passes through and **nothing it could have skipped**. The validator
   names any node the route did not need; when it does, either record the
   shorter route or narrow the `requires` that made the shortcut possible.

   A study that reproduced its chain twice recorded better evidence for one
   route, not a second route. Add the replay to that route's `witnesses`.

   Record `advisories` for each route.

5. Draft `observed_cuts` from the fixed-case evidence. At Stage 3 the observed
   cut is the upstream-fixed deployment. A fragment holding only a surviving
   route records that survivor and no blocked path; that is a legitimate cut.

6. Validate, fix, and repeat until clean.

## SEED

SEED owns the entry and the objectives, because objectives derive from the asset
graph and never from the vulnerability (CH-4), and it is the only role that
reads the advisory.

### Opening prompt

```text
You are the SEED role for the challenge graph over Stage 3 study `<study-dir>`. Author the terminals and the routes the advisory describes, as one fragment at `<out>/roles/seed.json`. It must pass graph_validate.py --study-dir `<study-dir>` --scope-registry `<scope-registry>` before you return. You own the entry node and every objective; a later role may add routes but may not add either. Return only the SEED response defined in the attached roles reference.
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
Cited outside evidence_root: <each node or route citing the study document>
```

## EXPAND

### Procedure

1. **Name the fault.** Read what `STAGE3_STUDY.md` says is defective, and what
   the upstream fix changed. Cross-check it against the analyzer's
   `observed_cuts[].implicated_nodes` — *interior nodes common to every blocked
   route and absent from every survivor* — which is the same fault derived
   extensionally from a defense that was really applied. Where the study
   retained no fixed-build evidence there is no observed cut and
   `implicated_nodes` is empty: declare the fault from prose and say it is
   unchecked. Never substitute a min-cut for it; a min-cut is arithmetic over
   the recorded topology and carries no claim that anything is defective.

   Read `implicated_nodes` as an **upper bound**: on the single-route fragment
   you are handed it is usually the whole route interior, not the fault. Report
   a disagreement only when the study's fault is *absent* from it, and do not
   reconcile the two.

2. **Expand from the fault.** This is the primary pass and it is bounded,
   because the fault is one named thing in the application:

   - other routes that reach the same fault;
   - other objectives the same fault exposes.

3. **Then, only where the study's own evidence suggests a second defect,**
   look for a route that avoids one of the cuts in `minimum_cuts_all`. This is
   secondary and speculative. Do not go looking for ways around functions that
   work correctly.

4. **Say how the observed cut treated your routes.** Read the fixed-build
   evidence and record each new route under the *same cut id SEED used* — two
   ids for one defense split the reading, so a route that escaped it would not
   show up against the cut it escaped. A fragment whose routes all survived
   records them under `survived` with an empty `blocked`; that is a legitimate
   cut and the point of the schema allowing it.

5. **Cite or downgrade.** A route needs a real line in retained evidence, like
   any other. A route you believe in but cannot cite is a **lead**: name it,
   say why the fault reaches it, and give the exact check that would settle it.
   A lead is not a node, carries no citation, and changes no number.

6. **Score what you did.** Report which cuts in `minimum_cuts_all` a new route
   avoids — each of those is eliminated as a candidate defense. Do not assert a
   new `mincut_all`; the root re-runs `graph_analyze.py` for that. When
   `cuts_truncated` is set the listing is capped, so treat elimination as a
   count, not a proof.

Root cause stays out of the IR. It is debatable by nature — the same two chains
are one weakness or two depending on where you stand — so it lives in your
report as a stated reading with a computed cross-check, and never as a field.

Write the fault, its cross-check, and every lead to `<out>/roles/expand.md`;
the response below summarizes it, and the leads have to outlive the dispatch.

Finding nothing is `needs_study`, never terminality. Say which fault you could
not reach another way, and by what search. Return no fragment rather than an
empty one.

### Opening prompt

```text
You are the EXPAND role for the challenge graph over Stage 3 study `<study-dir>`. You are given SEED's graph, its analysis, the study, and its evidence; you are blind to nothing. Identify the fault the study reproduced, then find further routes that reach that fault, and further objectives it exposes. Write them as one fragment at `<out>/roles/expand.json` that passes graph_validate.py --study-dir `<study-dir>` --scope-registry `<scope-registry>` on its own, and write your fault, its cross-check, and every lead to `<out>/roles/expand.md`. Copy any node SEED already declared under its exact id. You may add function nodes and routes; you may not add an entry or an objective. Return only the EXPAND response defined in the attached roles reference.
```

### Response

```text
Role: EXPAND
Fault: <one sentence>
Fault cross-check: implicated_nodes <ids> | none recorded (no observed cut)
Fragment: <absolute path, or none>
Routes added: <path ids, or none>
Cuts eliminated: <cuts from minimum_cuts_all a new route avoids, or none>
Leads:
- Claim: <the route the fault suggests>
  Reaches the fault by: <one sentence>
  Exact check: <the one command or request that would settle it>
Needs study: <when no route was found: the fault, and the search that failed>
```
