# Authoring

How a role builds its fragment. The contracts are in
[contracts.md](contracts.md); the format, and why each rule exists, is in
[graph-schema.md](graph-schema.md).

SEED follows the whole of *Fragments* and *Procedure*. EXPAND follows them too,
then *Expanding*. EXPAND copies SEED's entry rather than drafting its own; an
objective it reached on the target is its own to declare.

## Fragments

- **Neither role writes `graph.json`.** Each writes one fragment; the root
  merges them with `graph_merge.py`.
- **A fragment is a whole graph.** It carries the entry, the objectives it
  touches and its own function nodes, and it passes `graph_validate.py` alone
  before the role returns. SEED owns at least one route; EXPAND writes a
  fragment either way, and one carrying no route is what finding nothing looks
  like.
- **Redeclare a shared node under SEED's exact id and `symbol`.** `symbol` is
  required on every function node and never repeats across the document.
  `title` and `evidence` may differ; SEED's are kept.
- **Narrow a redeclared node's `predecessors`** to the ones your own routes
  use. The merge unions the lists back together.
- Everything in a fragment was reproduced — by the study, or by you. A route
  with no citable line is not a route.

## Procedure

1. **Draft nodes.** One `entry` for the identity and access the challenge
   grants the attacker, one `objective` per confirmed witness and scope, and a
   `function` for each application function the route passes through.

   Every function node is something you can point at in the application — a
   route, a handler, a named function. Record it in `symbol`. If you cannot
   name it, it is not a node.

   Authentication sits *behind* the entry, because the challenge grants the
   attacker its credential. Model it only when the attack turns on the
   authentication function itself.

2. **Decide granularity by what a defender can cut.**

   > **Name a mitigation that stops this link and not its neighbour.**
   > If you cannot, they are one node.

   Decide it against the application, not against `reproduce.py`'s output
   format.

3. **Wire `predecessors`.** They are OR by default — a route arrives through
   one of them. Set `conjunctive: true` only for a node that needs all of them.

4. **Establish every node and route against the running target.** Use
   `probe.py` (contracts.md) and paste what it prints under `evidence:`. It
   builds the three fields from the response and refuses a claim the response
   does not contain, which is the one thing hand-assembled evidence cannot check
   about itself. Do not write your own request harness.

   **Do not cite the study.** Its prose and its retained `evidence/` files say
   where to look; they are not facts this run established, and nothing in the
   graph may rest on them. A node you cannot reach on the target is not a node —
   it is an unsettled claim.

5. **Draft routes.** Each is one walk from the entry to an objective, listing
   every node it passes through and nothing it could have skipped. When the
   validator names a node the route did not need, either record the shorter
   route or narrow the `predecessors` that made the shortcut possible.

   Name it `PATH-<node it enters through>-<node that reaches the objective>`,
   `N-` dropped from both — see graph-schema.md. Do not invent a description.

   A chain reproduced twice is better evidence for one route, not a second
   route: add the replay to that route's `witnesses`. Record `advisories`.

6. **Record the cut the advisory accepted.** Name the advisory in
   `advisory_cut.advisory` — the CVE, or the upstream commit where the fix
   shipped without one. Read the fix and name the nodes it guarded in
   `advisory_cut.nodes` — that is the one cut here anyone has judged
   admissible, so it is the exemplar. Then run each route against the repaired
   build and record what it achieved. `survived` needs one witness. `refused`
   cannot be proved at all, so it records only what you sent, and its `tried`
   field names the payload **shapes** you attempted. Vary the shape, not just the
   value: a run recorded three routes closed on thirteen probes that all named
   the protected table directly, and a fourth shape — the query carried as a
   string literal — opened every one of them. If the only shape you tried is the
   study's own, say so in `tried`: that is the commonest way a run mistakes a
   payload for a route. Leave the cut out only when the study ships no fix.

7. **Validate, fix, repeat until clean.**

## Expanding

1. **Name the fault.** Read what `STAGE3_STUDY.md` says is defective, then
   establish it against the running target. Never substitute a min-cut for the
   fault: a min-cut is arithmetic over the recorded routes and claims nothing
   about what is defective.

2. **Expand from the fault.** It is one named thing in the application, so this
   is bounded:

   - other routes that reach the same fault;
   - other objectives the same fault exposes — **declare them**, with a scope
     from the registry, when you reached one on the target. Nothing at Stage 3
     declares the objective; both roles reconstruct it, so yours stands beside
     SEED's. You may not add an `entry`: that is the identity the challenge
     grants, and a second one lowers every cut.

3. **Then, only where the study's own evidence suggests a second defect,** look
   for a route that avoids the nodes the routes you have already share.
   Secondary and speculative. Do not go looking for ways around functions that
   work.

4. **Run it, then record it.** Run the check with `probe.py` and carry what it
   prints into the graph as the observation itself.

5. **Score what you did.** Do not assert a new `mincut_all`; the root re-runs
   the analyzer.

Root cause stays out of the IR: it lives in your response as a stated reading,
and never as a field.
