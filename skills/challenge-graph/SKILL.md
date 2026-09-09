---
name: challenge-graph
description: "Build the attack-graph intermediate representation for one completed Cyber Arena Stage 3 study, then compute its cuts, geometry, and coverage and render a diagram. Use when analyzing or visualizing what a challenge's reproduced attack structure is, or when checking whether a study's recorded decision matches its own evidence. Do not use to promote, reject, or review a challenge."
---

# Challenge graph

Turn one completed Stage 3 study into a graph of the attack structure it
reproduced, then compute cuts and geometry over it and draw it.

The graph records what was reproduced. It is not the complete attack surface,
it never claims closure, and it decides nothing: contestability admission
remains the empirical branch-survival test, and this skill only describes and
predicts.

You are the **root**. You set up, dispatch the SEED and EXPAND roles,
adjudicate what they return, and own every deliverable. You do not author the
graph you adjudicate.

## Read first

Resolve the directory containing this file as `<skill-root>`. Resolve the
current working directory's enclosing Git checkout as `<analysis-root>` only
when its origin identifies `cyber-arena-analysis`; otherwise stop and ask the
user to identify that checkout. Use Python 3.11 or newer.

1. Read [graph-schema.md](references/graph-schema.md) completely.
2. Read [roles.md](references/roles.md).
3. Read `<analysis-root>/skills/challenge-create/references/attack-scopes.json`
   before declaring any objective scope.

## Input

One required positional argument, absolute and never inferred:

```text
<absolute-study-dir> [--out <absolute-output-dir>]
```

Reject extra arguments. `<absolute-study-dir>` is a completed Stage 3 study
containing `STAGE3_STUDY.md` and whatever evidence it retained. The retained
corpus holds several incompatible `result.json` shapes: read the reproduced
revision from whichever of `reproduced_commit`, `commit`, or
`vulnerable_commit` is present, ignore `primary_commit` and `repair_commit`,
and say which field you used. Any `outcome` is accepted, because a graph over a
`rejected` study still shows why it was rejected.

This skill starts no container, network request, or game instance. It only
re-reads retained evidence.

## Output location

Derived, not supplied:

```text
<analysis-root>/artifacts/projects/<PROJECT>/graph/<study-name>/
```

`<PROJECT>` is copied verbatim from the study's own path — a study at
`artifacts/projects/<PROJECT>/stage3/...` writes to
`artifacts/projects/<PROJECT>/graph/...` — and `<study-name>` is the study
directory's basename, which for a study that *is* `stage3/` is `stage3`. Copy
both; do not derive them from `result.json`'s `repository`, whose casing and
punctuation do not match the directory names. Use `--out` only for a one-off.

Create `<out>`, and `<out>/roles/` once a role is dispatched. Keep only scratch
notes in `/tmp`, and never open a file under the study directory for writing.

## Execute in this order

1. Read `result.json` if present, confirm the reproduced revision, and list the
   evidence files it names.
2. Read `STAGE3_STUDY.md` whole. The attack chain and the witness and authoring
   consequences are the semantic source, and usually sit under headings named
   for them — but **the headings are not guaranteed**. Several studies name
   their sections differently or use a different heading level, and some have
   no section by either name. Locate the material by content and continue; a
   missing heading is not a reason to stop.

3. **Dispatch SEED.** Use the opening prompt in
   [roles.md](references/roles.md), attached unchanged along with
   [graph-schema.md](references/graph-schema.md) and the *Authoring procedure*
   below. Give it the study directory, the scope registry, and
   `<out>/roles/seed.json` as its fragment path.

   If independent agents are unavailable, follow the authoring procedure
   yourself, write the result straight to `<out>/graph.json` instead of a
   fragment, and skip to step 9. Report `roles: root_only` in the handoff, and
   never read a single-role result as terminal.

4. **Gate on SEED.** Validate its fragment. A fragment whose evidence does not
   resolve does not get to spend the second dispatch:

   ```text
   python3 <skill-root>/scripts/graph_validate.py <out>/roles/seed.json \
     --study-dir <absolute-study-dir> \
     --scope-registry <analysis-root>/skills/challenge-create/references/attack-scopes.json
   ```

5. **Analyze SEED's fragment**, so EXPAND receives `implicated_nodes` and
   `minimum_cuts_all` rather than deriving them:

   ```text
   python3 <skill-root>/scripts/graph_analyze.py <out>/roles/seed.json \
     --out <out>/roles/seed-analysis.json --study-dir <absolute-study-dir> \
     --scope-registry <analysis-root>/skills/challenge-create/references/attack-scopes.json
   ```

6. **Dispatch EXPAND** with [roles.md](references/roles.md),
   [graph-schema.md](references/graph-schema.md), and the *Authoring procedure*
   below attached unchanged — it authors nodes too, so the severability test
   binds it as much as SEED — plus SEED's fragment, that analysis, the study,
   its evidence, the scope registry, and `<out>/roles/expand.json` and
   `<out>/roles/expand.md` as its two output paths. Use the EXPAND opening
   prompt in [roles.md](references/roles.md). EXPAND is blind to nothing.

7. **Merge.** Never hand-edit a fragment and never assemble `graph.json`
   yourself:

   ```text
   python3 <skill-root>/scripts/graph_merge.py \
     <out>/roles/seed.json <out>/roles/expand.json \
     --out <out>/graph.json --record <out>/roles/merge.json \
     --study-dir <absolute-study-dir> \
     --scope-registry <analysis-root>/skills/challenge-create/references/attack-scopes.json
   ```

   Each fragment validates alone, so a duplicated `symbol` only appears when
   the union names one application function twice; the merged revalidation
   rejects it. Two *different* names for one function still get
   through, which is what `NODE-MERGE` below is for.

   To refuse one of EXPAND's routes, pass `--refute <PATH-ID>=<reason>`. The
   reason lands in `merge.json`. There is no other way to drop a route, which
   is the point: you own the deliverable, so a refusal must be on the record.

   Fragments each validate alone, but the union can still fail: widening a
   node's `requires` can open a shortcut that leaves an EXPAND route carrying a
   node it no longer needs. The merge writes nothing when that happens.
   Re-dispatch the owning role with the message; never repair a fragment by
   hand.

   When EXPAND returned no fragment, copy SEED's to `<out>/graph.json`, write
   no `merge.json`, and record `expand: needs_study` with the fault it could not
   reach another way.

8. **Adjudicate.** Re-read every cited construct in full — you saw SEED's
   reasoning as its dispatcher, so the artifact and its evidence are what you
   check, not the argument for it. Three judgments no script can make:

   - **`ENTRY-WIDE`** — a node declared `entry` that the scenario does not
     grant. The entry set is excluded from every cut, so widening it lowers the
     min-cut with nothing to catch it.
   - **`NODE-SPLIT` / `NODE-MERGE`** — a severability disagreement. Name a
     mitigation that stops one link and not its neighbour; if you cannot, they
     are one node. This sets every number.
   - **`CITATION-WEAK`** — the cited line carries the quoted string but does not
     support the claim. The validator checks the first and cannot check the
     second.

   Classify each `CONFIRMED` or `REFUTED` against re-read evidence. A confirmed
   contest is repaired by re-dispatching the owning role, never by editing its
   fragment. Adjudicate EXPAND's leads the same way and carry the surviving
   ones into the report; they are not nodes and change no number.

9. **Analyze and render** the merged graph:

   ```text
   python3 <skill-root>/scripts/graph_analyze.py <out>/graph.json \
     --out <out>/analysis.json --study-dir <absolute-study-dir> \
     --scope-registry <analysis-root>/skills/challenge-create/references/attack-scopes.json
   python3 <skill-root>/scripts/graph_render.py <out>/graph.json \
     --out <out>/graph.md --study-dir <absolute-study-dir> \
     --scope-registry <analysis-root>/skills/challenge-create/references/attack-scopes.json
   ```

   All four scripts revalidate, so no deliverable can be produced from a graph
   whose evidence does not resolve.

10. Resolve every `warnings` entry before reporting. A route's witness that
    also appears in the fixed-build evidence does not show the objective was
    reached — find a line that differs across builds, or say why none exists.

11. Reconcile the analysis against the study's own recorded decision. Compare
    `geometry`, `mincut_all`, `mincut_nontrivial`, `cuts_truncated`, and each
    observed cut's `reading` with what `STAGE3_STUDY.md` concluded. When
    `shallow` appears, read `mincut_nontrivial` rather than `mincut_all`.

    Raise a `NOTE` for exactly these disagreements, and no others:

    - the study reports a surviving route but no observed cut reads
      `contestable_observed`, or the reverse;
    - the study calls the chain nontrivial but `nontrivial_paths` is false, or
      the reverse;
    - a cut the analyzer lists among the cheapest is one the study rules out,
      for instance as feature amputation. The analyzer has no cost model, so
      `mincut_all` can understate what a *valid* defense costs;
    - EXPAND's fault and the study's own account of the fault disagree.

    The study's `outcome` is a Stage 3 authoring verdict, not a graph property;
    never report agreement or disagreement with it. **Never adjust the graph to
    make it agree** — the disagreement is the finding.

## Authoring procedure

SEED follows this, and so does the root when no independent agent is available.
It produces one fragment, not `graph.json`.

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

   Two steps a single fix covers are one node. Two steps a defender could guard
   independently are two. This is the decision that sets every number, so make
   it against the application, not against `reproduce.py`'s output format.

3. Wire each node's `requires`. Predecessors are **OR by default** — a route
   uses one of them. Set `requires_all: true` only for a genuine conjunction,
   such as a request that needs both an authenticated session and state stored
   by an earlier call.

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

   Record `advisories` for each route, listing every advisory it reproduces —
   a chained attack names several.

5. Draft `observed_cuts` from the fixed-case evidence. At Stage 3 the observed
   cut is the upstream-fixed deployment. A fragment holding only a surviving
   route records that survivor and no blocked path; that is a legitimate cut.

6. Validate, fix, and repeat until clean. A trivial one-node route is *not*
   rejected: it validates and the analyzer labels it `shallow`, so a graph over
   a rejected study still shows why it was rejected.

## Deliverable

```text
artifacts/projects/<PROJECT>/graph/<study-name>/
├── graph.json        the merged IR
├── analysis.json     cuts, mincut, geometry, coverage, frontier, warnings
├── graph.md          the diagram and summary tables
└── roles/                 dispatched roles only; absent under `roles: root_only`
    ├── seed.json             SEED's fragment
    ├── seed-analysis.json    what EXPAND was given
    ├── expand.json           EXPAND's fragment, when it found a route
    ├── expand.md             the fault, its cross-check, and every lead
    └── merge.json            `seed` and `expand` inputs, `nodes_added`,
                              `requires_widened`, `routes_added`,
                              `routes_refuted` with reasons, `nodes_dropped`,
                              `cuts_dropped` (absent when EXPAND returned
                              no fragment)
```

Report the study and reproduced commit, the geometry and `mincut_all`, whether
the observed cut left a surviving route, the open frontier — objectives with no
recorded route and routes no cut has been run against — every unresolved
`warnings` entry, and every `NOTE` where the analysis disagreed with the study.
Carry `merge.json` into the handoff: every route you refuted and why, and
whatever the merge dropped with it (`nodes_dropped`, `cuts_dropped`).
Report EXPAND's fault and whether `implicated_nodes` agreed, the cuts its
routes eliminated, its surviving leads, and `needs_study` when it found no
route. When `citation_sources` shows citations resolving outside
`evidence_root`, say so: that part of the reading rests on the study's own
prose.

## Cleanup

Remove `/tmp` drafts and confirm the study directory is unmodified. There is
nothing else to tear down, because this skill starts nothing.

## Boundaries

- The graph never promotes or rejects a challenge, and no skill may treat a
  graph property as an admission criterion.
- Never report a terminal reading as proof that no other attack path exists. A
  role that found nothing is `needs_study`.
- The entry set is the one author claim the analysis cannot check, because a
  node declared `entry` is excluded from every cut. Make it the identity the
  challenge grants, nothing more.
- Root cause never becomes a node or a field. It is a stated reading with a
  computed cross-check, because the same two chains are one weakness or two
  depending on where the modeler stands.
- The graph is a complete exploit map for the routes it holds. It stays in the
  Git-ignored `artifacts/` tree and never reaches an agent-visible surface.
