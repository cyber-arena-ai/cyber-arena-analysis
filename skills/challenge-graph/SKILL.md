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

3. **Dispatch SEED** with [roles.md](references/roles.md) and
   [graph-schema.md](references/graph-schema.md) attached unchanged, using the
   SEED opening prompt in the first. Give it the study directory, the scope
   registry, and `<out>/roles/seed.json` as its fragment path.

   If independent agents are unavailable, follow roles.md's authoring procedure
   yourself, write the result straight to `<out>/graph.json` instead of a
   fragment, and skip to step 9. There is no second fragment and no merge, so
   the deliverable carries no `merge.json` and none of the accountability one
   would give it. Report `roles: root_only` in the handoff, and never read a
   single-role result as terminal.

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

6. **Dispatch EXPAND** with the same two files and the EXPAND opening prompt,
   plus SEED's fragment, that analysis, the study, its evidence, the scope
   registry, and `<out>/roles/expand.json` and `<out>/roles/expand.md` as its
   two output paths.

7. **Merge.** Never hand-edit a fragment and never assemble `graph.json`
   yourself:

   ```text
   python3 <skill-root>/scripts/graph_merge.py \
     <out>/roles/seed.json <out>/roles/expand.json \
     --out <out>/graph.json --record <out>/roles/merge.json \
     --study-dir <absolute-study-dir> \
     --scope-registry <analysis-root>/skills/challenge-create/references/attack-scopes.json
   ```

   To refuse one of EXPAND's routes, pass `--refute <PATH-ID>=<reason>`. The
   reason lands in `merge.json`. The union is otherwise mechanical, so no route
   leaves this step unrecorded — you own the deliverable, and a refusal has to
   be on the record. The other way a route can disappear is a re-dispatch,
   which replaces a fragment wholesale; that is why step 8 makes you record
   those too.

   Fragments each validate alone, but their union can still fail; the merge
   writes nothing when it does. Re-dispatch the owning role with the message,
   and never repair a fragment by hand.

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
   fragment. **A confirmed change to SEED's node set invalidates EXPAND's
   fragment**: EXPAND wrote its routes against ids and symbols that no longer
   exist, and a split node's new symbols mean the duplicate guard cannot see the
   alias. Re-dispatch EXPAND too, then merge and analyze again. Record every
   re-dispatch and why in the handoff; nothing else does.

   Adjudicate EXPAND's leads the same way and carry the surviving ones into the
   report; they are not nodes and change no number.

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

10. Resolve every `warnings` entry before reporting. A witness that reads the
    same on the line its own route's `blocked` entry cites does not show the
    objective was reached — find a line that differs across builds, or say why
    none exists. Nothing is checked for a route no cut blocked, so an empty
    `warnings` can also mean there was nothing to compare against.

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

## Deliverable

```text
artifacts/projects/<PROJECT>/graph/<study-name>/
├── graph.json        the merged IR
├── analysis.json     cuts, mincut, geometry, coverage, frontier, warnings
├── graph.md          the diagram and summary tables
└── roles/            dispatched roles only; absent under `roles: root_only`
    ├── seed.json             SEED's fragment
    ├── seed-analysis.json    what EXPAND was given
    ├── expand.json           EXPAND's fragment, when it found a route
    ├── expand.md             the fault, its cross-check, and every lead
    └── merge.json            what merged and what was refused
```

Report the study and reproduced commit, the geometry and `mincut_all`, whether
the observed cut left a surviving route, the open frontier — objectives with no
recorded route and routes no cut has been run against — every unresolved
`warnings` entry, and every `NOTE` where the analysis disagreed with the study.
Carry `merge.json` into the handoff: every route you refuted and why, whatever
the merge dropped with it (`nodes_dropped`, `cuts_dropped`), and any SEED node
the union changed (`requires_widened`).
Report EXPAND's fault and whether `implicated_nodes` agreed, the cuts its
routes eliminated, its surviving leads, and `needs_study` when it found no
route. Report `citation_sources`: it counts the citations resting on
`STAGE3_STUDY.md` rather than on retained output, and that part of the reading
is the study's own prose.

## Cleanup

Remove `/tmp` drafts and confirm the study directory is unmodified. There is
nothing else to tear down, because this skill starts nothing.

## Boundaries

- The graph never promotes or rejects a challenge, and no skill may treat a
  graph property as an admission criterion.
- Never report a terminal reading as proof that no other attack path exists. A
  role that found nothing is `needs_study`.
- Root cause never becomes a node or a field. It is a stated reading with a
  computed cross-check, because the same two chains are one weakness or two
  depending on where the modeler stands.
- The graph is a complete exploit map for the routes it holds. It stays in the
  Git-ignored `artifacts/` tree and never reaches an agent-visible surface.
