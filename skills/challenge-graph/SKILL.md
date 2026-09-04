---
name: challenge-graph
description: Build the attack-graph intermediate representation for one completed Cyber Arena Stage 3 study, then compute its cuts, geometry, and coverage and render a diagram. Use when analyzing or visualizing what a challenge's reproduced attack structure is, or when checking whether a study's recorded decision matches its own evidence. Do not use to promote, reject, or review a challenge.
---

# Challenge graph

Turn one completed Stage 3 study into a graph of the attack structure it
reproduced, then compute cuts and geometry over it and draw it.

The graph records what was reproduced. It is not the complete attack surface,
it never claims closure, and it decides nothing: contestability admission
remains the empirical branch-survival test, and this skill only describes and
predicts.

## Read first

Resolve the directory containing this file as `<skill-root>`. Resolve the
current working directory's enclosing Git checkout as `<analysis-root>` only
when its origin identifies `cyber-arena-analysis`; otherwise stop and ask the
user to identify that checkout. Use Python 3.11 or newer.

1. Read [graph-schema.md](references/graph-schema.md) completely.
2. Read `<analysis-root>/skills/challenge-create/references/attack-scopes.json`
   before declaring any objective scope.

## Input

One required positional argument, absolute and never inferred:

```text
<absolute-study-dir> [--out <absolute-output-dir>]
```

Reject extra arguments. `<absolute-study-dir>` is a completed Stage 3 study
containing `STAGE3_STUDY.md`, `result.json`, and the evidence files
`result.json` names. The retained corpus holds three incompatible `result.json`
shapes: read the reproduced revision from whichever of `reproduced_commit`,
`commit`, or `vulnerable_commit` is present, and say which one you used. Any
`outcome` is accepted, because a graph over a `rejected` study still shows why
it was rejected.

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
directory's basename. Copy it; do not derive it from `result.json`'s
`repository`, whose casing and punctuation do not match the directory names and
which some studies do not retain. Use `--out` only for a one-off.

Create `<out>` and author `graph.json` there. Keep only scratch notes in `/tmp`,
and never open a file under the study directory for writing.

## Execute in this order

1. Read `result.json`, confirm the precondition, and list the evidence files it
   names.
2. Read `STAGE3_STUDY.md`, especially **Attack chain** and **Witness and
   authoring consequences**. These are the semantic source; the graph is their
   structured form.
3. Draft states: one `entry`, one `objective` per confirmed witness and scope,
   and the `intermediate` states the chain requires.
4. Draft operations, **one per required link named in the study's attack
   chain**, each citing its own distinct evidence line. Collapsing a chain into
   one operation, or splitting one link into two, flips the geometry between
   `shallow` and everything else, so the rule is not cosmetic: when a link has
   no evidence line of its own, model it as part of the neighbouring operation
   rather than inventing a citation for it.

   **Open each evidence file and cite a real line plus a string that is
   actually on it.** Do not write an operation from the study's prose alone.
   Mark authentication, setup, retries, encoding, reconnaissance, and proof
   submission as `counts_as_operation: false`.

   The attacker's observation of the result is not an operation: it is the
   objective state, produced by the operation that crosses the boundary. Work
   from [example-graph.json](references/example-graph.json), which fixes this
   and the `target.id` and `store` conventions.
5. Draft paths, then `observed_cuts` from the fixed-case evidence. At Stage 3
   the observed cut is the upstream-fixed deployment.
6. Validate, fix, and repeat until clean:

   ```text
   python3 <skill-root>/scripts/graph_validate.py <out>/graph.json \
     --study-dir <absolute-study-dir> \
     --scope-registry <analysis-root>/skills/challenge-create/references/attack-scopes.json
   ```

   A trivial one-operation path is *not* rejected: it validates and the
   analyzer labels it `shallow`, so a graph over a rejected study still shows
   why it was rejected.

7. Analyze and render:

   ```text
   python3 <skill-root>/scripts/graph_analyze.py <out>/graph.json \
     --out <out>/analysis.json --study-dir <absolute-study-dir> \
     --scope-registry <analysis-root>/skills/challenge-create/references/attack-scopes.json
   python3 <skill-root>/scripts/graph_render.py <out>/graph.json \
     --out <out>/graph.md --study-dir <absolute-study-dir> \
     --scope-registry <analysis-root>/skills/challenge-create/references/attack-scopes.json
   ```

   All three revalidate, so neither deliverable can be produced from a graph
   whose evidence does not resolve.

8. Reconcile the analysis against the study's own recorded decision. Compare
   `geometry`, `mincut_all`, `mincut_nontrivial`, `cuts_truncated`,
   `evidence_strength`, and each observed cut's `reading` with what
   `STAGE3_STUDY.md` concluded. When
   `shallow` appears, read `mincut_nontrivial` rather than `mincut_all`.

   Raise a `NOTE` for exactly these disagreements, and no others:

   - the study reports a surviving path but no observed cut reads
     `contestable_observed`, or the reverse;
   - the study calls the chain nontrivial but `nontrivial_paths` is false, or
     the reverse;
   - a cut the analyzer lists among the cheapest is one the study rules out,
     for instance as feature amputation. The analyzer has no cost model, so
     `mincut_all` can understate what a *valid* defense costs.

   The study's `outcome` is a Stage 3 authoring verdict, not a graph property;
   never report agreement or disagreement with it. **Never adjust the graph to
   make it agree** — the disagreement is the finding.

## Deliverable

```text
artifacts/projects/<PROJECT>/graph/<study-name>/
├── graph.json        the IR
├── analysis.json     cuts, mincut_all, geometry, coverage, frontier
└── graph.md          the diagram and summary tables
```

Report the study and reproduced commit, the geometry and `mincut_all`, whether
the observed cut left a surviving path, the open frontier — objectives with no
recorded path and paths no cut has been run against — and every `NOTE` where
the analysis disagreed with the study. When `evidence_strength.recorded_only` is
true, say so: the reading rests on the study's own tables, not raw output.

## Cleanup

Remove `/tmp` drafts and confirm the study directory is unmodified. There is
nothing else to tear down, because this skill starts nothing.

## Boundaries

- The graph never promotes or rejects a challenge, and no skill may treat a
  graph property as an admission criterion.
- Record only reproduced or dynamic evidence. An asserted alternative path is
  not evidence and the validator rejects it.
- A large `mincut_all` is sound; a small one may only mean no further path has
  been recorded. Never report a terminal reading as proof that no other attack
  path exists.
- The graph is a complete exploit map for the paths it holds. It stays in the
  Git-ignored `artifacts/` tree and never reaches an agent-visible surface.
