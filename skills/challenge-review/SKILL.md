---
name: challenge-review
description: "Review exactly one registered Cyber Arena attack/defense challenge at one selected stage or through the complete verifier, static, cheat, and exploitability review. Use when deciding whether a challenge is sound, defensible, exploitable, or ready for admission."
---

# Challenge review

Act as a lightweight reviewer and orchestrator. When required, run the canonical
verifier, dispatch independent specialists, wait for their results, and
adjudicate their evidence into one compact, mechanically rendered report. Do
not redo specialist reviews or modify the challenge, except for disposable
cheat mutations in isolated runtime state.

Resolve the directory containing this file as `<skill-root>`. If the current
working directory is inside the `cyber-arena-analysis` checkout, use that
repository as `<analysis-root>`. Otherwise stop and ask the user to identify the
`cyber-arena-analysis` checkout; do not default to a plugin installation or
cache directory. Persist reviews under `<analysis-root>/artifacts/reviews/`.
Locate the separate
`cyber-arena-orche` checkout as `<orche-root>`; do not persist review artifacts
there.

## Input

Treat `$ARGUMENTS`, or the explicit arguments supplied by the client, as
exactly three positional arguments:

```text
<challenge-id> <VERIFIER|STATIC|CHEAT|EXPLOITABILITY|ALL> <absolute-warehouse-path>
```

Reject missing or extra arguments and reject any other stage value. Do not
choose a challenge, infer a stage, or infer a warehouse. Require the warehouse
path to be absolute. Normalize the stage to lowercase when passing it to bundled
scripts. `CHEAT`, `EXPLOITABILITY`, and `ALL` begin with the verifier gate. A
single-stage review reports `PARTIAL`; `ALL` produces an overall verdict.

## Execute in this order

1. For `STATIC` or `ALL`, read `<analysis-root>/CONTRIBUTING.md`. For `STATIC`,
   `EXPLOITABILITY`, or `ALL`, also read
   `<analysis-root>/skills/challenge-create/references/attack-scopes.json`;
   for other scopes, load that registry only if adjudicating a surviving scope
   claim. Do not resolve upstream project identity during setup.
2. Initialize pinned review context; this validates runtime auto-discovery from
   the explicitly selected warehouse and records its absolute path, the
   challenge path, timestamp, run ID, and exact orchestrator commit. The
   collector pins orchestration commit
   `5952ef5d7a1924789da86640665e2cbd6500a8ec`, matching challenge creation:

   ```text
   python3 <skill-root>/scripts/collect-review-context.py <challenge-id> \
     --warehouse <absolute-warehouse-path> \
     --repo-root <orche-root> \
     --review-root <analysis-root>/artifacts/reviews \
     --output <temporary-context.json>
   ```

   Create the collector's `recommended_output_dir`, move the context to
   `context.json`, and initialize `review.json`:

   ```text
   python3 <skill-root>/scripts/init-report.py \
     --context <run-dir>/context.json \
     --scope <scope> \
     --output <run-dir>/review.json
   ```

3. Read [review-protocol.md](references/review-protocol.md) and the references
   for the selected scope. `ALL` uses [verifier.md](references/verifier.md),
   [static-checklist.md](references/static-checklist.md),
   [cheat-check.md](references/cheat-check.md), and
   [exploitability.md](references/exploitability.md). Read
   [antipattern-catalog.md](references/antipattern-catalog.md) only when
   classifying a surviving finding or validating a proposed WIP observation.
4. For `VERIFIER`, `CHEAT`, `EXPLOITABILITY`, or `ALL`, run the exact wrapper in
   [verifier.md](references/verifier.md) directly; do not delegate or substitute
   it. Resolve the verifier checks from its authoritative output and retain its
   verified image hash and frozen objective matrix for report assembly. For
   `VERIFIER`, proceed directly to report assembly after any verifier outcome.
   For `CHEAT`, `EXPLOITABILITY`, or `ALL`, dispatch specialists only after
   verifier `PASS`. On verifier `FAIL` or `BLOCKED`, record the dependent stages
   and their checks as `NOT_RUN` during report assembly and skip specialist
   dispatch. For `ALL`, verifier `FAIL` is a hard `REJECT`; unavailable external
   verifier infrastructure is `BLOCKED`.
5. Dispatch specialists:

   - For `STATIC`, `CHEAT`, or `EXPLOITABILITY`, dispatch the selected specialist.
   - For `ALL`, after verifier `PASS`, dispatch exactly three specialists—static,
     cheat, and exploitability—concurrently on isolated state.

   Start each task with the exact prompt in its stage reference, then provide
   the frozen context, review protocol, stage reference, and verifier output for
   dynamic stages. Give `<analysis-root>/CONTRIBUTING.md` only to the static
   specialist; give the attack-scope registry to static and exploitability. Do
   not preface or rewrite the prompt. Never reveal another specialist's
   findings, oracle reports, or a draft verdict.
   If independent agents are unavailable, stop as `BLOCKED`.
6. Wait for every dispatched specialist to finish before adjudicating. Do not
   leak partial findings between specialists or issue an early verdict.
7. For every specialist response, adjudicate each returned check result and the
   stage conclusion against its cited evidence. Then adjudicate every candidate,
   proposed unresolved concern, and WIP observation using the precision
   procedure in [review-protocol.md](references/review-protocol.md). Re-read
   cited evidence, refute weak claims, merge duplicates by root cause, and retain
   only supported check conclusions, actionable findings, benchmark-critical
   unresolved concerns, or supported non-enforcing observations.
8. Read [report-schema.md](references/report-schema.md), then populate
   `review.json` once from the authoritative verifier output and adjudicated
   specialist results. Fill the context image hash, objective matrix, stages,
   checks, retained findings, unresolved concerns, WIP observations, and
   verdict.
9. Render the report. The renderer validates `review.json` before writing
   Markdown:

   ```text
   python3 <skill-root>/scripts/render-report.py \
     <run-dir>/review.json --output <run-dir>/review.md
   ```

   JSON is authoritative. Never hand-author a second Markdown report.
10. Retain only `context.json`, `review.json`, `review.md`, canonical verifier
    output, and the minimum raw dynamic artifacts needed to substantiate a cheat
    or exploit result. Dynamic artifacts contain the exact command or request and
    observed output, not a reconstructed narrative. Preserve the exact
    authoritative `FLAG_SUBMITTED` JSON line used by `EXPLOIT-ACCEPT`; prose or
    exploit stdout is not acceptance evidence. Keep specialist transcripts and
    scratch work ephemeral.

## Stage boundaries

- **Verifier:** run only the checker in the pinned orchestration tree. It owns
  imports, Docker build and image-hash capture, mini orchestration, health,
  declared-store handler checks, live scoring-rail controls, and restart
  evidence.
- **Static:** inspect source only. Do not build, start services, invoke the
  verifier, mutate a deployment, or score an objective.
- **Cheat:** act as an authorized adversary. Seek the cheapest arena-specific
  in-band shortcut and trivial defense before evaluating normal behavior.
- **Exploitability:** reproduce the advisory-backed PoV through an
  attacker-visible, in-band path and obtain an authoritative accepted outcome
  for at least one current opponent objective. Other objectives require sound
  declarations and scoring rails, not known exploits.

Never use host Docker access, victim files or databases, facility secrets,
private handler state, or proof ground truth as attacker proof. Never launch
iterative hacker-fixer work from this skill; modifying or fortifying the
reviewed challenge is outside its scope.
