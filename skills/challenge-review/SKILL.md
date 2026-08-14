---
name: challenge-review
description: "Review exactly one registered Cyber Arena attack/defense challenge at one selected stage or through the complete verifier, static, cheat, and exploitability review. Use when deciding whether a challenge is sound, defensible, exploitable, or ready for admission."
---

# Challenge review

Act as a lightweight reviewer and orchestrator. Run the canonical verifier,
dispatch independent specialists, wait for their results, and adjudicate their
evidence into one compact, mechanically rendered report. Do not redo specialist
reviews or modify the challenge, except for disposable cheat mutations in
isolated runtime state.

## Input

Treat `$ARGUMENTS`, or the explicit arguments supplied by the client, as
exactly two positional arguments:

```text
<challenge-id> <VERIFIER|STATIC|CHEAT|EXPLOITABILITY|ALL>
```

Reject missing or extra arguments and reject any other stage value. Do not
choose a challenge or infer a stage. Normalize the stage to lowercase when
passing it to bundled scripts. `CHEAT`, `EXPLOITABILITY`, and `ALL` begin with
the verifier gate. A single-stage review reports `PARTIAL`; `ALL` produces an
overall verdict.

## Execute in this order

1. Locate the repository root. Read `challenge-warehouse/contributions.md` and
   `docs/attack_scopes.json`. Treat advisory CWE weakness labels as root-cause
   evidence, not as the Technical Impact proved by a flag.
2. Initialize deterministic context; this validates registry membership and
   records the challenge path, timestamp, run ID, and exact orchestrator,
   warehouse, and verifier commits:

   ```text
   python3 skills/challenge-review/scripts/collect-review-context.py <challenge-id> \
     --repo-root <repo-root> \
     --verifier-ref challenge-authoring \
     --output <temporary-context.json>
   ```

   The collector prints known IDs when membership fails. Registry membership is
   setup only; do not treat it as verifier evidence. Create the collector's
   `recommended_output_dir`, move the context to `context.json`, and initialize
   `review.json`:

   ```text
   python3 skills/challenge-review/scripts/init-report.py \
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
   classifying a surviving finding.
4. For `VERIFIER`, `CHEAT`, `EXPLOITABILITY`, or `ALL`, run the exact wrapper in
   [verifier.md](references/verifier.md) from the master context and populate
   the verifier checks from its authoritative output. Do not delegate or
   substitute this command. Require pinned source commits and a built-image
   `sha256:<64 hex>` ID. For `ALL`, verifier `FAIL` is a hard `REJECT`: mark the
   other stages `NOT_RUN` and skip to reporting. Treat unavailable external
   verifier infrastructure as `BLOCKED`. Continue only after verifier `PASS`.
5. Dispatch specialists:

   - For `STATIC`, `CHEAT`, or `EXPLOITABILITY`, dispatch the selected specialist.
   - For `ALL`, after verifier `PASS`, dispatch exactly three specialists—static,
     cheat, and exploitability—concurrently on isolated state.

   Start each task with the exact prompt in its stage reference, then provide
   the frozen context, contribution contract, review protocol, stage reference,
   and verifier output for dynamic stages. Do not preface or rewrite the prompt.
   Never reveal another specialist's findings, an oracle, or a draft verdict.
   If independent agents are unavailable, stop as `BLOCKED`.
6. Wait for every dispatched specialist to finish before adjudicating. Do not
   leak partial findings between specialists or issue an early verdict.
7. Adjudicate every candidate using the precision procedure in
   [review-protocol.md](references/review-protocol.md). Re-read cited evidence,
   refute weak claims, merge duplicates by root cause, and retain only
   actionable findings or benchmark-critical unresolved concerns. Do not use
   voting or numeric confidence thresholds.
8. Fill the selected high-level checklist. Use `UNKNOWN` only with concise
   evidence, one exact `next_check`, and a matching unresolved concern. Static
   review may require a later runtime check but never executes it. Keep each
   stage and checklist summary to one conclusion sentence; put supporting facts
   only in its `evidence` field or surviving finding. Use `BLOCKED` only for
   external infrastructure.
9. Persist only `context.json`, `review.json`, `review.md`, canonical verifier
   output, and the minimum raw dynamic artifacts needed to substantiate a cheat
   or exploit result. Dynamic artifacts contain the exact command or request and
   observed output, not a reconstructed narrative. Keep specialist transcripts
   and scratch work ephemeral.
10. Validate and render once:

   ```text
   python3 skills/challenge-review/scripts/validate-report.py <run-dir>/review.json
   python3 skills/challenge-review/scripts/render-report.py \
     <run-dir>/review.json --output <run-dir>/review.md
   ```

   JSON is authoritative. Never hand-author a second Markdown report.

## Stage boundaries

- **Verifier:** run only the pinned `challenge-authoring` checker. It owns
  imports, Docker build and image-hash capture, mini orchestration, health,
  every declared flag store, and restart evidence.
- **Static:** inspect source only. Do not build, start services, invoke the
  verifier, mutate a deployment, or submit a flag.
- **Cheat:** act as an authorized adversary. Seek the cheapest arena-specific
  in-band shortcut and trivial defense before evaluating normal behavior.
- **Exploitability:** prove an attacker-visible, in-band path obtains and
  submits every current opponent flag and realizes its declared attack scope
  through any genuine vulnerability that is not specific to the arena
  environment.

Never use host Docker access, victim files or databases, facility secrets,
private handler state, or flag ground truth as attacker proof. Never launch
iterative hacker-fixer work from this skill; fortification belongs to a separate
future `challenge-fortify` skill.
