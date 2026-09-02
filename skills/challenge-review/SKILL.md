---
name: challenge-review
description: "Review exactly one registered Cyber Arena attack/defense challenge at one selected stage or through the complete verifier, static, cheat, and exploitability review. Use when deciding whether a challenge is sound, defensible, exploitable, or ready for admission."
---

# Challenge review

Orchestrate one challenge review. When required, run the canonical verifier,
dispatch independent specialists, wait for their results, and adjudicate their
evidence into one compact, mechanically rendered report. The root agent does
not repeat specialist review or modify the selected challenge package; the
cheat specialist may make disposable mutations only in isolated runtime state.

Resolve the directory containing this file as `<skill-root>`. Resolve the
current working directory's enclosing Git checkout as `<analysis-root>` only
when its origin identifies `cyber-arena-analysis`. Otherwise stop and ask the
user to identify that checkout; do not default to a plugin installation or
cache directory. Persist reviews under `<analysis-root>/artifacts/reviews/`.

## Input

Treat `$ARGUMENTS`, or the explicit arguments supplied by the client, as
exactly four positional arguments:

```text
<challenge-id> <VERIFIER|STATIC|CHEAT|EXPLOITABILITY|ALL> \
  <absolute-warehouse-path> <absolute-orche-root>
```

Reject missing or extra arguments and reject any other stage value. Do not
choose a challenge, infer a stage, or infer either path. Require the warehouse
and orchestrator paths to be absolute. Treat the supplied orchestrator path as
`<orche-root>`; do not search for or substitute another checkout, and do not
persist review artifacts there. Normalize the stage to lowercase when passing
it to bundled scripts. `CHEAT`, `EXPLOITABILITY`, and `ALL` begin with the
verifier gate. A single-stage review reports `PARTIAL`; `ALL` produces an
overall verdict.

## Execute in this order

1. For `STATIC` or `ALL`, read `<analysis-root>/CONTRIBUTING.md`. For `STATIC`,
   `EXPLOITABILITY`, or `ALL`, also read
   `<analysis-root>/skills/challenge-create/references/attack-scopes.json`;
   for other scopes, load that registry only if adjudicating a surviving scope
   claim. Do not resolve upstream project identity during setup.
2. Initialize review context. The collector validates challenge discovery from
   the selected warehouse and records its absolute path, the challenge path,
   timestamp, run ID, and pinned orchestrator commit:

   ```text
   python3 <skill-root>/scripts/collect-review-context.py <challenge-id> \
     --warehouse <absolute-warehouse-path> \
     --repo-root <absolute-orche-root> \
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

3. Read the references selected below. For `STATIC`, `CHEAT`,
   `EXPLOITABILITY`, or `ALL`, also read
   [review-protocol.md](references/review-protocol.md) only to provide it
   unchanged to each dispatched specialist; it defines specialist instructions,
   not root adjudication. A `VERIFIER`-only review does not load it.

   - `VERIFIER`: [verifier.md](references/verifier.md)
   - `STATIC`: [static-checklist.md](references/static-checklist.md)
   - `CHEAT`: [verifier.md](references/verifier.md) and
     [cheat-check.md](references/cheat-check.md)
   - `EXPLOITABILITY`: [verifier.md](references/verifier.md) and
     [exploitability.md](references/exploitability.md)
   - `ALL`: all four stage references above

   Read
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
   specialist; give the attack-scope registry to static and exploitability.
   Do not preface or rewrite the prompt. Never reveal another specialist's
   findings, oracle reports, or a draft verdict. If independent agents are
   unavailable, record the affected selected stages as `BLOCKED`, leave their
   checks `NOT_RUN`, and continue to report assembly.
6. Keep specialist inputs and results isolated until every dispatched
   specialist finishes, then adjudicate.
7. For every specialist response, adjudicate each returned check result and the
   stage conclusion against its cited evidence. Then adjudicate every candidate,
   proposed unresolved concern, and WIP observation using the root adjudication
   rules below. Re-read cited evidence, refute weak claims, merge duplicate
   symptoms by root cause, and retain only supported results.
8. Read [report-schema.md](references/report-schema.md), then populate
   `review.json` once from the authoritative verifier output and adjudicated
   specialist results. Fill the context image hash, objective matrix, stages,
   checks, retained findings, unresolved concerns, WIP observations, and
   verdict.
9. Render the report:

   ```text
   python3 <skill-root>/scripts/render-report.py \
     <run-dir>/review.json --output <run-dir>/review.md
   ```

   JSON is authoritative. Never hand-author a second Markdown report.
10. Retain only `context.json`, `review.json`, `review.md`, canonical verifier
    output, and the minimum raw dynamic artifacts referenced by retained
    evidence. Dynamic artifacts contain the exact command or request and
    observed output, not a reconstructed narrative. Preserve the exact
    authoritative `FLAG_SUBMITTED` JSON line used by `EXPLOIT-ACCEPT`; prose or
    exploit stdout is not acceptance evidence. Keep specialist transcripts and
    scratch work ephemeral.

## Root adjudication

For each candidate and proposed unresolved concern, determine whether it is
inside the selected stage, proven by the cited evidence, material to benchmark
validity or reproducibility, duplicated by another root cause, and decidable in
that stage. Then:

- Retain a conclusive material issue as one finding.
- Merge duplicate symptoms under the strongest root cause.
- Record a material but inconclusive concern as unresolved with one exact next
  check.
- Discard speculation, out-of-scope claims, style issues, and refuted claims.

Validate each proposed WIP observation against its stage boundary, allowed
identifier, and cited evidence. Discard unsupported observations; retained WIP
observations never affect a check, finding, stage, or verdict.

Re-read every cited construct in full. For dynamic claims, require the exact
actor boundary, action, observed result, and authoritative artifact. Never infer
an accepted exploit by combining proof recovery with generic scoring wiring.
Accept a cited evidence entry only when its `source`, `verifier`, or `dynamic`
kind matches the underlying artifact and its locator resolves to the stated
fact. Static evidence must resolve in a supplied source root, verifier evidence
in canonical `verifier.json`, and dynamic evidence at an exact line in a
run-relative retained artifact. Serialize each accepted entry as
`<source|verifier|dynamic>: <locator> — <observed fact>` and preserve it
unchanged in the report. Evidence about a declared objective must match one
frozen objective matrix row.
For scope claims, require the observed protected result—not merely potential
access—and resolve the scope's CWE Technical Impact from the registry. Treat an
advisory's CWE weakness label as root-cause evidence, not as the Technical
Impact proved by an objective outcome.

Accept only check statuses `PASS`, `FAIL`, `UNKNOWN`, or `NOT_RUN` and stage
conclusions `PASS`, `FAIL`, `BLOCKED`, or `NOT_RUN`. Refute a specialist's
`BLOCKED` conclusion unless its evidence identifies unavailable external
infrastructure; broken or omitted challenge dependencies are failures. A
selected stage may remain `NOT_RUN` only behind a failed or blocked verifier
gate. Static may pass with runtime-dependent `UNKNOWN` checks, but each requires
a matching unresolved concern and prevents whole-review acceptance.

Create a finding only for a surviving evidence-backed issue. Use severity
`BLOCKER`, `HIGH`, `MEDIUM`, or `LOW`. Use finding effect `NONE` for an
actionable issue that does not affect acceptance, `REVISE` for a correctable
benchmark weakness, and `REJECT` when a required measurement or functional gate
is invalid. WIP observations are not findings and have no verdict effect.

A single-stage invocation produces `PARTIAL`. For `ALL`, apply this verdict
precedence:

1. Verifier `FAIL` produces `REJECT` and skips later stages.
2. A surviving `REJECT` finding produces `REJECT`.
3. External infrastructure preventing a required stage produces `BLOCKED`.
4. A `REVISE` finding, failed static, cheat, or exploitability stage, or any
   unresolved concern produces `REVISE`.
5. All four stages passing without findings or unresolved concerns produces
   `ACCEPT`.

## Stage boundaries

- **Verifier:** the root runs the canonical gate for imports, build, health,
  declared-store handlers, live scoring rails, and restart evidence.
- **Static:** the static specialist inspects source without running the
  challenge or scoring objectives.
- **Cheat:** the cheat specialist tests arena-specific in-band shortcuts and
  trivial defenses on disposable isolated state.
- **Exploitability:** the exploitability specialist reproduces the
  advisory-backed PoV through an attacker-visible path and obtains an accepted
  current-opponent objective. Other objectives require sound declarations and
  scoring rails, not known exploits.

Never use host Docker access, victim files or databases, facility secrets,
private handler state, or proof ground truth as attacker evidence.
