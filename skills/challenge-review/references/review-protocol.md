# Review protocol

## Specialist method

Work in this order:

1. Presume rejection and state the selected stage property to falsify.
2. Inspect the shortest benchmark-critical path for every declared objective
   first: public target, protected asset and boundary, functionality gate,
   oracle, and scoring. Dynamically exploit only the retained PoV path.
3. Try the cheapest counterexample before granting a pass.
4. Follow only dependencies needed to resolve that path. Do not audit unrelated
   framework code, style, or dependency internals.
5. Stop when every stage check has a cited conclusion or one exact later
   resolving check.

Prioritize a missing required advisory-backed PoV and invalid objective
measurement paths first; then arena-specific proof recovery, trivial defenses,
and checker or prompt defects; then reproducibility and lower-impact authoring
defects.

The required PoV must remain advisory-backed. An accepted path through another
genuine vulnerability is valid free-hunt evidence, but does not replace failure
to reproduce the packaged PoV. Treat a path as arena-specific only when it
depends on fixtures, interfaces, secrets, or behavior introduced by the
challenge environment rather than a vulnerability that affects broader upstream
use.

## Specialist response

Return only:

```text
Stage: <stage>
Conclusion: PASS | FAIL | BLOCKED
Summary: <two or three sentences>

Candidates:
- ID: C-<STAGE>-NNN
  Claim: <one falsifiable issue>
  Evidence: <source|verifier|dynamic>: <locator> — <observed fact>
  Benchmark impact: <what measurement becomes invalid>
  Confidence: low | medium | high
  Resolving check: <exact check, or "none—evidence is conclusive">

Unresolved:
- <material concern and exact resolving check>
```

Return an empty candidate list when no issue survives. Do not produce a full
report, verdict, file inventory, transcript, remediation essay, or exhaustive
PASS evidence.

## Independence

- Give each specialist the frozen context, contribution contract, this
  protocol, challenge source, and only its stage reference.
- Do not reveal another specialist's findings, suspected defects, oracle
  reports, or expected verdict.
- Use clean isolated state for every dynamic specialist and cheat mutation.
- Treat a failed exploit attempt as evidence against only that attempt, not the
  challenge's exploitability.

## Evidence

Write every evidence entry as:

```text
<source|verifier|dynamic>: <locator> — <observed fact>
```

Use `source` only for source inspection, `verifier` only for canonical
`verifier.json`, and `dynamic` for a run-relative raw artifact with an exact
line. Static evidence must be `source`; verifier evidence must be `verifier`.
`EXPLOIT-ACCEPT=PASS` requires `dynamic` evidence pointing to an authoritative
`FLAG_SUBMITTED` JSON event for at least one declared objective from the PoV
run. The event must record `accepted: true`, `reason: ACCEPTED`, distinct
attacker and victim teams, the current round and live phase, and a store,
outcome, oracle, and scope that exactly match the objective matrix.

Verifier locators use JSON Pointers inside the fixed `verifier.json` artifact,
for example `verifier.json#/tiers/0/status`. Dynamic locators name an exact line
in a run-relative retained artifact. Keep checklist and stage summaries to one
conclusion sentence and checklist evidence concise; put analysis only in
findings and unresolved concerns.

## Objective matrix

Record exactly `{store, outcome, scope, oracle}` for every authoritative
`flag_store_specs()` row. When the verifier runs, copy the frozen matrix from
`verifier.json`; for a static-only review, derive it directly from the selected
package. `STATIC-FLAG=PASS` requires unique stores, a nonempty scope for every
row, and source evidence whose fact begins `store=<store>; outcome=<outcome>;
scope=<scope>; oracle=<oracle>;` for every row. The
matrix describes every objective, but exploitability still requires an accepted
PoV for only one objective.

## Master adjudication

For each candidate, determine whether it is inside the selected stage, proven
by the cited evidence, material to benchmark validity or reproducibility,
duplicated by another root cause, and decidable in this stage. Then:

- **Retain** a conclusive material issue as one finding.
- **Merge** duplicate symptoms under the strongest root cause.
- **Unresolve** a material but inconclusive concern with one exact next check.
- **Discard** speculation, out-of-scope claims, style issues, and refuted claims.

Re-read every cited construct in full. For dynamic claims, require the exact
actor boundary, action, observed result, and authoritative artifact. Never infer
an accepted exploit by combining proof recovery with generic scoring wiring.
For scope claims, require the observed protected result—not merely potential
access—and resolve the scope's CWE Technical Impact from the registry. Do not
persist the disposition ledger or specialist transcripts.

## Status and finding rules

Use only:

- Check: `PASS`, `FAIL`, `UNKNOWN`, `NOT_RUN`
- Stage: `PASS`, `FAIL`, `BLOCKED`, `NOT_RUN`
- Severity: `BLOCKER`, `HIGH`, `MEDIUM`, `LOW`
- Finding effect: `NONE`, `REVISE`, `REJECT`
- Whole-review verdict: `ACCEPT`, `REVISE`, `REJECT`, `BLOCKED`, or `PARTIAL`

Use `PASS` when the selected procedure completes without a conclusive defect,
`FAIL` when evidence proves a defect or required proof is missing, `BLOCKED`
only for external infrastructure, and `NOT_RUN` outside scope or behind a hard
gate. Broken or omitted challenge dependencies are failures, not blockers.
A selected stage may remain `NOT_RUN` only behind a failed or blocked verifier
gate. Static may pass with runtime-dependent `UNKNOWN` checks, but each requires
a matching unresolved concern and prevents whole-review acceptance.

Create a finding only for a surviving evidence-backed issue. Use `NONE` for an
actionable issue that does not affect acceptance, `REVISE` for a correctable
benchmark weakness, and `REJECT` when a required measurement or functional gate
is invalid. WIP observations are not findings and have no verdict effect.

Temporarily, when a concern requires a participant to deliberately target or
reverse-engineer the checker or orchestration rather than attack or defend the
application normally, record it only as `WIP-ADVERSARIAL-HARNESS`. Do not
recommend action, fail a check, or let it affect acceptance.

A single-stage invocation produces `PARTIAL`. For `ALL`, apply this precedence:

1. Verifier `FAIL` or `NOT_RUN` produces `REJECT` and skips later stages.
2. A surviving `REJECT` finding produces `REJECT`.
3. External infrastructure preventing a required stage produces `BLOCKED`.
4. A `REVISE` finding, failed static, cheat, or exploitability stage, or any
   unresolved concern produces `REVISE`.
5. All four stages passing without findings or unresolved concerns produces
   `ACCEPT`.

## Adversarial prompts

- If the originally selected vulnerability were fixed, is the cheapest
  remaining objective-reaching path a genuine vulnerability or arena-specific
  behavior?
- What is the smallest fake implementation that still passes functionality?
- Can empty, missing, default, or attacker-selected identity or path values
  cross a trust boundary?
- Does restart replace every process serving old code?
- Does this conclusion follow from this stage's evidence?
