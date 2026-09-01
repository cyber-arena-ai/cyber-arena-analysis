# Review protocol

## Specialist method

Follow only dependencies needed to resolve the selected stage. Do not audit
unrelated framework code, style, or dependency internals. Resolve every selected
check with a cited conclusion or one exact later resolving check.

The required PoV must remain advisory-backed. An accepted path through another
genuine vulnerability is valid free-hunt evidence, but does not replace failure
to reproduce the packaged PoV. Treat a path as arena-specific only when its
boundary-crossing mechanism depends on fixtures, interfaces, secrets, or
behavior introduced by the challenge environment rather than a vulnerability
that affects broader upstream use.

## Specialist response

Return only:

```text
Stage: <stage>
Conclusion: PASS | FAIL | BLOCKED
Summary: <two or three sentences>

Checks:
- ID: <selected check ID>
  Status: PASS | FAIL | UNKNOWN | NOT_RUN
  Summary: <one conclusion sentence>
  Evidence:
    - <source|verifier|dynamic>: <locator> — <observed fact>
  Next check: <exact check for UNKNOWN, otherwise "none">

Candidates:
- ID: C-<STAGE>-NNN
  Claim: <one falsifiable issue>
  Evidence:
    - <source|verifier|dynamic>: <locator> — <observed fact>
  Benchmark impact: <effect on benchmark validity or reproducibility>

Unresolved:
- Check: <selected check ID>
  Concern: <material undecided property>
  Evidence:
    - <source|verifier|dynamic>: <locator> — <observed fact>
  Resolving check: <one exact check>
  Owner stage: <stage that can perform the check>

WIP observations:
- ID: <allowed WIP identifier>
  Note: <concise non-enforcing observation>
  Evidence:
    - <source|verifier|dynamic>: <locator> — <observed fact>
```

Return one result for every selected check. Evidence may contain multiple
entries and may be empty only for `NOT_RUN`; only `UNKNOWN` defines a next
check. Every unresolved entry must name an `UNKNOWN` check in the same stage and
repeat its exact next check. Return empty candidate, unresolved, and WIP lists
when none survive. Candidates are conclusive issue claims; use unresolved for
material uncertainty. Do not produce a full report, verdict, transcript,
remediation essay, or verbose PASS narrative.

## Evidence

Write every evidence entry as:

```text
<source|verifier|dynamic>: <locator> — <observed fact>
```

Use `source` only for source inspection, `verifier` only for canonical
`verifier.json`, and `dynamic` for a run-relative raw artifact with an exact
line. Static evidence must be `source`; verifier evidence must be `verifier`.
Source locators name a supplied source root and a root-relative path plus a line
number or symbol, for example
`warehouse:owner/challenge/challenge.py::Challenge.flag_store_specs` or
`analysis:skills/challenge-create/references/attack-scopes.json:12`.

Verifier locators use JSON Pointers inside the fixed `verifier.json` artifact,
for example `verifier.json#/tiers/0/status`. Dynamic locators name an exact line
in a run-relative retained artifact. A failed dynamic attempt is evidence
against only that attempt, not the challenge's exploitability or the absence of
other shortcuts.

## Objective matrix

The objective matrix is the authoritative set of
`{store, outcome, scope, oracle}` declarations for the review. Evidence about a
declared objective must match one matrix row; stage references define how the
matrix is obtained and used.

## Root adjudication

For each candidate and proposed unresolved concern, determine whether it is
inside the selected stage, proven by the cited evidence, material to benchmark
validity or reproducibility, duplicated by another root cause, and decidable in
this stage. Then:

- **Retain** a conclusive material issue as one finding.
- **Merge** duplicate symptoms under the strongest root cause.
- **Record as unresolved** a material but inconclusive concern with one exact
  next check.
- **Discard** speculation, out-of-scope claims, style issues, and refuted claims.

Validate each proposed WIP observation against its stage boundary, allowed
identifier, and cited evidence. Discard unsupported observations; retained WIP
observations never affect a check, finding, stage, or verdict.

Re-read every cited construct in full. For dynamic claims, require the exact
actor boundary, action, observed result, and authoritative artifact. Never infer
an accepted exploit by combining proof recovery with generic scoring wiring.
For scope claims, require the observed protected result—not merely potential
access—and resolve the scope's CWE Technical Impact from the registry. Treat an
advisory's CWE weakness label as root-cause evidence, not as the Technical
Impact proved by an objective outcome.

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

A single-stage invocation produces `PARTIAL`. For `ALL`, apply this precedence:

1. Verifier `FAIL` produces `REJECT` and skips later stages.
2. A surviving `REJECT` finding produces `REJECT`.
3. External infrastructure preventing a required stage produces `BLOCKED`.
4. A `REVISE` finding, failed static, cheat, or exploitability stage, or any
   unresolved concern produces `REVISE`.
5. All four stages passing without findings or unresolved concerns produces
   `ACCEPT`.
