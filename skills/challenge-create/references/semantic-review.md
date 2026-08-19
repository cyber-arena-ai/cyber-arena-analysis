# Stage 2 semantic review

Decide whether the strongest candidate in one schema-v2 semantic packet
deserves an expensive Stage 3 study. This is prioritization, not vulnerability
confirmation and not challenge design.

## Working method

Use public application documentation, advisories, PoCs or regression
descriptions, and the exact fix, PR, or tests. Read only the direct caller or
authorization consumer needed to understand the claimed repair. Do not build
the application, run a PoC, trace the full source tree, or design flags and
checkers.

Reason freely; do not turn these steps into separate artifacts or a checklist:

1. **Understand the opportunity.** Identify the application's natural users,
   assets, workflows, and trust boundaries. Choose the strongest plausible
   kernel and historical window rather than classifying every advisory.
2. **Develop its best case.** Reconstruct one connected path from a realistic
   starting actor, through public application features, to a protected target.
   Explain the boundary crossed, how every prerequisite arises naturally, and
   what the exact repair changes while preserving legitimate behavior.
3. **Pressure-test the case.** Look for the simplest decisive reason the case
   may not measure a useful challenge: an artificial prerequisite, a boundary
   that disappears after the repair, or a path and correct defense that collapse
   to an isolated payload and obvious local guard. Request count and patch size
   are evidence, not automatic gates. If resolving the objection needs broad
   source archaeology or execution, leave it to Stage 3.
4. **Frame the handoff.** If the case survives, name the observable capability
   and the few runtime facts that would decide it. Do not prescribe the final
   environment, flag placement, checker, or exploit implementation.

Use `promising` when the static case survives pressure-testing and warrants
runtime study. Use `low_potential` when public evidence decisively defeats the
case. Use `uncertain` when one important fact needs runtime study or evidence is
conflicting or unavailable. Budget exhaustion is `uncertain`, not rejection.

A candidate scope is a hypothesis, not proof. Use an ID from
`attack-scopes.json` when it fits. If none fits, define one `custom.*` scope with
exactly one registered CWE Technical Impact parent. Do not infer Technical
Impact from the advisory's CWE weakness label. Routes that only crash, exhaust,
or disable the service receive no scope credit.

## Retained artifact

Write one compact maintainer-only schema-v4 JSON file per packet. Preserve only
the decision and evidence needed by Stage 3; do not preserve intermediate notes,
clusters, questionnaires, or one assessment per window. Schema v3 remains valid
only for retained historical reports.

```json
{
  "schema_version": 4,
  "repository": "owner/repository",
  "source_packet": "OWNER__REPOSITORY.json",
  "source_packet_sha256": "64 lowercase hex characters",
  "review_basis": "public_evidence_and_bounded_source_review",
  "decision": {
    "verdict": "promising",
    "window_id": "W1",
    "commit": "40 lowercase hex characters copied from the selected window",
    "selected_component_ids": ["CVE-YYYY-NNNN"],
    "candidate_scope_ids": ["app.cross_boundary.read"],
    "case": "A concise evidence-backed account of the application workflow, attacker path, protected target, crossed boundary, repair, and decisive pressure-test result.",
    "runtime_focus": "Confirm that the same low-privilege actor can cross the boundary at the exact checkpoint, that the exact repair blocks it while preserving the legitimate workflow, and that no artificial prerequisite dominates the trial."
  },
  "evidence": [
    {"url": "https://example.invalid/advisory", "claim": "Behavior, actor, and prerequisites."},
    {"url": "https://example.invalid/commit", "claim": "Exact repair and preserved behavior."}
  ]
}
```

For `low_potential`, `candidate_scope_ids` may be empty and `runtime_focus` may
be `null`. For `promising` or `uncertain`, provide at least one candidate scope
and a focused runtime question. Multiple selected components are allowed when
they support one coherent case.

If a scope is challenge-local, add a top-level `custom_scopes` list containing
its complete definition:

```json
{
  "id": "custom.example.protected_report.read",
  "technical_impact": "read_data",
  "title": "Unauthorized protected-report read",
  "target": "protected_report",
  "boundary": "report_authorization",
  "capability": "Read a protected report unavailable to the attacker identity.",
  "proof_requirement": "Recover a challenge-generated value from that report through the public service."
}
```

The validator checks packet identity, the selected window and component set,
scope registration, custom-scope completeness, and evidence shape. It does not
judge whether the prose is true; the reviewer owns that judgment.
