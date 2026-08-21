# Stage 2 semantic review

Decide whether the strongest candidate in one schema-v2 semantic packet
deserves an expensive Stage 3 study. This is prioritization, not vulnerability
confirmation or full challenge design.

Require one evidence-backed attack chain and repair; do not require a second
route, a post-fix survivor, an intermediate release, a multi-advisory ladder,
or a minimum patch size.

## Working method

Use primary upstream evidence without executing the vulnerable application.
Clone or download exact source, patches, tests, advisories, and documentation
when useful; retain the small evidence extracts that support the decision.
Collection may be broad enough to resolve provenance, but analysis stays
focused on the selected chain, its direct consumers, repair, and operability.
Builds, deployments, PoC execution, and flag or checker design belong to later
stages.

Gather only the evidence needed for three connected judgments. Stop when
upstream evidence decisively defeats the case; only a `promising` decision must
complete all three:

1. **Complete case.** Use an upstream advisory, PoC or regression description,
   exact-revision authentication, authorization, and consumer source, and
   official workflow documentation to connect distinct baseline principals, a
   supported operation, attacker-controlled input, real consumer, crossed
   application boundary, and protected outcome. When the witness needs
   proof-bearing application state, identify the supported application
   operation that can create or update that state and a public locator that is
   not itself a credential. Use the exact patch, PR, tests, and release evidence
   to explain the repair and preserved legitimate behavior. Every essential
   hop and prerequisite needs affirmative evidence; an advisory claim without
   its consumer, account model, or asset lifecycle is incomplete.
2. **Strongest objection.** Try to defeat that case with the simplest material
   objection supported by upstream evidence: no distinct equal-privilege
   application principals, baseline-equivalent privilege, an
   infrastructure-planted or victim-supplied prerequisite, a locator that is a
   credential, a direct public shortcut, or a boundary invented by the proposed
   deployment. Do not enumerate hypothetical objections or require proof of a
   second route. Request count, patch size, locality, and apparent defensive
   depth are observations, never gates.
3. **Operability.** Use official install and build documentation to establish a
   supported self-hosting shape, essential services, special privileges or
   infrastructure, editable source availability, persistent state, and a
   supported restart or reload path. Kubernetes, host Docker, privileged
   nesting, multiple machines, or another essential unsupported facility are
   decisive when no ordinary supported alternative exists. Exact cold-start and
   rebuild timings remain Stage 3 measurements only after the documented shape
   is compatible.

These are reasoning prompts, not independent forms. Preserve the conclusion,
not a completed checklist. Use `promising` only when all three judgments have
affirmative upstream support and Stage 3 only needs to confirm or measure the
case. Use `uncertain` when an essential fact is unsupported, conflicting, or
unavailable; do not advance it until Stage 2 evidence resolves that fact. Use
`low_potential` when upstream evidence defeats the case. Budget exhaustion is
`uncertain`, not rejection.

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
    "case": "A concise evidence-backed account of the complete application path and repair, followed by the strongest material objection and why the case survives it.",
    "next_focus": "Confirm the already-supported path and repaired behavior live; do not use Stage 3 to discover a missing consumer, principal, asset, prerequisite, or deployment foundation.",
    "operability": {
      "risk": "low",
      "deployment": "Official single-service container with local persistent storage."
    }
  },
  "evidence": [
    {"kind": "attack_chain", "url": "https://example.invalid/advisory", "observed_at": "2026-08-21T00:00:00Z", "artifact": "evidence/advisory.txt", "sha256": "64 lowercase hex characters", "claim": "PoC or behavioral evidence establishes the actor, operations, and outcome."},
    {"kind": "repair", "url": "https://example.invalid/commit", "observed_at": "2026-08-21T00:00:00Z", "artifact": "evidence/repair.patch", "sha256": "64 lowercase hex characters", "claim": "Exact repair and preserved behavior."},
    {"kind": "operability", "url": "https://example.invalid/install", "observed_at": "2026-08-21T00:00:00Z", "artifact": "evidence/install.txt", "sha256": "64 lowercase hex characters", "claim": "Official deployment and build documentation establishes a compatible self-hosting shape and editable restart path."}
  ]
}
```

For `low_potential`, `candidate_scope_ids` may be empty and `next_focus` must be
`null`. For `promising`, `next_focus` names the decisive Stage 3 confirmation or
measurement. For `uncertain`, it names the missing upstream evidence that must
be gathered before advancing. Both require at least one candidate scope. A
`promising` decision requires retained `attack_chain`, `repair`, and
`operability` evidence. For `uncertain` and `low_potential`, `operability` may
be `null` when an earlier evidence gap or decisive objection stops the review;
preserve whatever evidence is available without pretending the missing kind
was established. Replace each example `observed_at` value with the actual
collection time.

`attack_chain` may retain a public PoC, upstream regression, or precise
behavioral reproduction description; semantic triage does not require
inventing a second route. Multiple selected components are allowed when they
support one coherent case. Evidence artifacts are small, maintainer-only
retained extracts or patches stored beside the review; they make the claim
resumable when a mutable page changes.

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
