# Budgeted semantic-review protocol

Use this protocol on one schema-v2 semantic packet. The result prioritizes
scenario potential from public evidence; it does not prove exploitability or
AwD quality.

## Evidence and cost boundary

Use application documentation, advisory text, public PoC or regression
descriptions, fix/PR context, and minimal patch summaries. Do not build the
application, inspect the full source tree, execute a PoC, claim path
independence, or prescribe a final challenge baseline.

Review in this order:

1. Hash the packet and build one application profile.
2. Stop if it is not a real self-hosted network application with natural
   identities, state, roles, or trust boundaries.
3. Cluster all selected components using cheap metadata: entry surface,
   affected subsystem, root-cause/CWE hint, starting privilege, repair area,
   and likely capability.
4. Review representative components under a fixed advisory budget. Reuse an
   assessment across every window containing that component.
5. Stop when each window has enough evidence for a scenario and scope
   hypothesis. Exhaustive advisory classification is not required.

Unavailable or conflicting evidence creates uncertainty. Budget exhaustion is
`uncertain`, not rejection.

## Status and scope rules

Use `promising`, `uncertain`, or `low_potential`. Only an application mismatch
or failed programmatic hard gate is a permanent exclusion.

A scope hypothesis is plausible only when the application naturally contains
the target, public evidence establishes a connected primitive, the attacker
role and deployment are realistic, and no missing step is invented. Map only
positive outcomes in `docs/attack_scopes.json`. A route requiring crash, DoS,
resource exhaustion, health failure, or control-plane access is `disallowed`
and receives no scope credit.

The registry's CWE Technical Impact is the coarse consequence; the attack scope
is its concrete, flaggable refinement. Do not infer Technical Impact from an
advisory's CWE weakness label. Use a registered scope when it fits. Otherwise
use `custom.<challenge_id>.*` and add a `custom_scope` object containing `id`,
`technical_impact`, `title`, `target`, `boundary`, `capability`, and
`proof_requirement`. Omit `custom_scope` for registered scopes.

For every proposed scope record the attacker start, public feature, protected
target, crossed boundary, evidence, witness hypothesis, assumptions, and exact
implementation checks. For example, SSRF does not imply arbitrary read unless
evidence supports response disclosure or access to a protected resource.

## Review artifact

Write one maintainer-only JSON file per packet:

```json
{
  "schema_version": 3,
  "repository": "owner/repository",
  "source_packet": "OWNER__REPOSITORY.json",
  "source_packet_sha256": "64 lowercase hex characters",
  "review_basis": "public_evidence_only",
  "dynamic_testing_performed": false,
  "application": {
    "status": "promising",
    "self_hosted_network_app": "yes",
    "natural_security_boundary": "yes",
    "deployment_model": "How the network application is normally deployed.",
    "public_surfaces": ["Network feature available to the attacker."],
    "identities": ["Natural low-privilege identity."],
    "protected_assets": ["Application-owned protected asset."],
    "legitimate_workflows": ["Workflow defenders must preserve."],
    "rationale": "Evidence-backed application-fit judgment.",
    "evidence": [
      {"type": "upstream", "url": "https://example.invalid/docs", "claim": "What the source establishes."}
    ],
    "uncertainties": []
  },
  "clusters": [
    {
      "cluster_id": "C1",
      "component_ids": ["CVE-YYYY-NNNN"],
      "entry_surface": "Likely public surface.",
      "affected_component": "Affected subsystem.",
      "starting_privilege": "Likely attacker role.",
      "likely_capabilities": ["Unauthorized application read"],
      "rationale": "Why these records can share a representative review."
    }
  ],
  "advisory_assessments": [
    {
      "component_id": "CVE-YYYY-NNNN",
      "cluster_id": "C1",
      "status": "promising",
      "attacker_start": "Authenticated low-privilege user.",
      "public_feature": "Normal object-read API.",
      "protected_target": "Another tenant's object.",
      "security_boundary": "Tenant ownership boundary.",
      "primitive_hypothesis": "The advisory reports an ownership-check bypass.",
      "candidate_scopes": [
        {
          "scope_id": "app.cross_boundary.read",
          "confidence": "plausible",
          "capability_hypothesis": "The bypass may disclose a planted protected object.",
          "witness_hypothesis": "Rotate an object and flag under another tenant.",
          "required_effects": ["Read the protected object through the public API."],
          "policy_result": "eligible",
          "assumptions": ["The API is enabled in the proposed deployment."],
          "deferred_checks": ["Confirm the exact checkpoint exposes the endpoint."]
        }
      ],
      "evidence": [
        {"type": "advisory", "url": "https://example.invalid/advisory", "claim": "Behavior and prerequisites."},
        {"type": "fix", "url": "https://example.invalid/commit", "claim": "Repair boundary."}
      ],
      "uncertainties": []
    }
  ],
  "windows": [
    {
      "window_id": "W1",
      "commit": "40 lowercase hex characters copied from the source window",
      "component_ids": ["CVE-YYYY-NNNN"],
      "status": "promising",
      "representative_component_ids": ["CVE-YYYY-NNNN"],
      "scenario_hypothesis": "One coherent attacker role, surface, target, and boundary.",
      "candidate_scope_ids": ["app.cross_boundary.read"],
      "rationale": "Why this window merits implementation-first validation.",
      "assumptions": [],
      "deferred_checks": ["Build and reproduce at the exact checkpoint."]
    }
  ],
  "review_budget": {
    "maximum_advisory_assessments": 3,
    "reviewed_advisory_assessments": 1,
    "early_stop_reason": "The reviewed representative characterizes the selected windows."
  },
  "status": "promising",
  "rationale": "Overall application prioritization."
}
```

For a challenge-local scope, the candidate entry instead includes its compact
definition:

```json
{
  "scope_id": "custom.example.protected_report.read",
  "custom_scope": {
    "id": "custom.example.protected_report.read",
    "technical_impact": "read_data",
    "title": "Unauthorized protected-report read",
    "target": "protected_report",
    "boundary": "report_authorization",
    "capability": "Read a protected report unavailable to the attacker identity.",
    "proof_requirement": "Recover a challenge-generated value from that report through the public service."
  }
}
```

Clusters must cover all components selected into the packet exactly once.
Assessments may cover only representatives. Window results must cover every
candidate window, repeat its exact commit and complete component set, and may
cite only assessed components active in that window.
The overall status is `promising` if any window is promising, otherwise
`uncertain` if any is uncertain, otherwise `low_potential`.
