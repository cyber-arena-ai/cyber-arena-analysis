# Challenge autocuration design

## Purpose

The autocuration pipeline turns public vulnerability evidence into focused,
runnable CyberArena challenges for frontier agents. A challenge is not a CVE
quiz and does not require an agent to reproduce an upstream patch. It is a free
hunt inside an exact historical application: the flag target steers the hunt,
and a successful score proves that the agent reached a meaningful security
capability.

The pipeline must preserve this character while avoiding two common failures:

- a challenge measures an arbitrary flag placement rather than the advertised
  capability; or
- an obvious feature-amputating or checker-specific defense is easier than
  understanding and repairing the vulnerability.

The target is a repeatable, evidence-backed authoring process that removes
obvious shortcuts. It is not perfect anti-cheat protection, an exhaustive audit
of an application, or a long checklist that substitutes format for technical
understanding.

## Design principles

**Flags prove capabilities, not vulnerabilities.** Advisories and commits
identify promising historical behavior. Scoring is tied to an observed outcome
such as a protected read, cross-boundary write, privileged action, or command
execution.

**The attack chain is the authoring contract.** Stage 3 traces the selected
identity and public entrypoint through the application features, vulnerable
transition, protected boundary, and observable outcome. Stage 4 may refine this
model with evidence, but must not silently choose a different vulnerability,
identity, or flag objective.

**Legitimate behavior survives; vulnerable behavior does not.** The checker
exercises legitimate features on the attack chain. It must not require the
vulnerability to remain exploitable, because a valid defense is expected to
close that transition.

**Overlaps are evidence, not noise.** The benchmark is a free hunt, so several
vulnerabilities may coexist at a selected revision. The pipeline records their
overlap and records additional genuine in-band paths to the scored capability.
Their presence is not a rejection condition and agents may score through any of
them. A distinct capability or identity may justify a separate challenge.

**Runtime claims require runtime evidence.** Advisory prose, source diffs, and
upstream tests select experiments; they do not prove exploitability, scenario
fit, or a sound flag witness.

## Pipeline

### Stage 1: evidence-backed discovery

Snapshot vulnerability sources with immutable provenance, verify their hashes,
join aliases, remove withdrawn records, and retain behavioral and repair
evidence. OSV remains the primary source because its Git ranges map naturally to
historical source windows. Other databases can enrich provenance and review
quality without silently changing affected ranges.

This stage ranks research opportunities. CVSS, CWE, advisory popularity, and
source-database presence may guide review order but are not admission gates.

### Stage 2: historical-window and semantic review

Resolve repository identities, affected Git ranges, repair boundaries, and
disjoint historical windows. A semantic review then identifies plausible
attacker identities, public features, capability scopes, and runtime questions.

The output is a source-linked hypothesis, not a challenge specification. It
must preserve overlaps between vulnerabilities because those overlaps may later
explain alternative scoring paths or unintended defenses.

### Stage 3: runnable challenge-kernel study

Stage 3 selects one historical window and establishes four facts in a disposable
environment:

1. The exact revision resolves, builds, and starts.
2. The selected vulnerability reproduces through the declared public interface;
   a fixed revision or equivalent narrow change blocks the same probe.
3. The complete attack chain and the legitimate features it depends on are
   understood.
4. A natural trial witness proves a registered capability, without an obvious
   non-vulnerability shortcut to the same result.

The fixed comparison establishes causality. It does not require challenge
agents to implement the upstream fix.

The central deliverable is a concise **attack-chain contract**:

```text
attacker identity
-> public entrypoint
-> authentication and permissions
-> required application features
-> vulnerable transition
-> protected boundary or action
-> independently observable capability proof
```

The study identifies three kinds of elements in that chain:

- **preserve** — legitimate behavior the authored checker must exercise;
- **close** — the vulnerable transition a defense should block; and
- **observe** — protected state, receipt, or output that proves the capability.

This is a causal explanation, not a requirement to create a checker leaf for
every node. One well-designed end-to-end witness should cover several features
when that better represents real use.

Stage 3 also performs a bounded alternate-path study around the proposed
identity and flag target. It looks for default or shared credentials, public
debug and backup routes, simpler reads or writes, and overlapping vulnerabilities
that reach the same proof. It does not claim that every vulnerability in the
application has been found.

### Stage 4: contract-driven challenge authoring

Stage 4 implements the real challenge from the Stage 3 contract. Its work
includes the exact application environment, attacker identity, flag or action
witness, start and restart behavior, intended exploit, external functionality
checker, and a narrow-defense comparison.

The authored result must demonstrate three coherent executions:

- the baseline exploit reaches the current capability proof;
- a narrow semantic defense blocks that exploit while the legitimate feature
  witness remains healthy; and
- obvious shortcut defenses fail, including disabling a required feature,
  rejecting the published identity, returning canned data, or matching only the
  known exploit string.

Feature-cut and shortcut mutations are experimental tools used to challenge the
author's understanding. They are not a checklist to ship with every challenge.
Their purpose is to show that cutting any preserved part of the chain turns the
checker red, while closing only the vulnerable transition leaves it green.

Completed packages then enter independent static, runtime, exploitability, and
adversarial review in the orchestration repository.

## Capability proofs and tiers

The [global attack-scope registry](ATTACK_SCOPE_REGISTRY.md) defines what a flag
means. Scope describes the demonstrated effect and crossed boundary; tier gives
only a coarse ordering of capability strength. Tiers should remain few and
interpretable rather than mimic fine-grained CVSS severity.

| Capability | Suitable proof |
| --- | --- |
| Protected read | Recover an unpredictable value stored as natural protected application data. |
| Cross-boundary write | Place a fresh action nonce into protected state; the scorer independently confirms the mutation. |
| Privileged control | Cause the protected action to emit a nonce-bound receipt or state transition. |
| Command execution | Recover a runtime value available only from the executed process or authority. |

A proof is sound only when successful scoring implies that the claimed
capability occurred. Merely submitting a public action nonce does not prove a
write; the scorer must observe the protected mutation. Likewise, reading an
arbitrary file planted beside a service does not prove application-level access
unless the flag location follows naturally from the claimed boundary.

Every capability proof has an authorized baseline and an unauthorized attacker
baseline. The value and relevant context rotate per team and round. Planting
must not create the vulnerable path, weaken application permissions, or encode a
CVE-specific hint. A stronger tier is awarded only when the stronger capability
is exercised, not because it could hypothetically follow from a weaker result.

## Checker and flag invariants

The checker is the executable form of the preserved side of the attack-chain
contract. It exercises ordinary public routes with the same class of identity
and behavior that legitimate use requires. It uses fresh state provisioned
independently into the active service, then verifies that state through the
public feature path. This prevents a canned responder or stale reference
instance from satisfying the checker without preserving application behavior.

Checker inputs, expression shapes, request envelopes, and timing should not form
an obvious fixed signature. Polling is jittered, manual checks are rate-limited,
and agent-visible results are coarse; detailed diagnostics remain in operator
artifacts. The authoritative checker runs outside the defender-controlled
service. An in-container helper may provision state, but an in-container script
cannot be the sole anti-cheat signal when the defender has root.

Challenge-specific controls should follow from the attack chain. For example, a
table-access vulnerability needs legitimate semantic decoys that reject a crude
keyword denylist while allowing a table-aware defense. A filtered export needs
both matching and non-matching records so ignoring the filter cannot pass. These
are consequences of the preserved behavior, not a universal collection of
special-case checks.

Flag integrity is independent of feature health. The orchestration layer verifies
the exact active value and handle after planting, after restart, and periodically
thereafter. The checker proves that required features remain usable; exact
retrieval proves that the scoring state was not deleted, moved, or altered.

## Handling overlapping vulnerabilities

Overlapping advisories are retained because an agent may discover any reachable
path in the historical application. During selection, the pipeline chooses one
scored capability and flag target. Other vulnerabilities are classified by
their relationship to that target:

- an unreachable path under the chosen identity remains documented context;
- a distinct capability with a different identity or proof becomes a future
  challenge candidate; and
- another genuine in-band vulnerability reaching the same flag is a valid
  free-hunt path, not a rejection condition; record it when discovered.

A blocker is a path that bypasses the application capability being measured,
such as leaked flag state, stronger unintended credentials, or infrastructure
access. Stage 3 performs a bounded search for these shortcuts; it is not an
exhaustive vulnerability audit.

This policy keeps the environment realistic without turning one package into a
bundle of unrelated fixes. It also prevents overlap discovery from becoming an
accidental requirement to reproduce every coexisting advisory.

## Ownership and artifacts

This repository owns discovery logic, source provenance, resolved windows,
semantic packets, dossiers, scope definitions, and the design of the Stage 3
handoff. These artifacts must remain reproducible and must distinguish confirmed
runtime facts from hypotheses.

The orchestration and challenge-warehouse repositories own disposable Stage 3
runtime evidence, Stage 4 challenge packages, Docker environments, flag and
restart implementations, checkers, exploits, and admission review. Migrated
copies left in their old location are retained as stale historical material
rather than deleted.

The handoff between repositories stays deliberately small: the Stage 3 study,
its exact source linkage, the attack-chain contract, raw vulnerable/fixed
observations, and the proposed capability proof. Machine validation checks that
these artifacts agree and exist; it does not attempt to replace the semantic
argument with a large schema.

## Admission standard and non-goals

A challenge is ready for independent review when its intended exploit scores,
its capability proof is sound, a narrow defense preserves the legitimate chain,
and the obvious shortcuts discovered from that chain do not score or remain
healthy. Infrastructure limitations should be recorded as incompatibilities to
fix, not used to reject an otherwise sound challenge kernel.

The minimum standard does not promise perfect checker indistinguishability,
exhaustive vulnerability discovery, or resistance to deliberate root-level
anti-harness engineering. Those are follow-up infrastructure problems when
observed. Autocuration succeeds when it consistently produces focused challenges
whose easiest natural solution is to understand the application, preserve its
useful behavior, and close the targeted security boundary.
