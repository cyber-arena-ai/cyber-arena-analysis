# OSS Challenge Contribution Guide

Use this guide to choose a promising OSS project, shape it into a strong Cyber
Arena challenge, and understand the evidence expected for admission. Once the
design is clear, follow the canonical
[challenge-authoring SOP](https://github.com/cyber-arena-ai/cyber-arena-orche/blob/main/docs/CHALLENGE_AUTHORING_SOP.md)
maintained in `cyber-arena-orche` to implement and validate it.

## 1. Select a suitable OSS application

Choose software that is **widely used, actively maintained, openly licensed, and
self-hostable**. It should be a real network service with meaningful identities,
data, roles, or trust boundaries and a security history that supports useful
confidentiality, integrity, privilege, or execution outcomes.

Every challenge must preserve a meaningful application-enforced boundary and
legitimate behavior a defender must preserve. The packaged `_exploit.py` is the
golden PoV: when run through an attacker-visible path at the pinned revision, it
must produce an authoritative accepted outcome for at least one objective.
Advisories, upstream reports, tests, PoCs, and source evidence may support the
PoV but are not required.

A rich attack surface with room for complex paths is desirable because it
supports game exploration, but no minimum attack complexity, chain length, or
patch size is required. Availability-only effects are not valid outcomes. The
required boundary and PoV may not be supplied by default credentials, disabled
security options, or artificial privileges.

## 2. Start from one pinned revision

A contribution starts from one OSS commit or release. Record the evidence
needed to justify that challenge:

- the upstream project and exact immutable revision;
- the intended security boundary and vulnerable behavior;
- the PoV's supporting provenance and evidence, including advisory and
  source-linked repair or fix references when available; and
- why the behavior is reachable in the proposed configuration.

## 3. Describe the challenge scenario

Before authoring, state:

- the attacker's starting identity and legitimate access;
- the public application feature available to them;
- the protected asset and security boundary they are trying to cross;
- the capability outcomes a successful attack may achieve;
- the legitimate workflow a defender must preserve; and
- the privileges and shortcuts that are explicitly unavailable.

Use this template:

> The attacker begins as `[role]` and can use `[public feature]`. The target is
> `[protected asset]` across `[security boundary]`. Successful attacks may
> achieve `[capability outcomes]`. Defenders must preserve `[legitimate
> workflow]`. The task does not grant `[artificial privileges or shortcuts]`.

Confirm that the pinned application can run in isolation, fit the arena's
resource budget, and rebuild and restart after source edits.

## 4. Design the challenge model

Every contribution makes four principal design decisions.

### Vulnerable service and minimal health check

Ship the selected application behavior in a realistic configuration. Define a
small behavioral check that guards the minimum legitimate workflow against
regression. The check is deliberately minimal, but must prevent trivial
defenses such as feature amputation while allowing an equivalent narrow
security fix.

### Tiered capabilities and flags

Each flag represents an observable capability outcome **instead of a CVE or
exploit path**. In the challenge's `_maintainer/README.md`, map each flag store
to a scope and, when the challenge defines a ladder, a local tier using the
[attack-scope registry](skills/challenge-create/references/attack-scopes.json), and state the concrete
evidence that its oracle proves in this application.

Prefer a challenge-local progression such as:

| Local tier | Typical registered scopes |
|---|---|
| 1 | `app.cross_boundary.read`, `network.internal.access`, `host.file.read`, `storage.private_object.read` |
| 2 | `app.cross_boundary.write`, `app.privileged.control`, `host.file.write`, `secret.credential.read` |
| 3 | `host.command.execute` |

This is a starting point, not a universal severity ordering. Adjust local tiers
when the application's actual boundary and capability progression differ.

Each flag must be **independently** scored so each capability can be observed
separately.

If no registered scope fits, do not modify the global registry. Declare a scope
only in that same `_maintainer/README.md` with the required fields from the
[attack-scope registry](skills/challenge-create/references/attack-scopes.json):

- `id`: `custom.<challenge_id>.<capability>`;
- `technical_impact`: exactly one registered MITRE CWE Technical Impact;
- `title`: a short outcome name;
- `target`: the protected asset or operation;
- `boundary`: the application-enforced boundary crossed;
- `capability`: the security outcome achieved;
- `proof_requirement`: what the objective's oracle proves.

`tier` and `rationale` are not required fields in the custom-scope schema.

Rotate both the flag value and its application context—the containing identity,
object, record, path, repository, or equivalent location. Use realistic
surrounding data and avoid fixed-target symmetry, flag-shaped fixtures, leaks,
or privileged shortcuts. Define `flag_id` to explicitly disclose the attack target whose key is checked by the scoreboard. A
flag ID must never reveal the flag, credentials, or private planting state.

Flag placement should remain **independent** of vulnerability selection. Different
natural attack paths may prove the same capability, and one attack chain may
reach several capability tiers. At least one planned flag must be reachable
through the intended public attack surface before hardening.

### Restart after patching

A defender's source change must become the newly evaluated service. Failed
builds or starts must be visible, old serving code must not remain active, and
required application and flag state must survive a valid restart.

### Challenge-specific prompt

Brief the legitimate application, public interface, connection facts, editable
source location, and concise source map. Do not reveal the CVE, vulnerability
class or location, exploit chain, payload, flag location, or recommended fix.
The prompt should support independent investigation rather than prescribe one
attack path.

## 5. Record provenance and prove reproducibility

In `_maintainer/README.md`, record:

- the upstream repository URL and exact source commit SHA;
- the CVE or upstream advisory ID and URL for each known vulnerability
  intentionally included;
- the upstream fix commit or pull request, when published;
- immutable base-image and behavior-relevant dependency pins.

Follow the SOP for the exact build and
validation procedure.

## 6. Review, fix, and rerun

Complete the SOP's canonical sanity checks, then invoke the automatic reviewer
with exactly one registered challenge slug and `ALL`. Use Claude Code by
default for final admission review; Codex is a supported fallback, not an
acceptance gate.

```text
Claude Code: /cyber-arena-analysis:challenge-review <challenge-slug> ALL <absolute-warehouse-path> <absolute-orche-root>
Codex:       $challenge-review <challenge-slug> ALL <absolute-warehouse-path> <absolute-orche-root>
```

Choose **all stages** for the final review. Read the generated
findings and evidence, fix the challenge, and rerun the failed stage.

Common issues to eliminate before submission include:

- mutable or incomplete source, image, and dependency provenance;
- a vulnerable path that is absent, disabled, or unreachable in the built image;
- fixed, leaked, or privileged flag placement that bypasses the claimed scope;
- a health check that accepts liveness, canned output, or feature amputation;
- a restart that keeps old code serving or loses required application state;
- a prompt that reveals the vulnerability, exploit path, fix, or flag location;
- exploit evidence that relies on host access, private planting state, or any
  input unavailable to the attacker.

A challenge is benchmark-ready only after an all-stage review establishes
static soundness, canonical verification, cheat and defense strength, and an
accepted in-band exploit through a genuine non-arena-specific vulnerability.
Record unresolved risks explicitly; no finite review proves that every
unintended path is absent.
