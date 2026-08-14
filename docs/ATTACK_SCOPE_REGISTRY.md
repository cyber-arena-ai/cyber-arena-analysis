# Global Attack Scope Registry

> Human-readable view of `docs/attack_scopes.json`. The JSON file is authoritative.

Flags prove capabilities, not CVEs. Every scope refines exactly one
[MITRE CWE Technical Impact](https://cwe.mitre.org/cwraf/enum_of_ti.html) into a
concrete protected target and independently observable proof. A challenge
selects applicable scopes from this registry and records its concrete flag
store and proof mechanism. Challenge-specific scopes use
`custom.<challenge_id>.*` and must name one of the same technical impacts.

| CWE Technical Impact | Scope | Target | Boundary |
| --- | --- | --- | --- |
| Read Data | `app.cross_boundary.read` | application data | tenant, owner, role, or visibility |
| Read Data | `host.file.read` | host file | application storage authority |
| Read Data | `secret.credential.read` | credential or secret | authentication or authorization |
| Read Data | `storage.private_object.read` | private object-store object | object-storage authorization |
| Modify Data | `app.cross_boundary.write` | application data | tenant, owner, role, or visibility |
| Modify Data | `host.file.write` | host file | application storage authority |
| Bypass Protection Mechanism | `network.internal.access` | internal network service | network reachability |
| Bypass Protection Mechanism | `app.privileged.control` | privileged application action | role authority |
| Execute Unauthorized Code or Commands | `host.command.execute` | service process | code-execution authority |

The CWE parent is deliberately coarse. The scope supplies the concrete
capability that a challenge can plant and verify. Advisory CWE weakness labels
describe root cause and do not determine the flag's Technical Impact.

## Disallowed success conditions

The registry awards no scope or flag credit for service crashes, sustained
availability loss, resource exhaustion, intended health-check failure, or
access to arena control-plane/private planting state. A route must map to a
positive scope, support an independent proof, and not require one of these
effects.

## Per-challenge mapping rule

For every planted flag, record: scope ID, local tier ordering, store, authorized baseline identity, proof returned to the scorer, and legitimate workflow that must remain functional. Local tiers describe challenge progression or partial credit, not universal severity. Planting must not add the selected vulnerable path or encode a CVE-specific hint.

Use an existing scope when it fits. A custom scope must define `id`,
`technical_impact`, `title`, `target`, `boundary`, `capability`, and
`proof_requirement`. Retain that definition in the Stage 3 study and the
implemented challenge's maintainer-only documentation. Promote it to this
registry only when it is reusable across challenges.
