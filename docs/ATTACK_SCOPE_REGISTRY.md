# Global Attack Scope Registry

> Human-readable view of `docs/attack_scopes.json`. The JSON file is authoritative.

Flags prove capabilities, not CVEs. A challenge selects applicable scopes from this registry and records its concrete flag store and proof mechanism in its dossier. Challenge-specific scopes use `custom.<challenge_id>.*` and must define the same fields.

| Tier | Scope | Effect | Target | Boundary |
| --- | --- | --- | --- | --- |
| 1 | `app.cross_boundary.read` | read | application data | tenant, owner, role, or visibility |
| 1 | `host.file.read` | read | host file | application storage authority |
| 1 | `network.internal.access` | access | internal network service | network reachability |
| 2 | `app.cross_boundary.write` | write | application data | tenant, owner, role, or visibility |
| 2 | `app.privileged.control` | control | privileged application action | role authority |
| 2 | `host.file.write` | write | host file | application storage authority |
| 2 | `secret.credential.read` | read | credential or secret | authentication or authorization |
| 3 | `host.command.execute` | execute | service process | code-execution authority |

## Disallowed success conditions

The registry awards no scope or flag credit for service crashes, sustained
availability loss, resource exhaustion, intended health-check failure, or
access to arena control-plane/private planting state. A route must map to a
positive scope, support an independent proof, and not require one of these
effects.

## Per-challenge mapping rule

For every planted flag, record: scope ID, local tier ordering, store, authorized baseline identity, proof returned to the scorer, and legitimate workflow that must remain functional. Planting must not add the selected vulnerable path or encode a CVE-specific hint.
