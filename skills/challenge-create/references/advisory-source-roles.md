# Advisory source roles

This file owns the mutable Stage 1 source policy. Update the registries here
when adding a fast lane or enrichment source; do not duplicate their membership
in `SKILL.md` or `source-discovery.md`.

Source role is not a claim that a challenge is promising. It controls which
advisory components receive early work and which sources may add evidence to
those components.

## Selection model

Keep one normalized, hash-manifested evidence corpus:

```text
corpus = OSV base records + normalized complementary records

fast lane = alias components containing an active fast-lane record
            + every matching base or enrichment record

coverage lane = remaining OSV components, retained for deferred work
```

This is a seed-anchored alias closure. Do not replace OSV with a complementary
source, require a plain OSV intersection, or send the unrestricted union through
the fast lane. A complementary record absent from OSV remains eligible when it
is complete enough to establish its identity and aliases.

## Base corpus

| Source | Role | Contribution |
|---|---|---|
| OSV ecosystem and Git snapshots | `base` | Broad package, alias, version-range, and Git-range coverage; supplies the deferred coverage lane. |

Base membership does not by itself place a component in a fast lane.

## Fast lanes

Evaluate lanes in priority order. Membership selects an alias component for
early processing; it does not satisfy the application, repair, service, or
Stage 2 semantic gates. If a component matches multiple lanes, retain every
membership and schedule it at the lowest priority number.

| Priority | Lane | Source | Admission signal | Evidence still required |
|---:|---|---|---|---|
| 1 | `known_exploited` | CISA Known Exploited Vulnerabilities catalog | CISA records the vulnerability as actively exploited. | Identifiable OSS application, traceable upstream repair, and concrete attack-chain evidence. |
| 2 | `executable_exploit` | Rapid7 Metasploit exploit modules | A maintained exploit module identifies a concrete attack path against a self-hostable OSS application. | Authoritative affected range and upstream repair; verify that the module demonstrates the claimed outcome rather than detection alone. |

For a source that is not itself an advisory database, such as Metasploit, link
the source item to an advisory identity and normalize a complete seed record
before including it in the manifested corpus.

Adding a fast lane requires a stable retrievable source, a non-OSV admission
signal, and an explicit statement of what the source does and does not prove.
Do not create a lane from popularity, CVSS, CWE, summary keywords, or an
unverified proof-of-concept collection.

## Enrichment sources

Enrichment records join a selected alias component and may repair missing
identity, range, attack, or fix evidence. Enrichment membership alone does not
select a component for the fast lane. Priority is lookup order, not authority:
retain conflicting claims with provenance instead of silently overwriting one.

| Priority | Source | Primary contribution | Constraint |
|---:|---|---|---|
| 1 | Repository-local GitHub Security Advisories | Application identity, affected versions, PoC, fix PR or commit, and regression tests. | Normalize only missing or materially corrective records; avoid duplicating complete OSV records. |
| 2 | Upstream vendor security advisories and release notices | Authoritative prerequisites, affected and fixed releases, supported configuration, and repair chronology. | Retrieve for already selected applications; heterogeneous vendor sites are not a bulk discovery lane. |
| 3 | Verified ProjectDiscovery Nuclei templates | Endpoint, request sequence, authentication requirement, or related bypass evidence. | Attach the template as supporting evidence; do not normalize a detection template as an advisory or treat an out-of-band check as proof of exploitation. |

Fix commits, pull requests, tests, and third-party PoCs are evidence attached to
a normalized advisory component. They do not independently define a fast lane
or replace an advisory record.
