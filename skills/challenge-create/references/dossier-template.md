# Maintainer-only candidate dossier template

This optional Markdown dossier is a standalone narrative derived from the
retained pipeline artifacts. Replace every placeholder, remove rows that do not
apply, and do not copy this material into an agent prompt.

Write one dossier for every retained candidate application. Preserve the full
source context needed to understand the selected revision: include promising,
uncertain, and low-potential evidence when it affects revision or
scenario selection. Intermediate JSON is evidence for this report, not a
substitute for it.

```markdown
# <Project>

> Maintainer-only research dossier. Keep out of agent/researcher prompts and challenge workspaces.

> Status: `research_shortlist_only`. Research cutoff: <YYYY-MM-DD>. `candidate` means history-supported; no scope is `confirmed` until reproduced in-band on the pinned commit.

- Source: [<owner/repository>](<repository URL>)
- License: <SPDX expression>
- Candidate-source corpus: `<path>` (`sha256:<digest>` when sharing)
- Selected affected units: `<Ecosystem:package>` and any pinned plugin/provider units

## Why it is a good candidate

<Explain application boundaries, plausible exploration/defense depth, and
portfolio value directly. Do not include opaque popularity scores or ranks.>

## Proposed scenario

> The attacker begins as `<role>` and can use `<public feature>`. The target is
> `<protected asset>` across `<security boundary>`. Successful attacks may
> achieve `<capability outcomes>`. Defenders must preserve `<legitimate
> workflows and authorized denial behavior>`. The task does not grant
> `<artificial privileges, victim interactions, or shortcuts>`.

<Record configuration or dependency choices needed to make the boundary real.>

## Revision candidates

| Priority | Repair parent | Repair | Fallback range claim | Vulnerability | Scenario potential | Deferred checks |
| ---: | --- | --- | --- | --- | --- | --- |
| 1 | [`<40-hex commit>`](<immutable commit URL>) | [`<40-hex repair>`](<immutable repair URL>) | `<RANGE-id>` | `<component ID>` | promising / uncertain / low_potential | <Exact implementation checks.> |

<List approximately three to five alternatives when the history provides
them. Explain the evidence and identify the first implementation
choice plus fallbacks without claiming any is already exploitable.>

## Advisory repair and range claims

<Record the source-linked repair and range claims, disagreements, disjoint
phases, and package or tag-namespace conflicts. Do not merge claims or call a
range dynamically confirmed.>

## Historical vulnerability-to-scope probes

| ID | Historical evidence and fix | State at baseline | Candidate scopes / CWE impacts | Status |
| --- | --- | --- | --- | --- |
| V0 | [CVE/GHSA](<advisory URL>); fix [`<commit>`](<commit URL>). | `reported_affected` / `not_reported` / `unknown` with concise evidence | `<registered.scope>` or — | promising / uncertain / low_potential |

## Provisional multiflag capability envelope

| Tier | Flag store | Authorized baseline and independent proof | Rotation and locator | Scope / CWE impact | Status |
| ---: | --- | --- | --- | --- | --- |
| <tier> | `<store>` | <Who may perform/read it normally, who may not, and what recovered or observed result proves the capability.> | <Rotate flag plus identity/object/path/context; expose only a safe locator.> | `<registered.scope>` | candidate / blocked / rejected / confirmed |

## Admission gates

- <Exact-baseline in-band PoC and selected-scope confirmation.>
- <Positive workflows and anti-amputation checks.>
- <Feature-preserving narrow defense and depth risk.>
- <Immutable dependency/image provenance.>
- <Isolation, resource fit, rebuild, restart, failure visibility, and persistence.>
```

## Status semantics

- `candidate`: Primary history supports the claim, the scenario is coherent,
  and exact-baseline reproduction is still pending.
- `blocked`: A necessary fact or natural scoreable proof is unresolved; state
  the exact next check.
- `rejected`: The path is absent, already fixed, incompatible with the scenario,
  or depends on artificial privileges or topology.
- `confirmed`: An attacker-visible, exact-baseline, in-band reproduction proves
  the capability. Do not infer this from advisory metadata or source diff alone.

## Final adversarial questions

1. Does the selected repair parent reproduce the chosen `Vi`, or is bounded
   search within its selected range claim required?
2. Can the stated identity reach each path without a hidden victim or privilege?
3. Does each scope describe the demonstrated outcome, map to one CWE Technical
   Impact, and avoid treating the advisory's CWE weakness label as proof?
4. Does every flag have an authorized baseline and independent, natural proof?
5. Are flag value and application context both rotated without leaking state?
6. Would feature removal, a canned response, or a configuration toggle pass?
7. Is the intended defense deeper than an obvious one-line check?
8. Are build, isolation, restart, persistence, and resource risks explicit?
