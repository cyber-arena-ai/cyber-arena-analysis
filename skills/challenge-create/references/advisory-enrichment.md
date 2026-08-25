# Complementary advisory review

Use the retained OSV snapshot as the discovery seed, not as a claim that every
relevant advisory or repository relationship is present. Perform this bounded
review after a project is shortlisted and before semantic triage.

This process improves evidence coverage but does not permit an agent to
manufacture an affected range or silently add an unvalidated component to a
semantic packet.

## Sources

Prefer first-party or immutable evidence:

- upstream GitHub Security Advisories and repository security notices;
- release security notes and changelogs;
- fix commits, pull requests, and regression tests;
- advisories for separately versioned bundled applications, plugins, providers,
  or server modules;
- aliases that connect records already retained in the source corpus.

Use blogs and third-party PoCs only to locate behavior or primary evidence.
Retain the primary URL for every claim used in the review.

## Bounded method

1. Start from one shortlisted repository and its schema-v2 semantic packet.
2. Search the upstream security history around the packet's selected releases,
   fixes, and affected feature families.
3. Resolve aliases, package identities, fix commits, and release containment.
4. Decide how each complementary record relates to the retained packet:
   - **supporting evidence** clarifies the actor, behavior, feature, or repair;
   - **alias evidence** connects records already represented in the packet;
   - **new component evidence** introduces a vulnerability not represented by
     the packet.
5. Put supporting and alias evidence directly in the semantic review with a
   precise claim. Do not add a new component id to `selected_component_ids`
   unless the packet contains it.
6. If a new component changes the selected affected set or historical window,
   normalize its complete OSV-shaped record into a hash-listed advisory archive
   as specified by [source-discovery.md](source-discovery.md), then rerun Stage
   1 and the mechanical Stage 2 resolver against that same manifest. Until
   then, return `uncertain`; do not maintain a parallel hand-built Git
   chronology.

## Duplicate screening

Before expensive runtime work, compare the proposed application, advisory,
asset, and boundary against registered warehouse challenges and open PRs. An
exact slug or advisory collision is mechanical. Whether two challenges measure
the same protected asset and boundary requires judgment.

Refresh this cheap check at Stage 4 because open PR state can change after
semantic review.

## Claim boundary

Complementary review may improve understanding of the selected attack chain
and patch. It does not confirm runtime feature presence, reachability,
exploitability, proof placement, challenge depth, or a second attack route.
Semantic triage owns the static principal, asset-lifecycle, and operability
case; Stage 3 owns live confirmation and measurement.
