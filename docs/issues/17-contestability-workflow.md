# Align the challenge workflow with the contestability model

**Status:** Accepted design; implementation pending.

**Design source:**
[`cyber-arena-docs/docs/contestability.md`](https://github.com/JianhongTu/cyber-arena-docs/blob/master/docs/contestability.md)
at commit `eb7f6f3`.

The current workflow can promote a challenge after reproducing one scoring path
and showing that a narrow patch blocks it. `CONTRIBUTING.md` tries to reject
shallow challenges through proxies such as attack-chain complexity and patch
size, while the creation and review skills do not require a scoring path to
survive the tested patch. That does not implement the accepted contestability
criterion.

Update this repository to use the documented branch-survival test as the
admission gate.

## Required changes

1. Link the public contestability page from `AGENTS.md`, `CONTRIBUTING.md`, and
   the affected skills while preserving the normative precedence of
   `challenge-model.md`. Replace the complexity, request-count, and patch-size
   proxies in `CONTRIBUTING.md` with a concise statement of the branch-survival
   gate. Remove the Gitea counterexample; the empirical test, not an anecdote,
   should decide admission.
2. Keep Stage 2 as source-based prioritization. Update
   `skills/challenge-create/SKILL.md` and
   `skills/challenge-create/references/semantic-review.md` so their current
   no-second-route language is explicitly limited to Stage 2. One
   evidence-backed path may justify runtime study, but it is not contestability
   evidence and cannot justify authoring. Do not require Stage 2 to reproduce a
   second path without a running application.
3. Update Stage 3 in `skills/challenge-create/SKILL.md` and
   `skills/challenge-create/references/stage3-study.md` to perform and retain all
   six observations: reproduce one nontrivial scoring path, reproduce a
   materially different path, apply a targeted patch to the first, verify the
   first is blocked, verify the SLA still holds, and verify the second still
   scores.
4. Make the Stage 3 decision sharp: `ready_for_authoring` requires all six
   observations; a reproduced one-operation scoring shortcut is `rejected` as
   shallow; a terminal patch is `rejected`; and an incomplete or inconclusive
   test is `needs_study` with the missing observation named.
5. Retain the minimum commands and raw results for both vulnerable paths, the
   targeted patch, the blocked first path, the post-patch SLA, and the surviving
   path. Update `result.json` or its validator only if needed to close those
   artifacts mechanically; semantic path independence remains a review
   judgment.
6. Update `skills/challenge-create/references/stage4-authoring.md` to confirm
   that the packaged vulnerable service still reproduces both accepted scoring
   paths before handoff. The targeted patch is study evidence, not shipped
   challenge behavior.
7. Align `skills/challenge-review/SKILL.md` and
   `skills/challenge-review/references/cheat-check.md` with the same admission
   gate. The dynamic review must apply a targeted patch on clean state, confirm
   the patched path is blocked and the SLA passes, then reproduce the
   materially different path. An `ALL` review cannot admit a shallow or
   terminal challenge.

## Non-goals

- Do not reconstruct or serialize the complete attack DAG.
- Do not introduce minimum request counts, patch line counts, vulnerability
  counts, objectives, tiers, or CVEs as substitutes for the empirical test.
- Do not treat payload, parameter, encoding, or endpoint variants that depend
  on the same vulnerable decision as materially different paths.
- Do not claim that a terminal result proves the application has no
  undiscovered vulnerabilities.
- Do not change `cyber-arena-docs/docs/challenge-model.md`; the contestability
  page is the accepted design for this workflow change.

## Acceptance criteria

- Creation guidance has one consistent definition of contestability and links
  to the public design source instead of duplicating or weakening it.
- No challenge reaches `ready_for_authoring` without retained evidence for all
  six branch-survival observations.
- Final admission review independently fails a reproduced one-operation
  shortcut or terminal patch.
- Existing Stage 2 evidence triage remains non-runtime and does not claim that
  one path proves contestability.
- The narrow relevant tests pass, followed by
  `python3 -m pytest -q skills/*/tests`.
