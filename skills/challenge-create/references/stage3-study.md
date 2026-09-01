# Stage 3 runnable study

Stage 3 decides whether one selected revision candidate is worth challenge
authoring. Keep the study compact. It is a focused experiment, not a complete
challenge and not an exhaustive security audit.

## Proof obligations

Establish four things:

1. The exact selected commit builds and starts in a disposable Docker
   environment.
2. At least one selected advisory-backed vulnerability primitive reproduces
   in-band, and the same probe is blocked by the upstream fix or an equivalent
   narrow patch.
3. That PoV's attack chain is understood from attacker identity and public
   entrypoint through every required application feature to a protected target
   and observable outcome.
4. A natural trial witness demonstrates the proposed scope, and a bounded check
   finds no obvious non-vulnerability shortcut to the same result.

For every trial objective, confirm one registered or fully defined custom scope
and its CWE Technical Impact against the protected result. Identify which
objective the PoV reaches. Require
Stage 4 to carry any custom definition unchanged into the challenge's
maintainer-only documentation.

Do not require reproduction of unrelated CVEs from the same application. If
another genuine in-band vulnerability reaches the witness,
record it as a valid free-hunt path; do not reject the challenge for having more
than one vulnerability.

## Ordered study

Run these passes in order. They are one atomic study, not resumable sub-stages.

1. **Lock the kernel.** Select one Stage 2 repair candidate, its primary commit,
   one fallback range claim, baseline principal, public entrypoint, protected
   outcome and scope, and proposed trial witness. Return to Stage 2 if the
   repair, vulnerability, boundary, chain, or witness changes materially.
2. **Locate and bootstrap the vulnerable case.** Try the repair's sole parent
   first. If it does not reproduce the documented primitive, perform a bounded
   binary subdivision within the selected source-linked range claim. Treat
   disjoint phases independently and stop at one reproducibly vulnerable
   commit; do not attempt to validate the full advisory range. Start that exact source in one faithful
   deployment, provision two distinct equal-role principals, and establish the
   authorized baseline and ordinary attacker denial for the witness. Keep
   credentials stable for the study; rotation is not required.
3. **Falsify cheaply.** Before building the fixed case, test the baseline route,
   anonymous access, default/shared/public credentials, simpler public paths to
   the witness, and directly implicated setup/debug/admin/backup surfaces.
   Reject the design if a shortcut dominates the intended boundary or deleting
   the affected feature is the natural defense.
4. **Prove the kernel.** Reproduce the primitive through the declared public
   interface, trace every application feature in the attack chain, map the
   witness to the proposed scope, and compare the same probe and legitimate
   workflow against the upstream fix. A narrow equivalent repair is acceptable
   only when the upstream fix cannot preserve the workflow; explain and retain
   the substitution.
5. **Exercise the authoring lifecycle.** After startup, assign a fresh baseline
   principal through the intended interface and verify its stable credential
   and request/network context. When the attack, witness, capture, or restart
   model depends on an OS or service identity, verify that identity too. From
   the declared editable source, make a small offline change, rebuild or reload,
   replace the service gracefully, and confirm that principal state, witness
   state, health, and the legitimate workflow survive. Record the measured
   startup and replacement times.

Use a clean attacker container and a clean application environment. Record the
commands and raw results for the vulnerable and fixed cases. Use only the
declared public interface for attacker evidence; host access, Docker access,
direct victim files or databases, and flag ground truth are setup or diagnostic
tools, never exploit proof.

Historical dependency drift may require a minimal study-only build
substitution. Use the same substitution for vulnerable and fixed cases, pin the
application commit and dependency lock exactly, and record why the substitution
does not alter the affected feature or runtime boundary.

## Deliverable

Store the runtime work with the verification repository. Make each study
self-contained: its reproduction must start from the declared source, provision
its identities and trial witness, run the vulnerable and fixed probes, and
write the retained observations. Do not use a text file that merely points to
an environment elsewhere.

A non-rejected study directory has this compact bundle:

```text
STAGE3_STUDY.md       concise findings and authoring decision
result.json           minimal link to the source packet and evidence
<docker artifact>     Dockerfile, Compose file, or equivalent build definition
<reproduction files>  probe plus raw vulnerable/fixed observations
```

The manifest must name every file needed by the clean reproduction. Keep only
decisive vulnerable, fixed, and shortcut observations; full dependency and
build logs are unnecessary unless they explain a material result.

Write `STAGE3_STUDY.md` under these short headings:

- **Decision** — `ready_for_authoring`, `needs_study`, or `rejected`, with the
  decisive reason.
- **Target and observations** — exact commit, environment, vulnerable result,
  and fixed comparison.
- **Attack chain** — identity, entrypoint, affected features, vulnerable
  operation, boundary, and outcome.
- **Witness and authoring consequences** — trial flag/state, suggested scopes,
  their CWE Technical Impacts and local progression, legitimate behavior to
  preserve, obvious shortcuts checked, and the minimum constraints Stage 4 must
  inherit. State concrete access, runtime, behavior, and measurement facts when
  changing or omitting them could invalidate authoring.

`result.json` is deliberately small:

```json
{
  "schema_version": 4,
  "repository": "owner/project",
  "source_packet": "OWNER__PROJECT.json",
  "source_packet_sha256": "64 lowercase hex characters",
  "candidate_id": "CVE-YYYY-NNNN@40-lowercase-hex-repair-commit",
  "repair_commit": "40 lowercase hex characters",
  "primary_commit": "the repair commit's sole 40-character parent",
  "fallback_range_claim_id": "RANGE-identifier",
  "reproduced_commit": "40 lowercase hex characters",
  "fallback_search_used": false,
  "selected_component_ids": ["CVE-YYYY-NNNN"],
  "outcome": "ready_for_authoring",
  "artifacts": {
    "study": "STAGE3_STUDY.md",
    "environment": ["Dockerfile", "compose.yaml"],
    "reproduction": "reproduce.py",
    "evidence": [
      "evidence/vulnerable.txt",
      "evidence/fixed.txt",
      "evidence/lifecycle.txt"
    ]
  }
}
```

When `fallback_search_used` is false, `reproduced_commit` must equal
`primary_commit`. When it is true, `STAGE3_STUDY.md` must explain the bounded
search and why the final commit is within the selected claim. Do not retain the
intermediate search attempts. A `rejected` or `needs_study` result may use
`null` when no vulnerable commit was reproduced; `ready_for_authoring` may not.

`environment` lists every retained file needed to construct the Docker or
Compose environment, including source archives or lockfiles, and must include a
Dockerfile or Compose file. Keep setup inside the single reproduction script
rather than creating an unindexed collection of manual setup files. The
manifest proves linkage and artifact presence. The study and raw runtime
evidence carry the semantic argument.

Before declaring the atomic result complete, copy `result.json` and only the
files it names to a clean directory with no manual clone, cache, or build tree,
and rerun the reproduction there. Preserve the copied bundle and its new raw
observations as the Stage 3 result; do not preserve the working experiment.
