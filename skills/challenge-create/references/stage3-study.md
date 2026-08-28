# Stage 3 runnable study

Stage 3 decides whether one selected historical window is worth challenge
authoring. Keep the study compact. It is a focused experiment, not a complete
challenge and not an exhaustive security audit.

## Proof obligations

Establish four things:

1. The exact selected commit builds and starts in a disposable Docker
   environment.
2. Each vulnerability primitive selected for the proposed challenge reproduces
   in-band, and the same probe is blocked by the upstream fix or an equivalent
   narrow patch.
3. The attack chain is understood from attacker identity and public entrypoint
   through every required application feature to the protected target and
   observable outcome.
4. A natural trial witness demonstrates the proposed scope, and a bounded check
   finds no obvious non-vulnerability shortcut to the same result.

For every trial flag, confirm one registered or fully defined custom scope and
its CWE Technical Impact against the observed result. One reproduction may
prove multiple flags when their attack chain overlaps. Use independent
reproductions for materially independent paths. Require Stage 4 to carry any
custom definition unchanged into the challenge's maintainer-only documentation.

Do not require reproduction of unrelated CVEs that merely coexist in the
selected window. If another genuine in-band vulnerability reaches the witness,
record it as a valid free-hunt path; do not reject the challenge for having more
than one vulnerability.

## Ordered study

Run these passes in order. They are one atomic study, not resumable sub-stages.

1. **Lock the kernel.** Select one Stage 2 window and write down the exact
   commit, baseline principal, public entrypoint, protected outcome and scope,
   and proposed trial witness. Return to Stage 2 if any of these changes
   materially during the study.
2. **Bootstrap the vulnerable case.** Start the exact source in one faithful
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
   principal through the intended interface and verify its stable credential,
   service identity, and request/network context. From the declared editable
   source, make a small offline change, rebuild or reload, replace the service
   gracefully, and confirm that principal state, witness state, health, and the
   legitimate workflow survive. Record the measured startup and replacement
   times.

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
stage4-contract.json  general facts and open questions for authoring
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
  inherit.

`result.json` is deliberately small:

```json
{
  "schema_version": 3,
  "repository": "owner/project",
  "source_packet": "OWNER__PROJECT.json",
  "source_packet_sha256": "64 lowercase hex characters",
  "window_id": "W1",
  "commit": "40 lowercase hex characters",
  "selected_component_ids": ["CVE-YYYY-NNNN"],
  "outcome": "ready_for_authoring",
  "artifacts": {
    "study": "STAGE3_STUDY.md",
    "stage4_contract": "stage4-contract.json",
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

`environment` lists every retained file needed to construct the Docker or
Compose environment, including source archives or lockfiles, and must include a
Dockerfile or Compose file. Keep setup inside the single reproduction script
rather than creating an unindexed collection of manual setup files. The
manifest proves linkage and artifact presence. The study and raw runtime
evidence carry the semantic argument.

For `ready_for_authoring` and `needs_study`, write this general
`stage4-contract.json` rather than adding application-specific manifest fields:

```json
{
  "schema_version": 1,
  "facts": [
    {
      "area": "access",
      "requirement": "Assign a fresh equal-role baseline principal after startup.",
      "evidence": ["evidence/lifecycle.txt"]
    },
    {
      "area": "runtime",
      "requirement": "Replacement preserves principal and witness state.",
      "evidence": ["evidence/lifecycle.txt"]
    },
    {
      "area": "behavior",
      "requirement": "Preserve the legitimate workflow exercised by the study.",
      "evidence": ["evidence/fixed.txt"]
    },
    {
      "area": "measurement",
      "requirement": "Observe the protected outcome through the public service.",
      "evidence": ["evidence/vulnerable.txt"]
    }
  ],
  "open_questions": []
}
```

Each fact has one area from `access`, `runtime`, `behavior`, or `measurement`, a
concrete requirement, and one or more evidence paths already named by
`result.json`. Record a fact only when changing or omitting it could invalidate
principal assignment, public exploit reachability, objective proof, the
declared workflow, or rebuild/restart persistence.

An open question has `area`, `question`, `disposition` (`blocking` or
`deferred`), and `reason`. `ready_for_authoring` requires facts in all four
areas and no blocking question. `needs_study` requires at least one blocking
question. A rejected study may omit the contract.

Before declaring the atomic result complete, copy `result.json` and only the
files it names to a clean directory with no manual clone, cache, or build tree,
and rerun the reproduction there. Preserve the copied bundle and its new raw
observations as the Stage 3 result; do not preserve the working experiment.
