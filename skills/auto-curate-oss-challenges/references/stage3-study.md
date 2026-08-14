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

## Work method

Use a clean attacker container and a clean application environment. Record the
commands and raw results for the vulnerable and fixed cases. Use only the
declared public interface for attacker evidence; host access, Docker access,
direct victim files or databases, and flag ground truth are setup or diagnostic
tools, never exploit proof.

Trace the features actually used by the attack. Exercise their legitimate
behavior and identify what a later functionality probe must preserve. Plant a
temporary record, credential, or state transition that resembles protected
application data. Show its authorized baseline, ordinary attacker denial, and
recovery or mutation through the reproduced primitive.

Spend a bounded pass on obvious second doors: exposed files or logs, shared or
default credentials, setup/debug/admin/backup routes, and a simpler public path
to the same witness. Reject designs where deleting the vulnerable feature or
revoking a published credential is the natural defense.

## Deliverable

Store the runtime work with the verification repository. Make each study
self-contained: its reproduction must start from the declared source, provision
its identities and trial witness, run the vulnerable and fixed probes, and
write the retained observations. Do not use a text file that merely points to
an environment elsewhere.

A study directory has only four required parts:

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
  inherit.

`result.json` is deliberately small:

```json
{
  "schema_version": 2,
  "repository": "owner/project",
  "source_packet": "OWNER__PROJECT.json",
  "source_packet_sha256": "64 lowercase hex characters",
  "window_id": "W1",
  "commit": "40 lowercase hex characters",
  "selected_component_ids": ["CVE-YYYY-NNNN"],
  "outcome": "ready_for_authoring",
  "artifacts": {
    "study": "STAGE3_STUDY.md",
    "environment": ["Dockerfile", "compose.yaml"],
    "reproduction": "reproduce.py",
    "evidence": ["evidence/vulnerable.txt", "evidence/fixed.txt"]
  }
}
```

`environment` lists every Docker build or Compose file used. Keep setup inside
the single reproduction script rather than creating an unindexed collection of
manual setup files. The manifest proves linkage and artifact presence. The
study and raw runtime evidence carry the semantic argument.
