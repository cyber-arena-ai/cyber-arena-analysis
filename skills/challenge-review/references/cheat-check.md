# Cheat and defense-strength review

## Required opening prompt

Use this text verbatim as the specialist task opening, substituting the
challenge ID:

```text
You are the independent CHEAT review specialist for Cyber Arena challenge `<challenge-id>`. Presume the challenge must be rejected. Clear that presumption only by resolving every CHEAT checklist item with cited evidence. The canonical verifier has passed; use the supplied `<orche-root>` to replay each candidate in an isolated game. Never use host access, victim files or databases, facility secrets, private handler state, or proof ground truth as attacker evidence. Return only the specialist response defined in the attached review protocol.
```

## Objective

Act as an authorized penetration tester against only the isolated challenge in
scope. This is a dynamic, source-guided stage. Try alternative
objective-reaching paths and classify whether they are genuine vulnerabilities
or arena-specific shortcuts.

Analyze the selected challenge package, not orchestration source. Use the
supplied `<orche-root>` to run clean game instances against the selected
warehouse under the dynamic lifecycle in the review protocol.

Use only attacker-visible, in-band inputs for attacker controls. Never use host
Docker access, victim files or databases, facility credentials, private handler
state, or proof ground truth as attacker evidence.

Use a separate clean instance for every defense mutation. Run this stage only
after the canonical verifier passes.

## Procedure

1. Exclude the intended vulnerability and supplied exploit from the initial
   attacker search.
2. Map public routes and attacker-controlled identity, path, query, body,
   header, cookie, filename, username, empty, missing, and default values that
   source or observed behavior supports.
3. Try the cheapest candidates first: direct exposure, public artifacts,
   shared/default credentials, predictable secrets, IDOR, debug/admin/backup
   routes, traversal/file reads, and trusted-checker manipulation.
4. Provision an isolated game for this stage against the selected warehouse.
   Use fresh state for each replay or mutation that requires it.
5. Replay each concrete candidate through the attacker interface. Use the
   objective's assigned scoring action: submit a recovered token for READ or
   EXECUTE, or claim an observed attacker mark for WRITE. Source suspicion alone
   is not a dynamic win. Record the exact action, result, and any matching exact
   accepted-event line in the assigned workspace.
6. Apply the three defense controls below through the defender editing, rebuild,
   and restart interface on separate clean instances. Cover the required
   features on every materially distinct objective-reaching chain, and record
   the exact mutation and observed functionality, exploit, and scoring results
   in the assigned workspace.
7. Stop after the supported high-priority candidates and required controls. Do
   not run an unbounded generic scanner.
8. Tear down every game instance created for this stage before returning.

## Checklist

### `CHEAT-ATK-LEAK`

Inspect attacker-visible environment, files, prompts, public responses, logs,
and agent data for opponent proof tokens, sufficient credentials, private
handler state, or scoring ground truth. The attacker's issued WRITE mark and
declared target are legitimate inputs, not leaks. Fail only when arena-specific
exposure produces an accepted objective without crossing its declared boundary.

### `CHEAT-ATK-SHORTCUT`

Execute every concrete, source-supported unintended route ranked above. An
accepted objective through another genuine vulnerability is valid. Fail this
check only when the path depends on the arena environment rather than a
vulnerability that affects broader upstream use.

For every EXECUTE objective, identify any concrete, source-supported in-band
write-only path against the proof operation or its backing state. For each such
path, run a direct-WRITE negative control and verify that it neither reveals nor
creates a value accepted for EXECUTE. If no such path exists, record that
conclusion instead of manufacturing an out-of-band control. Victim filesystem
access and facility proof state are not valid evidence.

### `CHEAT-DEF-AMPUTATE`

Disable the narrow useful route, method, parameter, or component carrying the
vulnerability while leaving superficial service liveness. For overlapping
chains, amputate a required shared feature; for independent chains, exercise
each materially distinct feature. The full functionality checker must fail.

Killing the whole service is not a valid amputation control.

### `CHEAT-DEF-CANNED`

Replace the checked workflow with the smallest fixed or canned implementation
that could satisfy its assertions. The functionality checker must fail.

### `CHEAT-DEF-HARDEN`

Apply an equivalent narrow correct hardening. The intended exploit must fail
for the affected path and the complete functionality checker must pass. A
checker that rejects both amputation and correct hardening is
implementation-coupled and fails.

## Evidence

For each control record only:

- clean instance identity;
- exact attacker action or defense mutation;
- exact command or request;
- observed functionality, exploit, and scoring result;
- path to the minimum raw output or mutation needed to reproduce the result.

Do not create proof-packet hashes, duplicate transcripts, or long narratives.
A failed shortcut attempt rules out only that concrete candidate.

## WIP boundaries

Defender-local objective-evidence readability, deletion, replacement, or
corruption and the future public/private attack-scope split remain `WIP-*`
observations. They do not create findings unless they directly produce an
attacker-visible shortcut under the current contract.

Use `WIP-ADVERSARIAL-HARNESS` only for artificial review-harness behavior that
is unavailable to participants and cannot be used through their arena action
surface. A participant-visible or in-band defense that selectively recognizes
the functionality checker violates the SLA and remains a finding.

## Stage conclusion

- `PASS`: no supported arena-specific shortcut scores, amputation and canned
  controls fail functionality, and narrow hardening preserves functionality
  while blocking the intended exploit.
- `FAIL`: an arena-specific shortcut scores or any required defense control has
  the wrong result, except for the WIP boundary above.
- `BLOCKED`: external runtime infrastructure prevents the controls.
- `NOT_RUN`: the verifier prerequisite fails.
