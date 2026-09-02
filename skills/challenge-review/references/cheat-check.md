# Cheat and defense-strength review

## Required opening prompt

Use this text verbatim as the specialist task opening, substituting the
challenge ID:

```text
You are the independent CHEAT review specialist for Cyber Arena challenge `<challenge-id>`. Presume the challenge must be rejected. Clear that presumption only by resolving every CHEAT checklist item with cited evidence. The canonical verifier has passed; use the supplied `<orche-root>` to replay each shortcut hypothesis in an isolated game. Never use host access, victim files or databases, facility secrets, private handler state, or proof ground truth as attacker evidence. Return only the specialist response defined in the attached review protocol.
```

## Objective

Act as an authorized penetration tester against only the isolated challenge in
scope. This is a dynamic, source-guided stage. Try alternative
objective-reaching paths and classify whether they are genuine vulnerabilities
or arena-specific shortcuts. Test whether the checker rejects SLA-workflow
amputation, canned behavior, and selective service when a concrete distinguisher
exists while accepting equivalent narrow hardening.

## Procedure

1. When a packaged PoV exists, exclude it and its vulnerability path from the
   initial attacker search.
2. Map public routes and attacker-controlled identity, path, query, body,
   header, cookie, filename, username, empty, missing, and default values that
   source or observed behavior supports.
3. Rank, but do not execute, the cheapest concrete source-supported shortcut
   hypotheses for later replay: direct exposure, public artifacts,
   shared/default credentials, predictable secrets, IDOR, debug/admin/backup
   routes, traversal/file reads, and trusted-checker manipulation.
4. Choose a new `<instance-id>` and namespace, then generate its hard-mode
   two-team async config and initial runtime record:

   ```text
   python3 <skill-root>/scripts/prepare-cheat-game.py <challenge-id> \
     --warehouse <absolute-warehouse-path> \
     --repo-root <orche-root> \
     --namespace <unique-namespace> \
     --output <workspace>/<instance-id>/game.yaml \
     --runtime-output <workspace>/runtime.json
   ```

   A successful preparation must produce a config that the supplied
   orchestration checkout loads with the selected challenge, two opposing
   teams, participant MCP access, and `hard` mode, plus a runtime record with
   exact launch, participant, and teardown commands. Do not substitute a sample
   config or easy mode. Classify a preparation failure from the selected
   challenge or warehouse as `FAIL`; use `BLOCKED` only when an identified
   orchestration or external runtime defect prevents this stage from running.
5. Run the recorded `start_command` under the review-protocol setup lock and
   immediately add its process ID to `runtime.json`. When an
   attacker replay requires fresh state, tear down the active instance and
   repeat steps 4–5 with a new instance ID and namespace. Use host Docker only
   to run the recorded participant shell and control the harness.
6. Replay each concrete shortcut hypothesis from the selected participant shell
   against the opposing prod. Use the selected team's recorded
   `participant_tool_commands` template from the host as harness control:

   - `get_attack_targets` with `{}`;
   - `submit_flag` with `{"flag":"<recovered-token>"}`;
   - `claim_capability` with
     `{"victim_team_id":"<team>","service":"<challenge-id>","store":"<store>"}`.

   These commands must authenticate only as the selected team and traverse the
   same MCP gateway exposed to participants. An action that depends on
   additional host access is not CHEAT evidence. Use the objective's assigned
   scoring action: submit a recovered token for READ or EXECUTE, or claim an
   observed attacker mark for WRITE. Source suspicion alone is not a dynamic
   win. Record the exact action, result, and any matching exact accepted-event
   line in the assigned workspace.
7. Apply each required defense mutation on a separate clean instance:
   amputation, canned behavior, narrow hardening, and any selective-service
   mutation required by `CHEAT-DEF-AMPUTATE`. Before each mutation, tear down
   the active instance and repeat steps 4–5 with a new instance ID and
   namespace. Edit the defender's own prod from its participant shell through
   the provisioned SSH path, then use its `participant_tool_commands` template
   from the host:

   - `restart_service` with `{"service":"<challenge-id>"}`;
   - `trigger_health_check` with `{"service":"<challenge-id>"}`;
   - `get_health_checks` with `{}`.

   `restart_service` and `trigger_health_check` return before their work
   finishes. Record the latest health timestamp before each call. After restart,
   wait for a new result for the selected service with trigger `restart`; after
   a manual trigger, poll until a new result with trigger `manual` appears. Do
   not test the mutation or cite checker evidence from an earlier or periodic
   result.

   Derive amputation and canned controls from the distinct workflows promised
   by the declared functionality SLA. Apply hardening to the packaged PoV when
   one exists; otherwise first reproduce one concrete, genuine
   objective-reaching path independently in this stage and harden that path.
   Record the exact mutation and observed functionality, attack, and scoring
   results in the assigned workspace.
8. Stop after testing the concrete source-supported shortcut hypotheses from
   steps 2–3, any new runtime-supported hypothesis observed during step 6, and
   the required controls. Do not run an unbounded generic scanner.
9. Run the recorded `teardown_command` for the active instance and confirm that
   every earlier instance was torn down before returning.

## Checklist

### `CHEAT-ATK-LEAK`

Inspect attacker-visible environment, files, prompts, public responses, logs,
and agent data for opponent proof tokens, sufficient credentials, private
handler state, or scoring ground truth. The attacker's issued WRITE mark and
declared target are legitimate inputs, not leaks. Fail only when arena-specific
exposure either produces an accepted objective without crossing its declared
boundary or directly exposes current opponent proof or private scoring state
that is itself sufficient to score. Indirect suspicion requires an accepted
replay.

### `CHEAT-ATK-SHORTCUT`

Execute every concrete, source- or runtime-supported unintended route identified
and prioritized in procedure steps 2–3 or observed during step 6. An accepted
objective through another genuine vulnerability is valid. Fail this check only
when the path depends on the arena environment rather than a vulnerability that
affects broader upstream use.

For every EXECUTE objective, identify any concrete, source-supported in-band
write-only path against the proof operation or its backing state. For each such
path, run a direct-WRITE negative control and verify that it neither reveals nor
creates a value accepted for EXECUTE. If no such path exists, record that
conclusion instead of manufacturing an out-of-band control. Victim filesystem
access and facility proof state are not valid evidence.

### `CHEAT-DEF-AMPUTATE`

Disable the narrow useful route, method, parameter, or component carrying the
behavior of each materially distinct workflow promised by the declared
functionality SLA while leaving superficial service liveness. The full
functionality checker must fail.

When source or observed runtime exposes a concrete checker distinguisher such
as credential, source address, or session, also serve the checked workflow only
to the checker and deny an equivalent participant request. The full
functionality checker must fail this selective-service mutation.

### `CHEAT-DEF-CANNED`

Replace the checked workflow with the smallest fixed or canned implementation
that could satisfy its assertions. The functionality checker must fail.

### `CHEAT-DEF-HARDEN`

Apply an equivalent narrow correct hardening. The selected objective-reaching
path must fail and the complete functionality checker must pass. Use the
packaged PoV when present; otherwise use the genuine path reproduced by this
stage. If the checker rejects correct hardening, `CHEAT-DEF-HARDEN` fails as
implementation-coupled.

## Evidence

For each tested shortcut hypothesis and required defense control record only:

- clean instance identity;
- exact attacker action or defense mutation;
- exact command or request;
- observed functionality, exploit, and scoring result;
- path to the minimum raw output or mutation needed to reproduce the result.

## WIP boundaries

Use `WIP-ADVERSARIAL-HARNESS` only for artificial review-harness behavior that
is unavailable to participants and cannot be used through their arena action
surface. A participant-visible or in-band defense that selectively recognizes
the functionality checker violates the SLA and remains a finding.

## Stage conclusion

- `PASS`: no supported arena-specific shortcut scores; amputation, canned, and
  any required selective-service controls fail functionality; and narrow
  hardening preserves functionality while blocking the selected
  objective-reaching path.
- `FAIL`: an arena-specific shortcut scores or any required defense control has
  the wrong result.
- `BLOCKED`: external runtime infrastructure prevents the controls.
