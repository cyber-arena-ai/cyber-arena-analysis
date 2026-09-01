# Stage 4 authoring

Stage 4 translates one accepted Stage 3 study into one registered challenge.
It is an atomic authoring stage, not another semantic study and not a sequence
of resumable sub-stages. Keep partial work in the warehouse worktree; preserve
only the final result defined below.

## Inputs and contract gate

Start with the accepted Stage 3 `result.json` and `STAGE3_STUDY.md`. Refresh the
registered-challenge and open-PR collision check from
[advisory-enrichment.md](advisory-enrichment.md) before spending build time.
Hash both Stage 3 files before authoring so the final result binds the mechanical
manifest and the semantic contract it implements.

Lock and give every implementation agent:

- the exact orchestration commit pinned in `SKILL.md`; and
- one exact challenge-warehouse base commit.

Read the complete normative challenge model, then the authoring SOP and
interfaces from the locked orchestration commit. Confirm that the Stage 3
objective, scope, oracle, baseline principal, target, boundary, witness, and SLA
are expressible without changing their meaning. Before authoring a batch at a
new locked pair, smoke-test package discovery from the external warehouse once.
Reuse that preflight result for every challenge in the batch. A missing shared
interface or semantic disagreement is an orchestration blocker: stop before
authoring rather than using another checkout or an uncommitted framework patch.

## Ordered gates

Use the cheapest gate that can still reject the work. A failure stops forward
progress until corrected; it does not create a persistent Stage 4 result.

### 1. Package and static gate

Create `stage4/warehouse` from the locked warehouse base. Sparse checkout may
materialize `_registry` and the new `<contributor>/<challenge>` package during
implementation. Implement the smallest importable package and registration row,
then run its unit tests, registration validation, and the canonical static
check.

Registration must validate the new row against its package. If the warehouse
validator requires every existing package, expand the checkout for that command
instead of treating sparse-checkout misses as challenge failures. Fix target
metadata errors before building an image.

### 2. Packaged vulnerability gate

Package the exact vulnerable revision and realistic configuration from Stage 3.
Before completing principal, objective, checker, or restart plumbing, replay the
selected attack chain from an attacker-shaped container and confirm that the
packaged service reaches the same Stage 3 witness.

Stop when packaging removes the vulnerability, changes the application-owned
boundary, requires startup network access, or invalidates the Stage 3 witness.

### 3. Arena lifecycle and build gate

Implement the locked SOP contract:

- provision distinct, equal-privilege baseline principals once per match and
  keep their credentials fixed for that match;
- use `plant`/`retrieve` for every store; READ and EXECUTE score through
  `submit_flag`, while WRITE scores through `claim_capability` using the
  authoritative-state observation path;
- converge fresh round context, proof material, and public target IDs;
- capture through the trusted facility vantage required by the normative model;
- rebuild from defender-edited source, replace the serving process, and preserve
  required application and objective state; and
- exercise the Stage 3 legitimate workflow through the external SLA checker.

Run the canonical build gate. Challenge probes use the framework-provided
`target.host` and named ports in both verifier and game contexts; they must not
call Docker APIs to repair framework addressing. Incompatible probe contexts
are an orchestration blocker.

### 4. Defense controls

Prove the checker rejects feature amputation and canned success responses, and
accepts the narrow repair while preserving the declared workflow. For an
EXECUTE objective, also retain the direct-WRITE negative control required to
show that a write primitive cannot forge the execution witness. These are
capability controls; do not generalize application-specific runtime fixes into
new workflow requirements.

### 5. Final live gates

Against the final warehouse commit and the locked orchestration commit, run the
canonical static, build, and game commands in order. Then run the packaged PoV
inside the attacker container using only attacker-visible inputs and require a
current-opponent submission or capability claim with outcome `ACCEPTED` for at
least one objective.

The generic game gate verifies deployment, cross-team reachability, and scoring
rails; it does not solve the challenge. It never replaces the accepted PoV.
After any correction, rerun the affected gate, then rerun all final gates at the
final warehouse commit.

## Persistent result

Keep one compact `stage4/result.json` completion manifest. Do not retain raw
gate output, intermediate pass reports, or per-fix summaries; independent
admission review reruns and preserves its own evidence. `pr-report.md` remains
the concise human handoff.

`result.json` has this fixed schema:

```json
{
  "schema_version": 1,
  "decision": "ready_for_review",
  "challenge": {
    "name": "challenge-kebab-name",
    "package": "contributor/challenge_snake_name"
  },
  "inputs": {
    "stage3_result": {
      "path": "artifacts/projects/OWNER__PROJECT/stage3/STUDY/result.json",
      "sha256": "64 lowercase hex characters"
    },
    "stage3_study": {
      "path": "artifacts/projects/OWNER__PROJECT/stage3/STUDY/STAGE3_STUDY.md",
      "sha256": "64 lowercase hex characters"
    },
    "orchestration_commit": "40 lowercase hex characters",
    "warehouse_base_commit": "40 lowercase hex characters"
  },
  "output": {
    "warehouse_commit": "40 lowercase hex characters",
    "pr_report": "artifacts/projects/OWNER__PROJECT/stage4/pr-report.md"
  },
  "checks": {
    "registration": {
      "status": "passed",
      "command": "exact command"
    },
    "static": {
      "status": "passed",
      "command": "exact command"
    },
    "build": {
      "status": "passed",
      "command": "exact command"
    },
    "game": {
      "status": "passed",
      "command": "exact command"
    },
    "controls": {
      "command": "exact command or retained reproduction entrypoint",
      "feature_amputation": "rejected",
      "canned_response": "rejected",
      "correct_hardening": "accepted",
      "direct_write": "not_applicable"
    },
    "pov": {
      "status": "accepted",
      "command": "exact attacker-container command"
    }
  }
}
```

All commits are full Git object IDs and all paths are repository-relative. The
`inputs.orchestration_commit` value must equal the pin in `SKILL.md`. The
warehouse worktree must be clean at `output.warehouse_commit`. Do not write
`ready_for_review` unless every required check has the literal outcome above and
the PoV received an accepted current-opponent outcome. For an EXECUTE objective,
`direct_write` must be `rejected`; otherwise it is `not_applicable`. Commands use
environment-variable names rather than embedding credentials or proof tokens.
Validate JSON syntax with `python3 -m json.tool stage4/result.json` before
handoff.
