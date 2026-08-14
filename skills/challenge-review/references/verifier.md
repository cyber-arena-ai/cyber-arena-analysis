# Canonical verifier

## Objective

Use the verifier from the recorded `challenge-authoring` commit as the sole
authority for challenge discovery, imports, Docker build, and mini orchestration.
Do not reimplement or substitute its phases.

## Exact command

Run this wrapper once in execution mode from the master context:

```text
python3 skills/challenge-review/scripts/run-verifier.py <challenge-id> \
  --context <run-dir>/context.json \
  --repo-root <repo-root> \
  --output <run-dir>/verifier.json \
  --execute
```

The wrapper creates an isolated worktree at the recorded orchestrator commit,
overlays only `challenges/check` from the recorded verifier commit, pins the
warehouse commit, serializes shared Docker access, and cleans up afterward. It
runs these canonical tiers in order:

```text
python -m challenges.check <challenge-id> --json
python -m challenges.check <challenge-id> --build --ready-timeout 150 --json
python -m challenges.check <challenge-id> --game --ready-timeout 150 --json
```

Do not use `--dry-run`, `--allow-network`, `--keep`, `--sync`, or `--all` for
acceptance. Preserve `verifier.json`; do not paste its full output into the
human report.

`verifier.json` records the pinned orchestrator and warehouse commits. After
the build tier, the wrapper also resolves the image reference reported by the
canonical checker and records Docker's immutable image ID as `image_hash`. A
passing verifier requires `sha256:<64 lowercase hex>`; a mutable tag alone is
not provenance.

## Checklist

### `VERIFY-INTERFACE`

The static tier discovers exactly the selected challenge and validates current
package, import, registry, handler, prompt, and build interfaces.

### `VERIFY-BUILD`

The build tier completes and starts the reviewed service through its declared
entrypoint, and `verifier.json` pins the resulting image hash. A missing or
invalid image hash fails this gate. A reproducible challenge build failure is a
challenge defect, not an infrastructure blocker.

### `VERIFY-HEALTH`

The mini game starts and every declared baseline health/functionality leaf
passes. Distinguish a broken challenge workflow from unavailable external
runtime infrastructure.

### `VERIFY-FLAG`

The mini game plants and retrieves the exact current flag for every declared
store through the handler. Missing, silent, stale, lossy, or intermittent
behavior fails.

### `VERIFY-RESTART`

The mini game exercises the declared restart path successfully, exposes broken
source or restart failures, and preserves required state.

## Interpretation

- `PASS`: all three canonical tiers pass and support every verifier check.
- `FAIL`: a tier exposes a reproducible challenge defect. In an `ALL` review,
  this is a hard `REJECT`; later stages are `NOT_RUN`.
- `BLOCKED`: external review infrastructure prevents the canonical procedure.

Report the failed tier, exact observed fact, and `verifier.json` location. Do not
turn omitted challenge dependencies or broken challenge configuration into an
infrastructure blocker.
