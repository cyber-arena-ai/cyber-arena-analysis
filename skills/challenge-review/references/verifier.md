# Canonical verifier

## Objective

Use the verifier from the recorded orchestration commit as the sole authority
for challenge discovery, imports, Docker build, and mini orchestration.

## Exact command

The root agent runs this wrapper once in execution mode:

```text
python3 <skill-root>/scripts/run-verifier.py <challenge-id> \
  --warehouse <absolute-warehouse-path> \
  --context <run-dir>/context.json \
  --repo-root <orche-root> \
  --output <run-dir>/verifier.json \
  --execute
```

The wrapper creates an isolated worktree at the recorded orchestrator commit,
passes the selected warehouse to orchestration before startup, serializes shared
Docker access, and cleans up afterward. It runs these canonical tiers in order:

```text
python -m challenges.check <challenge-id> --json
python -m challenges.check <challenge-id> --build --ready-timeout 150 --json
python -m challenges.check <challenge-id> --game --ready-timeout 150 --json
```

Acceptance uses `--execute`; `--dry-run` output is not evidence. Preserve
`verifier.json`; do not paste its full output into the human report.

`verifier.json` records the review run ID, pinned orchestrator commit, and
selected warehouse path. After the build tier, the wrapper also resolves the
image reference
reported by the canonical checker and records Docker's immutable image ID as
`image_hash`. A passing verifier requires `sha256:<64 lowercase hex>`; a mutable
tag alone is not provenance. After the static tier, the wrapper also freezes
the selected package's authoritative objective matrix as `{store, outcome,
scope, oracle}` rows. Copy that matrix and the image hash into `review.json`;
the report validator binds both back to this artifact.

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

The mini game starts, probes both teams, and every emitted final
health/functionality leaf passes. Distinguish a broken challenge workflow from
unavailable external runtime infrastructure.

### `VERIFY-FLAG`

The build tier round-trips handler placement and retrieval for every declared
store. For WRITE, that round trip covers the integrity anchor; the tier also
checks authoritative-region readability and absent-mark behavior. The game tier
checks live placement, scoring rails, and packaged PoV evidence when available.

### `VERIFY-RESTART`

The build tier invokes the declared restart handler, reruns functionality, and
confirms planted flags remain retrievable.

## Interpretation

- `PASS`: all three canonical tiers pass and support every verifier check.
- `FAIL`: a tier exposes a reproducible challenge defect. In an `ALL` review,
  this is a hard `REJECT`; later stages are `NOT_RUN`.
- `BLOCKED`: external review infrastructure prevents the canonical procedure.

Report the failed or blocked component, exact observed fact, and `verifier.json`
location. Do not turn omitted challenge dependencies or broken challenge
configuration into an infrastructure blocker.
