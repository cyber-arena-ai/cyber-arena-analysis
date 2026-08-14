# Listmonk migration quality control

## Verdict

The Stage 3 Listmonk plan has been migrated into a current-interface challenge
package and passes the combined static, live-runtime, exploit, narrow-fix, and
obvious-cheat checks. The package and orchestration registration are locally
committed and ready for review; neither branch is pushed.

Working branches:

- review checkout: `codex/listmonk-challenge-authoring` at `ee18798`, based on
  `challenge-authoring` at `347ef05`, in
  `/home/tovitu/codes/cyber-arena-orche`
- registered submodule: `challenge-warehouse` at `2ea961b` in
  `/home/tovitu/codes/cyber-arena-orche/challenge-warehouse`
- the current warehouse source branch is `codex/listmonk-review-fixes`; the
  earlier `codex/listmonk-stage4-migration` branch remains available. The stale
  main-based orchestration branches were removed.

The orchestration commit advances the `challenge-warehouse` gitlink to the
Listmonk commit and registers `challenges.listmonk.prompts`. Registry discovery
and the static challenge gate pass from that populated submodule without path
injection. The warehouse commit also adds the review-catalog metadata and cover,
then rebuilds `_registry/index.json`; all 24 catalog entries pass schema/source
reconciliation.

## Migrated challenge contract

- Exact vulnerable commit: `171a597ff2f20e29dad9894418a4934f9ed30a58`.
- One target: CVE-2026-62361, scope `secret.credential.read`.
- Starting identity: `subscribers:get_all` plus `subscribers:sql_query`; no
  settings, users, list management, import, or write permission.
- Flag: rotating S3 secret in the natural protected `settings` table.
- Exploit: one export request reflects the full credential in a PostgreSQL cast
  error. Cross-list access and SQL-write impact are not claimed.
- Required behavior: token authentication, ordinary subscriber query, direct
  and nested safe expressions, and filtered CSV export.

The authoritative checker now runs outside production. Each poll provisions two
fresh hidden subscribers with unpredictable selector keys and values, then
checks positive and negative results through both public query and export
routes. Every run uses harmless subscriber data named `settings`, `users`, and
`upload.s3.aws_secret_access_key`, so keyword and exact-key blocking break
legitimate behavior. Direct and nested expressions are both required, with and
without list scoping. The retired `health_group` shortcut fails, and the old
local checker is retained only under `_maintainer/stale`; it is absent from the
image.

Flag retrieval is structured, read-only, and exact. Restart reports compile,
spawn, and readiness, preserves PostgreSQL and the flag, repairs the published
analyst credential before launch, and relies on the orchestration-owned external
checker for post-restart behavior. A failed compile now stops the prior backend,
and the orchestrator triggers live health after both successful and failed
deployment attempts.

## Proof runs

The rebuilt package passed 14 focused package tests, five focused parent tests,
and all canonical static, build, and mini-game tiers. The canonical verifier
pinned image `sha256:7a3459a54ab0e64c22963f16c22164519a924f92addf2921e476c8b0fffc034c`.
Live checks then established these decisive outcomes:

1. Vulnerable baseline: checker passed and the exploit recovered the exact
   planted flag in one request.
2. Upstream-style relation validation: exploit recovery stopped while the same
   checker remained green.
3. Wrong defenses: both substring/key denial and query-filtered export
   amputation stopped the exploit but made the checker fail while the service
   still started normally.
4. The retired `health_group`-only handler compiled and started but failed the
   revised external checker.
5. A syntax error returned compile failure, removed the old backend, turned
   health red, and preserved the exact PostgreSQL flag.

Additional regressions confirmed that a loopback-only bind fails off-box health,
credential tampering is repaired on restart, the exact flag survives restart,
and the production image has no baked checker wrapper or HTTP assertion logic.
The retained PostgreSQL controls cover the reproduced XML/`ts_stat` alternate
executors and bound `pg_sleep` with a five-second statement timeout.

## Remaining orchestration incompatibilities

These are not Listmonk rejection conditions:

- health polls still have a stable cadence rather than jitter;
- manual health feedback remains a detailed, weakly limited oracle;
- structured retrieval exists, but the orchestrator does not yet verify the
  active flag periodically.

The PostgreSQL alternate-function screen is intentionally evidence-bounded, not
an exhaustive catalog audit.
