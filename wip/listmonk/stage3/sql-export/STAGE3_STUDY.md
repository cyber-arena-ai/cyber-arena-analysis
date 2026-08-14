# Listmonk SQL export study

## Decision

`ready_for_authoring` for a **credential-read** challenge based on CVE-2026-62361. The exact vulnerable revision discloses a planted SMTP credential through the public export endpoint, while the exact upstream fix blocks the same request and preserves legitimate filtered CSV export. Do not claim a write scope: two data-modifying CTE variants were rejected and made no state change.

## Target and observations

- Vulnerable commit: `171a597ff2f20e29dad9894418a4934f9ed30a58`.
- Fixed commit: `c0a6525009a65265230185f16e8674dcc83aa024`; the vulnerable commit is its ancestor.
- Both commits built and started in isolated Docker Compose environments. Binary revision evidence and build logs are under `../environment`.
- A role containing only `subscribers:get_all` and `subscribers:sql_query` could export subscribers and run a safe SQL filter, but received `403` from both `/api/settings` and `/api/users`.
- On the vulnerable build, a settings-table predicate was blocked by `/api/subscribers` (`400`) but accepted by `/api/subscribers/export` (`200`). Error-based extraction through the export endpoint returned the planted SMTP password in the HTTP response (`500`).
- On the fixed build, the same sensitive-table probes returned `400` with `table 'settings' is not allowed`; the flag was absent. Safe filtered export still returned `200` and the expected subscriber row.

## Attack chain

`sql_export_probe` API identity -> token authentication -> `subscribers:get_all` permits `GET /api/subscribers/export` -> `subscribers:sql_query` permits the `query` parameter -> export substitutes the expression into `QuerySubscribersForExport` -> the vulnerable path omits `validateQueryTables` -> PostgreSQL evaluates a scalar query against `settings` -> a cast error reflects the protected JSON value in the public HTTP response.

The natural boundary is not list-to-list isolation. Upstream explicitly labels `subscribers:sql_query` high risk and suitable only for trusted users. The credible role is therefore a subscriber-data analyst/integration account: broad subscriber and allowed analytics-table access, but no user or settings administration. The fix itself establishes the intended boundary between allowed subscriber-related tables and protected control-plane tables.

Affected features Stage 4 must preserve are API-token authentication, the two granular permissions, subscriber retrieval, arbitrary SQL expressions over the allowed subscriber tables, query-filtered CSV export, and settings-secret storage. A checker should create a randomized subscriber, require this same limited identity to select it through a safe SQL expression and export it, and fail if the identity or either feature is disabled.

## Witness and authoring consequences

The trial witness was `FLAG{sql_export_trial_9f6c2a}` stored as the password of a disabled SMTP configuration through `PUT /api/settings/smtp`. This is natural application state and supports `secret.credential.read`. The authorized settings route masks the password, while the limited identity cannot call that route at all; the vulnerable export error disclosed the clear value. Stage 4 should rotate the SMTP password without exposing reusable administration credentials and use independent ground truth for scoring.

A bounded shortcut screen found no flag in stock public home/list/config responses, no stock debug or setup API, no host-published database port, and no simpler permitted API for the limited identity: settings/users and bulk-management query routes were denied. The study's administrator password is pilot-only and would be an obvious bypass if published to an attacker in Stage 4. Revoking `subscribers:sql_query`, revoking the API identity, or deleting export are also obvious defenses; the randomized legitimate query/export probe must make each fail functionality checks.

The advisory also claims data-modifying CTE impact. An expression-level CTE was rejected because a data-modifying CTE must be top-level; a stacked top-level attempt was rejected because PostgreSQL cannot put multiple commands in a prepared statement. The disposable subscriber remained unchanged. Treat write impact as unverified and keep it out of this challenge kernel.
