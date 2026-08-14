# Listmonk CSV import cross-list study

## Decision

`ready_for_authoring`. CVE-2026-34584 has a small, natural authorization
boundary and reproduced as a persistent cross-list write at commit
`171a597ff2f20e29dad9894418a4934f9ed30a58`. The upstream import-handler fix
blocks the same request while preserving an authorized import.

## Target and observations

The selected checkpoint is the first parent of upstream fix
`347f5976759232c36e571cf58b4bfe33c2794f35`. It ran in an isolated Docker
network with no host ports. A separate client container used only HTTP.

An API user holding `subscribers:import` and `list:get`/`list:manage` on only
Field Reports could see list 3 and not protected Partner Signups list 4. On the
vulnerable build, importing one CSV row into either ID returned 200 and
finished with one row imported. Independent database observation found the
second row attached to protected list 4. With the exact `cmd/import.go` from
the upstream fix, list 3 still imported successfully while list 4 returned 403
and created no subscriber or membership.

## Attack chain

`ops-analyst` authenticates with its own API token, sends a multipart CSV to
`POST /api/import/subscribers`, and passes the `subscribers:import` middleware.
The vulnerable handler trusts `params.lists`; the asynchronous importer uses
those IDs in its subscriber upsert and persists a `subscriber_lists` row for a
private list the identity cannot see or manage. The resulting scope is
`app.cross_boundary.write`.

The affected features are API-token authentication, scoped list roles, list
visibility, multipart CSV upload, subscriber import/status handling, and
persistent subscriber-to-list membership. These are the behaviors Stage 4
must exercise rather than accepting service liveness alone.

## Witness and authoring consequences

The trial witness is a randomized subscriber email/name inserted into a
checker-owned private list. An authorized observer verifies the resulting
membership; the attacker neither needs nor receives protected-list read
access. For a write-scope challenge, the round-specific value should be an
action nonce that the checker expects inside the protected membership, not a
secret exposed elsewhere for retrieval.

The future checker should rotate the private target list and nonce, assert an
authorized import into the caller's own list, assert list visibility remains
scoped, and independently observe the protected membership. This makes
disabling CSV import, breaking per-list roles, or returning canned success an
obvious failure.

A bounded HTTP screen found no ordinary second write path for this identity:
protected-list read, subscriber query, direct subscriber creation, and bulk
list management were denied; the public subscription form rejected the private
list. Stage 4 still needs its normal adversarial review and must provide the
target list locator without granting protected read access.
