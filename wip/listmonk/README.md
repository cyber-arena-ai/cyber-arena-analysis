# Listmonk curation artifacts

This directory persists the Listmonk Stage 1–3 evidence used to design and
evaluate the first challenge. The selected target is CVE-2026-62361 at commit
`171a597ff2f20e29dad9894418a4934f9ed30a58`, with the proposed scope
`secret.credential.read`.

## Contents

- `stage1/candidates.json` — retained Stage 1 shortlist output.
- `stage2/` — Listmonk source result, overlap analysis, Git windows, canonical
  semantic packet, and semantic review.
- `stage3/environment/` — exact vulnerable/fixed Docker recipes and raw build,
  startup, source, and image observations. Run `prepare.sh` in this directory to
  fetch the pinned source revisions before rebuilding.
- `stage3/sql-export/` — selected CVE-2026-62361 feasibility report,
  reproduction, manifest, and raw observations.
- `stage3/cross-list/` — retained CVE-2026-34584 feasibility study for a future
  separate challenge. It is not the current scoring target.
- `CURRENT_IMPLEMENTATION_COMPARISON.md` — pre-migration comparison against the
  partial warehouse implementation.
- `MIGRATION_QC.md` — migrated package contract, proof runs, and remaining
  orchestration incompatibilities.

Disposable source worktrees, Docker images, containers, and authentication
cookies were intentionally not copied from the original `/tmp` study. The
retained preparation scripts reconstruct the worktrees at exact commits.

The semantic review was originally produced from a byte-different packet whose
only differences were relocated provenance paths and the resulting source-file
hash. Its `source_packet_sha256` was rebound here to the canonical persisted
packet after confirming that repository, windows, checkpoints, components, and
advisory evidence were unchanged.

## Selected Stage 3 result

The SQL-export study is `ready_for_authoring`. It proves a protected credential
read through the vulnerable export path, shows the fixed comparison rejecting
the same protected-table access, preserves legitimate filtered export, and
rejects the unconfirmed SQL-write claim.

Runtime artifacts are retained here as work in progress. Once the challenge is
authored, verification-owned copies should move to `cyber-arena-orche`; this
directory remains the curation handoff.
