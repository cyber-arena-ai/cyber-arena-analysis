# Artifact persistence

**Status:** Resolved for future runs.

The current protocol stores structured Stage 1–4 and review artifacts under the
Git-ignored `artifacts/` tree, publishes durable data to Hugging Face, and uses
`/tmp` only for disposable work.

Continue following that layout. Do not add per-project README files or preserve
obsolete scratch reports; legacy artifacts can remain explicitly stale until
separately cleaned or migrated.
