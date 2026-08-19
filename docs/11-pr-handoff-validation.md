# PR handoff validation

**Status:** Missing pipeline stage.

The workflow produces a PR report but does not mechanically verify that the
final warehouse and registration branches are ready to submit.

Add a small handoff validator that checks clean worktrees, allowed diff scope,
registry metadata and referenced assets, package and registry tests, the exact
reviewed warehouse pointer, registration-only orchestration changes, and the
four-heading PR report. It should prepare PR bodies and stop before push unless
the user authorizes publication.
