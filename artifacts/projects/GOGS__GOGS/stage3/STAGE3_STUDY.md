# Gogs CVE-2026-52806 Stage 3 study

## Decision

`ready_for_authoring`. At exact checkpoint `e3bb4165dceb96b66053a067f9f3584302413a0e`, an ordinary authenticated repository owner can use Gogs' public branch, pull-request, and rebase-merge workflow to execute an attacker-selected command as the service process. The exact `internal/database/pull.go` repair hunk from `a9dbafbfd8e1020bacc626420238c01d75d03364` blocks the same probe without breaking an ordinary rebase merge.

## Target and observations

The retained Compose environment builds Gogs from source at `e3bb4165dceb96b66053a067f9f3584302413a0e`, with SQLite and Git in Alpine containers. The fixed control rebuilds that same checkpoint after applying only the upstream pull-request merge hardening hunk from `a9dbafbfd8e1020bacc626420238c01d75d03364`; this holds the UI, database, Git version, and public request sequence constant instead of conflating the repair with later Gogs changes.

Both images built, started, and returned HTTP 200 from `/healthcheck`. In each case, a separately provisioned second account was denied `/admin` with 403, yet could create its own repository, enable rebase, push branches, create a PR, and complete a normal rebase merge. The merged feature remained retrievable from the public raw-file route.

For CVE-2026-52806, the attacker pushed an option-like base branch whose `--exec` payload hashes a fresh process-only nonce and calls back to the attacker container. On the vulnerable image, the first PR in a fresh repository was created with 302 and exposed the rebase merge action; merge returned 500, but the independent callback contained the exact expected digest. The HTTP error alone is not treated as success. With the exact repair hunk, the identical flow merged with 302 and produced no callback.

The advisory's local-copy dependency is real. After the first malicious PR created the repository local copy, a second malicious PR creation against the same repository returned 500 in both images because `testPatch` took the existing-copy checkout path. The reliable trigger is therefore the first malicious PR in a fresh attacker-owned repository, not an arena-preseeded repository.

## Attack chain

The starting identity is an ordinary, non-site-admin user. The public chain is: authenticate; create a repository; enable pull requests and rebase merging; push a normal feature branch and a valid option-like base ref over Git HTTP; create the first PR in that fresh repository; choose “Rebase before merging”; reach `PullRequest.Merge`; and cross the boundary where `pr.BaseBranch` is passed to `git rebase` without an end-of-options marker. Git interprets the branch as `--exec`, and its shell executes the attacker-selected command in the Gogs process context. A later checkout fails and causes HTTP 500 only after execution.

The affected features are account authentication, repository creation, Git HTTP push and ref handling, repository advanced settings, compare/PR creation, the first-copy `testPatch` path, PR mergeability, rebase merge, and server-side Git invocation. The repair adds safe end-of-options handling to the merge commands; it does not require removing those features.

## Witness and authoring consequences

The confirmed scope is `host.command.execute`, mapped to CWE Technical Impact `execute_unauthorized_code_or_commands`. The witness meets the registered proof rule: an attacker-selected server-side command transforms a fresh nonce, and the independent attacker callback observes the result. There is one confirmed local tier; Stage 4 should add another flag only if a distinct, independently proved capability is intentionally planted.

The authorized baseline records the nonce digest at setup; unauthenticated requests cannot create a repository, the ordinary user cannot reach site administration, and a normal rebase emits no callback. The exploit recovers the transformed witness only through command execution. A bounded shortcut pass found no witness in `/.env`, the Gogs config path, `/backup/`, `/install`, or `/robots.txt`; the exposed profiler index returned 200 but did not reveal the nonce or provide the measured command capability. No shared/default credential is used for the service administrator.

Stage 4 must preserve the listed public features and verify them with fresh non-flag canaries. Its scored target must be reachable by an attacker-selected command, not by a public file, log, setup route, or fixed canned operation. The challenge must permit an ordinary user to create a fresh repository and must not have the checker or setup create a Gogs local copy for that attacker repository before the malicious PR. Merge HTTP status is never a flag witness. The checker should accept the narrow upstream end-of-options repair while rejecting feature amputation such as disabling Git push, PRs, rebase, repository ownership, or normal rebase merging. A randomized normal PR/rebase probe and an independent randomized command witness are the minimum functionality and exploit invariants.
