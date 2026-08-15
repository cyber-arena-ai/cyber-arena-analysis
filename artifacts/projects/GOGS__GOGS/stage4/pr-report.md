## Source and service

The candidate came from the retained OSV source corpus's GIT and Go records for
[CVE-2026-52806 / GHSA-qf6p-p7ww-cwr9](https://github.com/gogs/gogs/security/advisories/GHSA-qf6p-p7ww-cwr9).
It packages [Gogs](https://github.com/gogs/gogs), a self-hosted Git service used
by individuals and teams to host repositories and collaborate through Git and
pull requests, at exact vulnerable revision
[`e3bb4165dceb96b66053a067f9f3584302413a0e`](https://github.com/gogs/gogs/commit/e3bb4165dceb96b66053a067f9f3584302413a0e).
The retained project catalog reported 47,692 GitHub stars; the retained Stage 1
artifact does not record the catalog's observation timestamp.

## Vulnerability and patch

An ordinary repository owner can push an option-like base ref, create the first
pull request in a fresh repository, and choose rebase merge. The vulnerable
pull-request path passes the attacker-controlled base ref to `git rebase`
before an end-of-options marker, so Git interprets it as `--exec` and runs an
attacker-selected command as the Gogs service process. Upstream patched the
issue in
[`a9dbafbfd8e1020bacc626420238c01d75d03364`](https://github.com/gogs/gogs/commit/a9dbafbfd8e1020bacc626420238c01d75d03364)
by separating option parsing from attacker-controlled refs in the relevant Git
merge, rebase, and checkout operations. The exact repair blocks command
execution while preserving normal rebase merges.

## PoC

The public PoC registers its own non-admin user, creates a genuinely fresh
repository, enables rebase merging, pushes the required refs over Git HTTP,
opens the first malicious pull request, and invokes rebase merge. Its selected
command transforms the protected value and returns it over a callback before
submission; an HTTP 500 response is never counted as success. The vulnerable
and fixed observations are retained in
[`evidence/vulnerable.txt`](../stage3/evidence/vulnerable.txt) and
[`evidence/fixed.txt`](../stage3/evidence/fixed.txt). The authored flow remains
in the separate challenge implementation workspace.

## Flags and capabilities

The challenge plants one rotating store, `host.command.execute`, as a protected
audit-signing key readable by the Gogs service process at
`/srv/gogs-data/protected/audit-signing-key`. Recovering it through the
victim-originated command callback proves the registered
`host.command.execute` capability and the CWE Technical Impact
`execute_unauthorized_code_or_commands`. Merely reading a file or observing a
merge error does not prove this scope.
