# Semantic repair boundaries

**Status:** Stage 2 and Stage 3 linkage must change.

An advisory may identify a release merge or version bump rather than the commit
that actually repairs the vulnerability. Using its parent can therefore select
an already-patched Stage 3 baseline.

Stage 2 should retain the reported boundary while recording the semantic fix,
its vulnerable parent, boundary kind, and evidence. It should select an explicit
`study_commit`. Stage 3 validation must bind to the semantic review and require
that selected commit rather than relying only on the source packet checkpoint.
