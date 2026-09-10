# Corpus

What varies across the retained Stage 3 studies. Read it so a difference does
not read as a fault. Nothing here asks for an output.

## `result.json` has several incompatible shapes

The reproduced revision is in whichever of `reproduced_commit`, `commit`, or
`vulnerable_commit` is present. `primary_commit` and `repair_commit` are
different things and are not it. Some studies retain no `result.json` at all.

`repository` is not a reliable source for the output path: its casing and
punctuation do not match the directory names, and some studies omit it.

## Headings are not guaranteed

The attack chain and the witness and authoring consequences are the semantic
source, and usually sit under headings named for them. Several studies name
those sections differently or use a different heading level, and some have no
section by either name. Locate the material by content; a missing heading is
not a reason to stop.

## Studies differ in what they retained

There are 34 studies and no single bundle shape. 30 hold a Dockerfile or
compose file, a reproducer, and an `evidence/` directory together in the study
directory. The rest vary, so establish what a study has by looking rather than
by pattern:

- **Prose only.** `VIKUNJA__VIKUNJA/stage3` is `STAGE3_STUDY.md` alone;
  `GRAFANA__GRAFANA/stage3` adds only `result.json`. Neither has a target to
  stand up, and the second looks like a bundle study until you check.
- **Bundle in a sibling.** `KNADH__LISTMONK/stage3/cross-list` has a reproducer
  and `evidence/` but no Dockerfile; its `environment.txt` points at a sibling
  directory.
- **A differently named reproducer.** `APACHE__ACTIVEMQ/stage3/activemq-cve-2026-34197`
  ships `reproduce.sh`, not `reproduce.py`.

A study directory may be the `stage3/` directory itself, or a named
subdirectory of it. `<study-name>` is its basename either way, which for the
former is `stage3`.

## Any outcome is in scope

`outcome` is a Stage 3 authoring verdict, not a graph property. A graph over a
`rejected` study still shows why it was rejected, so no outcome is refused and
none is agreed or disagreed with.

## Bundles are not uniform

`reproduce.py` may or may not accept `--keep`. Some are hermetic and tear down
every image on exit. Where `--keep` exists it retains the services but not the
credentials, which are generated per run.
