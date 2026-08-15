# Cyber Arena Analysis

This repository is the permanent home for Cyber Arena challenge curation and
admission-review workflows. It contains the contribution contract, portable
agent skills, and the artifact data contract. Challenge implementation and
orchestration code remain in `cyber-arena-orche`.

## Workflows

- [`challenge-create`](skills/challenge-create/SKILL.md):
  discover candidates, reconstruct historical Git windows, perform semantic
  triage, run a focused feasibility study, author and register the challenge in
  `cyber-arena-orche`, and prepare the handoff.
- [`challenge-review`](skills/challenge-review/SKILL.md): independently review
  one registered challenge. Claude Code is recommended for final admission;
  Codex remains a supported fallback.
- [`CONTRIBUTING.md`](CONTRIBUTING.md): challenge selection and design contract.

The skills bundle their operational scripts and references.

## Retained artifacts

```text
artifacts/
├── sources/                  # current project catalog and OSV corpus
├── candidates.json           # current shortlist
└── projects/OWNER__PROJECT/
    ├── stage2/
    ├── stage3/
    ├── stage4/
    └── review/
```

`artifacts/` is a Git-ignored local workspace for data, not repository source.
We recommend publishing its stable structure to a Hugging Face dataset for
durable storage and history. Do not commit artifact contents to this repository.
Disposable clones, build trees, containers, and failed experiments belong in
`/tmp`.

## Tests

The workflow code is Python-standard-library-only. With `pytest` available:

```bash
python3 -m pytest -q skills/*/tests
```
