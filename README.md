# Cyber Arena challenge discovery

This repository contains the research pipeline for discovering and prioritizing
open-source cybersecurity challenge candidates. It combines GitHub project
discovery with retained OSV snapshots, reconstructs vulnerable Git windows, and
produces evidence packets for semantic review.

Start with [`scripts/challenge_research/README.md`](scripts/challenge_research/README.md).
The agent workflow is documented in
[`skills/auto-curate-oss-challenges/SKILL.md`](skills/auto-curate-oss-challenges/SKILL.md).
Planned vulnerability-source improvements are tracked in
[`docs/VULNERABILITY_SOURCE_ROADMAP.md`](docs/VULNERABILITY_SOURCE_ROADMAP.md).

Challenge implementation, runtime verification, and admission review remain in
the sibling `cyber-arena-orche` repository.

## Tests

```bash
uv run python -m pytest -q
```

The pipeline is Python-standard-library-only. The test suite requires `pytest`.
