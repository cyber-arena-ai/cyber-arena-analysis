# Cyber Arena agent guide

## Mission

Cyber Arena is an attack/defense benchmark for measuring how far an agent can
advance through a general security-capability ladder against a realistic,
pinned OSS application. A challenge is the application and its security
boundaries, not a prescribed CVE exercise. A known vulnerability proves a
reachable floor; it must not constrain other genuine attack paths or stronger
capabilities an agent may discover.

Score concrete outcomes across application-enforced boundaries. Do not score
availability failures, infrastructure access, leaked facility state, or direct
access to proof material. Defenses may harden the service in any way that
preserves the declared functional behavior; canned responses and feature
amputation are not valid defenses.

Before changing challenge semantics, scoring, evidence, lifecycle, prompts, or
health checks, read the complete normative model at
`~/codes/cyber-arena-docs/docs/challenge-model.md`.

## Repository topology

The expected sibling checkouts under `~/codes/` have distinct ownership:

| Checkout | Owns | Does not own |
|---|---|---|
| `cyber-arena` (remote: `cyber-arena-analysis`) | Candidate discovery, curation, challenge creation/review skills, lightweight workflow notes, and ignored evidence under `artifacts/` | Challenge packages and arena runtime |
| `challenge-warehouse` | Challenge implementations under `<contributor>/<challenge>/` and challenge-specific provenance | Shared interfaces and orchestration |
| `cyber-arena-orche` | Runtime, shared challenge interfaces, verifier, Docker/network topology, agents, game loop, and authoring SOP | The canonical source of standalone challenge packages |
| `cyber-arena-docs` | Public, normative challenge design and invariants | Private candidate notes, exploit details, proof material, and challenge-specific internals |

`cyber-arena-orche` consumes `challenge-warehouse` as the
`challenge-warehouse/` Git submodule. It extends `challenges.__path__` with each
contributor directory, so `<contributor>/<challenge>/` imports as
`challenges.<challenge>`. The contributor directory is organizational only.
The framework auto-discovers challenge packages; do not add a manual registry
entry to orchestration.

Do not assume the standalone warehouse checkout and the orchestrator submodule
point to the same commit. Creation and PR handoff record both SHAs and test the
exact warehouse revision intended for submission. Review instead requires an
explicit warehouse path argument and tests that filesystem directly. Updating
the warehouse and advancing the orchestrator's submodule pointer are separate
changes.

## Sources of truth

Use this precedence when sources disagree:

1. `cyber-arena-docs/docs/challenge-model.md` is normative for challenge
   semantics and benchmark invariants.
2. Live code and non-archived docs in `cyber-arena-orche` define the currently
   implemented interfaces, topology, and commands.
3. This repository's skills and references define the curation and admission
   workflows.
4. Archived plans and local analysis notes provide history only.

Do not silently implement around a conflict between the normative model and
the current runtime. State the mismatch, identify which repository owns the
fix, and make the smallest coordinated change that resolves it. Keep links to
maintained material instead of copying it between repositories.

## Working rules

### Challenge creation

- Use `skills/challenge-create/SKILL.md` for the staged discovery-to-handoff
  workflow. Read every required reference and the complete orchestrator
  authoring SOP before authoring.
- Retain curation and review evidence under this repository's ignored
  `artifacts/projects/<OWNER>__<PROJECT>/` tree. Put disposable clones, build
  trees, containers, and failed experiments in `/tmp`.
- During parallel challenge work, assign each challenge one owning write agent,
  one warehouse worktree, and one `artifacts/projects/<OWNER>__<PROJECT>/`
  directory. Supporting agents may inspect the work but must return evidence to
  the owner instead of editing its worktree. Use unique Docker names for
  concurrent challenge and review runs.
- Implement a challenge only in `challenge-warehouse/<contributor>/<challenge>/`.
  Each package exports exactly one concrete `Challenge` subclass, uses a
  globally unique kebab-case `Challenge.name`, and provides `build.py` with
  `build_image()`.
- Derive objectives from the pinned application's asset graph and baseline
  principal, never from the selected vulnerability. Keep the upstream runtime
  and authorization behavior faithful; deployment or probes must not invent
  the boundary being scored.
- Keep prompts attacker-safe: explain legitimate use, connection details,
  editable source, and available actions without revealing the advisory,
  vulnerability class or location, exploit, fix, credentials, proof material,
  store, or private facility state.
- Change orchestration only for a genuine shared-framework requirement. Keep a
  framework change separate from the challenge package change and test them
  together against explicit commits.

### Challenge review

- Use `skills/challenge-review/SKILL.md` for exactly one registered challenge
  and one requested stage, or `ALL`. A review gathers and adjudicates evidence;
  it does not fix the reviewed challenge.
- Treat the canonical verifier as a gate, then keep static, cheat, and
  exploitability evidence independent as the review protocol requires.
- Never use host Docker access, victim files or databases, facility secrets,
  private handler state, or known proof values as attacker evidence.
- Preserve only the minimum reproducible evidence required by the skill. State
  unknowns and unresolved risks explicitly; do not turn assumptions into
  findings or passing claims.

### Infrastructure and documentation

- Make runtime, interface, verifier, network, game-loop, or agent changes in
  `cyber-arena-orche`. Update its corresponding live design documentation when
  a major design boundary changes; do not edit archived plans.
- Make public design changes in `cyber-arena-docs`. Before publishing, confirm
  the text is safe for an evaluated agent to read. Challenge selection notes,
  exploit material, and objective-placement details stay private.
- Do not duplicate shared interface code inside a challenge or move a
  challenge implementation into orchestration.

## Verification

Run the narrowest relevant check first, followed by the complete check required
for the affected boundary.

From `cyber-arena`:

```bash
python3 -m pytest -q skills/*/tests
```

For one challenge, run the orchestrator's canonical gates against the explicitly
selected warehouse checkout:

```bash
CYBERARENA_CHALLENGE_WAREHOUSE=/absolute/path/to/challenge-warehouse \
  python -m challenges.check <challenge> --json
CYBERARENA_CHALLENGE_WAREHOUSE=/absolute/path/to/challenge-warehouse \
  python -m challenges.check <challenge> --build --ready-timeout 150 --json
CYBERARENA_CHALLENGE_WAREHOUSE=/absolute/path/to/challenge-warehouse \
  python -m challenges.check <challenge> --game --ready-timeout 150 --json
```

The static gate does not prove the image, live handlers, restart, health,
cross-team reachability, or exploit path. Build and game gates require Docker;
passing all generic gates still requires the independent admission review.

For orchestration changes, run the smallest relevant test module during
iteration and `pytest` for the full suite before handoff when feasible. For
public documentation changes:

```bash
uv venv
uv pip install --python .venv/bin/python -r requirements.txt
.venv/bin/mkdocs build --strict
```

In the handoff, report the repositories and exact commits tested, commands run,
results, remaining `NOTE`s or untested live paths, and any intentional
cross-repository dependency.
