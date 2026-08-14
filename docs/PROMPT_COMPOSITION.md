# Agent Prompt Composition

What text the competing agent actually receives, and where each part comes from
in code. The agent's context is **four layers**, but only two are ours to write
per challenge:

| Layer | What | Who provides it |
|---|---|---|
| **S0** | The CLI's own system prompt (claude/codex/opencode) | the vendor CLI — we don't touch it |
| **S1** | The **MCP tool schema** — every tool's name, arguments, and return shape | auto-injected by the MCP server (`gamemgr/mcp_server.py`) when the CLI connects; the model reads it directly |
| **L1** | The **shared briefing** — game rules, strategy, tool roster, the SSH/patch mechanic | framework, identical for every challenge (`agents/prompts/_l1.py`) |
| **L2** | The **per-challenge briefing** — service brief, source map, connection facts, hint | the challenge (`challenges/<pkg>/prompts.py::build_advanced_prompt`) |

The prompt we hand the agent (its single opening user turn, re-sent verbatim on
any supervised restart) is **L1 + L2**. Tool mechanics live in S1, so neither L1
nor L2 restates a tool's arguments or returns — they only *name* the tool.

## The formula (async mode — the only mode that ships)

```
AgentConfig.system_prompt = build_async_prompt(
    cfg, service_name=..., total_rounds=..., round_min=..., hint=...)

build_async_prompt  =  render_tools( build_l1(cfg, total_rounds, round_min)
                                     + "\n\n"
                                     + mod.build_advanced_prompt(cfg, service_name, hint),
                                     cfg )
```

- `build_l1` (`agents/prompts/_l1.py`) returns the shared briefing, byte-identical
  across challenges except the four config slots it fills by `str.replace`:
  `{team_id}`, `{total_rounds}`, `{round_min}`, `{own_prod_host}`.
- `mod` is the challenge's prompt module, resolved from `_PROMPT_MODULES`
  (`agents/prompts/__init__.py`) by `service_name` (== `Challenge.name`). Its
  `build_advanced_prompt(cfg, *, service_name, hint)` returns the L2 body
  (SERVICE / SOURCE MAP / CONNECTION FACTS / ending), filling `{opposing_host}`
  and `{service_name}`. The ending is the challenge's `Hint:` line when
  `hint=True`, else the fixed no-hint sentence.
- `render_tools` (`agents/prompts/_helpers.py`) rewrites every canonical tool
  name to the running provider's form, so L1 and L2 can write tool names in one
  canonical backticked style (`` `submit_flag` ``) and stay provider-agnostic:

  | provider | `submit_flag` renders as |
  |---|---|
  | claude (default) | `mcp__cyberarena__submit_flag` |
  | codex | `submit_flag` (bare) |
  | opencode | `cyberarena_submit_flag` |

## Config + difficulty plumbing (`gamemgr/game_mgr.py`)

`async_agent_config_for(team_id)` picks the team's deployed challenge, then
`_system_prompt_for(cfg, service_name)` supplies the run parameters and calls
`build_async_prompt`:

- `total_rounds` and `round_min` come from `RoundConfig` (`round_secs // 60`);
- `hint` comes from the challenge's game.yaml **`ChallengeConfig.level`** —
  `level: hard` → `hint=False` (no-hint sentence), anything else → the `Hint:`
  line.

**Setting it in a game.yaml.** `level` is a per-challenge field (default
`"easy"`), a sibling of `deploy_on` under `challenges:`. Omit it (or `easy`)
for the hinted briefing; set `hard` to drop the hint so the agent must find the
vulnerability unaided:

```yaml
challenges:
  - name: 8-bit-oracle
    type: 8-bit-oracle
    port: 17280
    deploy_on: [team1, team2]
    level: hard          # default "easy" (hinted); "hard" = no hint
```

The `config/v3_example/*.yaml` configs carry this as a commented-out line for
reference.

The per-team `AgentConfig` fields spliced into L1/L2 (`team_id`,
`own_prod_host`, `opposing_prod_hosts`, `team_token`, `submit_url`,
`mcp_endpoint`, `provider`/`model`) are set here before the prompt is built.

## Async-only

There is no separate ATTACK / DEFENSE prompt and no `WRONG_PHASE` gate: attack
and defense run simultaneously for the whole game. The retired sync per-phase
config builders (`attack_agent_config_for` / `defense_agent_config_for`) delegate
to the same `_system_prompt_for`, so there is exactly one prompt path.

## Adding a new challenge's prompt

1. Write `challenges/<pkg>/prompts.py` exposing
   `build_advanced_prompt(cfg, *, service_name, hint=True)` that returns the L2
   body — SERVICE, SOURCE MAP, CONNECTION FACTS, and a one-line `Hint:` —
   following the standard in [CHALLENGE_AUTHORING_SOP.md](CHALLENGE_AUTHORING_SOP.md)
   (no vulnerability class, hotspot, exploit, patch, flag location, or equivalent
   answer material in either hint variant). Keep tool names canonical and
   backticked; `render_tools` handles providers.
2. Register `"<challenge-name>": "challenges.<pkg>.prompts"` in `_PROMPT_MODULES`.
3. That's it — L1 is shared, and S1 (tool mechanics) is injected automatically.
