# Challenge Authoring SOP

Package a vulnerable application into a CyberArena challenge as one
self-contained `challenges/<snake_name>/` directory. Reference:
`challenges/nautilus_ico/` in `cyber-arena-orche` (DEF CON Finals 2025 `ico`).
Interface ABCs live at `challenges/interface/` in that repository.

This SOP is the authoring contract. The sibling `challenge-review` skill defines
the evidence and verdict rules used to review a registered implementation.

## 1. Layout

```
challenges/<snake_name>/
├── __init__.py                # must — exports the Challenge class
├── challenge.py               # must — composition root
├── prompts.py                 # must — challenge-specific L2 briefing
├── build.py                   # must — docker build of the image
├── functionality_test.py      # recommended — FunctionalityTest impl (liveness)
├── checker.py                 # optional — network CHECKER (see §3.5); PREFERRED
├── flag_handler.py            # recommended — FlagHandler impl
├── restart_handler.py         # recommended — RestartHandler impl
├── _maintainer/
│   └── README.md              # must for new contributions — research evidence
├── flag_facility_setup.sh     # optional — flag-service facility deps (see §3.2)
├── health_facility_setup.sh   # optional — health-poller facility deps (see §3.2)
└── image/                     # docker build context
    ├── Dockerfile             # must
    ├── entrypoint.sh          # must
    ├── restart.sh             # must — framework-invoked rebuild + respawn
    ├── checker.sh             # optional — in-prod CHECKER, un-baked (see §3.5)
    └── service/               # recommended — baked source / binaries
```

Recommended Python files can be inlined into `challenge.py` if your
challenge is small. The surfaces they implement are still required —
see §3.

`_maintainer/README.md` is the canonical non-agent-facing record for upstream
provenance, the pinned revision, vulnerability reachability, and each flag
store's scope, tier, and proof requirement. Existing package-level READMEs may
retain this role until migrated.

## 2. Naming

| What | Style | Example | Used as |
|---|---|---|---|
| Directory | `snake_case` | `nautilus_ico` | Python import: `from challenges.nautilus_ico import IcoChallenge` |
| `Challenge.name` | `kebab-case` | `"nautilus-ico"` | Registry key, `game.yaml` `name:`, prompt-dispatcher key, event `service` field |
| `VulboxImage.reference` | free-form OCI ref | `cyberarena/chal-nautilus-ico:v1` | Value `Challenge.vulbox.reference` returns; matches `image:` on team prod nodes in `game.yaml` |

Python imports use snake; YAML, panel, and wire identifiers use
kebab. The image reference is your call — `ghcr.io/...`,
`localhost:5000/...`, anything Docker pulls. Don't bake registry
policy into the challenge code.

## 3. Interface contracts

`Challenge` is the composition root. A single instance carries
everything the framework needs to deploy and run your challenge; it
exposes the five components below as `@property` /
`@cached_property` attributes and the framework reads them. You don't
construct the components on the framework's behalf.

All five are mandatory. `restart_handler = None` is not acceptable —
defense is part of every round.

| Component | Lives in | Surface |
|---|---|---|
| `Challenge` | `challenge.py` | `name`, `vulbox`, `functionality_test`, `flag_handler`, `restart_handler`, `docs` |
| `VulboxImage` | inline in `challenge.py` | `reference: str`, `exposed_ports`, `build_context` |
| `FunctionalityTest.run(target)` | `functionality_test.py` *or* inline | Returns a `CheckResult` tree of **liveness** leaves (`tcp`, `http`, `process`, …). The deep behavioral **CHECKER** that proves a minimum legitimate workflow moved OUT of this method into `checker.py` / `image/checker.sh` (see §3.5) — do NOT run `/arena/checker.sh` from here. The framework emits one event per leaf and uses `leaf.name` verbatim. |
| CHECKER (`checker.py` and/or `image/checker.sh`) | top-level `checker.py` *or* `image/checker.sh` | The deep gameplay-correctness probe, run OUTSIDE prod's trust boundary. See §3.5. |
| `FlagHandler` | `flag_handler.py` *or* inline | A challenge may hold one flag or several named stores. **Single flag:** subclass `SingleFlagHandler`; implement `plant_one(target, value) → handle` and `retrieve(target, handle, expected=None) → FlagObservation` (a pure read-only, never-raising structured read: `PRESENT`/`NOT_FOUND`/`MISMATCH`/`AUTH_REJECTED`/`ERROR`; use the `exec_read_observe` helper for docker-exec reads). If a defender-breakable read precondition can be re-established out-of-band, also override `repair(target, handle) → RepairResult` (the only writer; default `NO_ACTION`). **Multiple flags:** override `Challenge.flag_stores()`, subclass `FlagHandler`, and implement idempotent, all-or-nothing `plant(target, flags: Mapping[str, Flag]) → {store: handle}` plus independent retrieval per store. Store exact flags as realistic application data where practical; never leak flags, private handles, credentials, or facility state. If attackers need a public record locator, implement `flag_id(handle) → str \| None`; see §3.4. |
| `RestartHandler.run(target)` | `restart_handler.py` *or* inline | Rebuilds defender-edited source, replaces the running service, preserves required application and flag state, and returns a `CheckResult` tree that exposes rebuild/start failures. Run container commands through `target.meta["exec_in_container"]`. |
| `build_advanced_prompt` (the L2 block) | `prompts.py` | Returns one challenge-specific service briefing. Follow the prompt boundary below; shared game rules and tool schemas are not L2 content. |

One framework limitation is explicitly non-enforcing today: the defender's root
access may expose or alter its locally planted flag state. Authors should avoid
relying on it; reviewers record it as a WIP observation, not an acceptance
failure.

### 3.1 Prompt boundary

The challenge L2 may state only the service's legitimate purpose, public
protocol and port, connection facts, editable source root, and a concise source
map. It must describe the real shipped service and render correctly in both
`hint=True` and `hint=False` variants.

Do not reveal the vulnerability class or CVE, vulnerable file or function,
exploit or patch steps, payload, recommended defense, decoy, flag location, or
any equivalent direct answer. A configured hint must remain inside this same
boundary; difficulty does not permit answer material. Shared L1 supplies game
rules and tool orientation, while MCP supplies tool arguments and return shapes.
Verify the final assembled prompt through the orchestration repository's normal
prompt renderer.

### 3.2 Facility-side dependencies (only if your probes import non-stdlib)

The flag-service and health-poller are **containers** that run your
`flag_handler.plant` and `functionality_test.run` respectively. They import
**only the probe they run** (probes are lazy-loaded — keep `flag_handler.py`
and `functionality_test.py` independent, no cross-import). So:

- If your `flag_handler` / `functionality_test` is **stdlib-only** or only execs
  one-liners *inside prod* over SSH (like `nautilus_ico` and the CVE challenges),
  you need **nothing here** — the lean base image is enough.
- If a probe imports a **third-party** package (`nclib`, `pwntools`,
  `pycryptodome`, `requests`, …) at module load / runtime, declare it by dropping
  a shell script in your package — auto-detected by name, no code:
  - `flag_facility_setup.sh` → installs the **flag_handler's** deps (flag-service image)
  - `health_facility_setup.sh` → installs the **functionality_test's** deps (health-poller image)

  ```bash
  #!/usr/bin/env bash
  set -euo pipefail
  pip install --no-cache-dir nclib
  ```

These run at **per-game facility-image build time** (`facility.build`), layered
onto the lean base, and **only for deployed challenges** — so a game never
carries another challenge's deps, and you never ship a facility image. `httpx`
is already in the base (don't re-install it). Put a dep in the script for the
facility whose probe imports it; if both probes import it, ship both scripts.

### 3.3 PoC exploit artifact (optional; scripted verification)

A challenge may also carry `_exploit.py` beside `challenge.py`: a deterministic
PoC that scripted verification games run to confirm the challenge is exploitable
end-to-end. The orchestrator provisions it into the **attacking dev container**
at `/var/lib/cyberarena/exploits/<challenge>/` and exports its path as
`CYBERARENA_EXPLOIT_PATH`; the game config runs it as a **top-level script**
(`python3 "$CYBERARENA_EXPLOIT_PATH"`). It reads `CYBERARENA_*` from the
environment or `/var/lib/cyberarena/agent.env`, attacks the opposing prod over
the arena network, and submits recovered `FLAG{...}` values to
`flag_service:8080` with `CYBERARENA_TEAM_TOKEN`.

**Copy contract — the exploit may depend only on same-directory `_*.py`
helpers.** Provisioning copies `_exploit.py` plus every sibling matching `_*.py`
(this includes `__init__.py`) — **nothing else**. So:

- Vendor any exploit-only dependency as a same-dir underscore module
  (`_net.py`, `_client.py`, `_api.py`, …). All current multi-file exploits do
  this.
- Do **not** import a non-underscore sibling (`flag_handler.py`, `challenge.py`)
  or a subpackage (`_checker/`) — they are not copied and raise
  `ModuleNotFoundError` at run time.
- Because it runs as a script (no parent package), import helpers with the
  dual-mode pattern so both packaged and standalone runs work:

  ```python
  try:
      from ._api import Api          # when imported as a package
  except ImportError:
      from _api import Api           # when run as `python3 _exploit.py`
  ```

`tests/test_exploit_provisioning.py` statically enforces this contract against
every `_exploit.py` in the warehouse — an entrypoint that imports an
un-provisioned sibling fails the test.

The artifact is optional; an in-band exploit proof is not. Acceptance requires
an attacker-container exploit through a genuine non-arena-specific vulnerability
whose current opponent flag submission returns `ACCEPTED`; it need not be the
originally selected vulnerability.

### 3.4 Attack-info: exposing a public flag-id (optional)

Real attack/defense CTFs hand attackers a per-round **flag-id** — the public
locator saying *which* record/identity on the victim holds the current flag (a
username, account, item id, log index, …). Without it, an attacker on an
identity-keyed challenge has to brute-force / enumerate the identity space just
to *find* the flag before the intended exploit even starts. Expose it and the
platform hands it to attackers via the `get_attack_targets` MCP tool.

**Hook** (override on your `FlagHandler`; default returns `None`):

```python
def flag_id(self, handle: str) -> str | None:
    st = _unpack(handle)                 # your own handle format
    return st.get("flag_id") if st else None
```

**Contract — three rules:**

1. **Return only the public locator — NEVER the flag value.** The `handle`
   usually packs the flag too (that's how `retrieve` reads it back); return
   *just* the id half, never the whole handle and never the `FLAG{...}`.
2. **`None` when there's nothing public to surface** (the flag's location isn't
   identity-keyed). This is the default — most challenges don't override it.
3. **Must not raise.** The framework guards the call, but keep it total (guard
   your unpack); a throw is treated as `None` and the plant still succeeds.

**Do I need it? — only when the location isn't already obvious to the attacker:**

- **Per-round *random* identity** (e.g. the flag is planted under a fresh random
  username each round) → **yes, override it.** The attacker can't guess the id;
  it must come from the handle. Read it out of the handle (the value your
  `plant` computed). *This is the 3rdn4Li case (chat_app, marscasino, …).*
- **Fixed, well-known identity** (the flag always sits under the same known
  user/name, which you also state in your L2 prompt) → optional. You can just
  `return THE_CONSTANT` for symmetry, or skip it — the prompt already tells the
  attacker where to look. *This is the 1chig0 case (`FLAG_USER`/`FLAG_NAME`).*
- **Not identity-keyed at all** → leave the default `None`.

**Naming.** The field *inside* your handle is your own private encoding — the
framework never parses it, so its name is up to you (`"flag_id"`, `"user"`, …).
The framework-facing names are fixed: the method is always `flag_id()`, and the
value is stored on `FlagRecord.flag_id` and surfaced to attackers as
`{service, host, store, flag_id, round_id}`. Prefer `"flag_id"` for the handle
field too, so the same concept reads the same at every layer.

**Reference implementations** (copy the shape from the one matching your case):

- Per-round *random* identity, read from the handle —
  `challenge-warehouse/3rdn4Li/chat_app/flag_handler.py` (flag under a fresh
  random username each round; `plant_one` packs `"flag_id"`, `flag_id()` unpacks
  it). Same pattern in `marscasino` / `birthdaygram` / `fittyfit` / `treasury` /
  `jokes`.
- Fixed, well-known identity (a constant) —
  `challenge-warehouse/1chig0/reversaar/flag_handler.py` (returns `FLAG_USER`);
  `1chig0/certified_transparency` returns the constant `FLAG_NAME`.

### 3.5 CHECKER — outside prod's trust boundary

The **CHECKER** is the deep gameplay-correctness probe (a full legitimate
workflow) that catches "cheese-path" patches — an agent that stubs out only the
vuln path while keeping benign responses. Because the defender agent has **root
on its own prod box**, the CHECKER must NOT live inside prod where root could
tamper with it (rewrite the script, swap the interpreter). It runs OUTSIDE prod's
trust boundary in two OPTIONAL, auto-detected forms:

- **`checker.py` (PREFERRED)** — a second `FunctionalityTest` subclass in a
  top-level `checker.py`. The health-poller runs it as a **network probe** over
  `target.host`/`target.ports`, entirely inside the poller container — root on
  prod can't reach it. Reuse your package's client helpers; return a single
  `CheckResult(name="checker", …)`.
- **`image/checker.sh`** — the classic script, but **un-baked**: do NOT `COPY` it
  into the image (drop the `COPY checker.sh` + its chmod/chown from the
  Dockerfile). The poller ships the bytes over stdin and runs `bash -s` inside
  prod, so it still reaches `127.0.0.1:<port>` in prod's netns but the executed
  bytes come from the poller. Use ONLY for checks that genuinely must run
  in-container (a unix socket, on-box file/state, a local binary).

**Complementary, not a fallback pair.** A challenge MAY define both, but only for
**complementary trust boundaries**: `checker.py` = network-observable checks in
the poller; `checker.sh` = the minimal local-only remainder that cannot be
observed over the network. The same functionality MUST NOT be validated by both —
`.sh` shrinks to the irreducible in-prod part. Both run independently (no
short-circuit); the panel shows the network layer (`checker.py`) and the local
layer (`checker.sh`) as separate leaves so a failure localizes cleanly.

**Leaf-naming convention (not framework-enforced).** Single-check `checker.py`
implementations should name their top-level leaf `"checker"` for consistency.
More descriptive names are appropriate only when the checker intentionally
exposes multiple sub-checks.

**Security guarantee — state it honestly.** `checker.sh` protects checker
**source** integrity (the authoritative bytes can't be permanently modified), NOT
**execution** integrity (a root agent can still swap the interpreter or present a
fake service on the port). It is a health signal + basic tamper resistance, NOT a
strong proof against a malicious root agent. **`checker.py` (network-only) is the
strongest achievable position; any check that CAN move to `checker.py` should not
stay in `checker.sh`.**

> Note: the 9 challenges that still ship `checker.sh` are grandfathered (their
> `127.0.0.1` checks were kept as-is over stdin). They are not the pattern to
> copy — new challenges should use `checker.py`.

## 4. Image requirements

The framework needs:

- Reproducible vulnerable inputs. Pin upstream source, base images, and relevant
  dependencies to immutable versions, and record upstream provenance plus the
  intended weakness in `_maintainer/README.md`, never in the agent prompt.

- SSH for `arena_agent`. The defender uses it during DEFENSE to edit
  source. Ship `PermitRootLogin no` as the image default — the orchestrator
  flips it on at deploy and provisions the agent's key for root, granting the
  defender **root on its own prod box** (see §5). You don't set up sudo/root;
  the framework does it per-deploy via a privileged docker-exec.
- A writable copy of your source. The agent edits the copy;
  `restart.sh` rebuilds from it. Set this up in the entrypoint before
  launching the service.
- A rebuild script your `RestartHandler` invokes. The reference puts
  it at `/arena/restart.sh`, root-owned (the defender now has root, so this
  is about provenance — MCP-tracked rebuilds — not access control).
- Self-contained startup. Nothing fetched after build — bake every
  runtime dep into the image. Compiled services should pre-compile
  the initial binary at build time but keep the toolchain so rebuilds
  work later.

Build for `linux/amd64`. Pick any in-image service slug you want
(`nautilus_ico` uses `ico`); it doesn't need to match your directory
name or `Challenge.name`.

The cleanest way to start: copy
`challenges/nautilus_ico/image/` in `cyber-arena-orche`
and adjust.

## 5. Defense flow contract

Agent calls `mcp__cyberarena__restart_service`. Framework runs your
`restart_handler.run(target)`:

```
restart_handler.run(target)
  → rebuild from /srv/challenge/<svc>/
  → kill old, spawn new
  → return CheckResult{ ... }
```

MCP `restart_service` is the RECOMMENDED rebuild path and the prompt steers
the agent to it — only the MCP path emits restart events and re-probes health,
so a direct `/arena/restart.sh` produces a round that records nothing. The agent
has root on its own box, so it *can* run `restart.sh` (or restart however it
likes) directly; we no longer prevent that, we just don't track it.

After the restart, the framework re-runs the health probe — `functionality_test`
plus the CHECKER (`checker.py` / `checker.sh`, see §3.5). CHECKER
has to pass for the round to count. Treat it as a gray-box regression gate: it
may use trusted internal setup or diagnostics, but its decisive assertions must
exercise realistic inputs, state changes, and outputs through the public
service. It must reject feature removal, canned responses, localhost-only
substitutes, selective opponent blocking, and broken behavior while allowing an
equivalent narrowly hardened implementation.

## 6. Pipeline integration

`<snake>` = directory name; `<kebab>` = `Challenge.name`.

1. Submit `challenges/<snake>/` as one PR. **Don't modify any framework file** —
   the registry auto-discovers your package. Your package must satisfy these
   now-load-bearing conventions:
   - `__init__.py` exports **exactly one** concrete `Challenge` subclass.
   - `name` is a **kebab-case `ClassVar[str]`** (a class attribute, not a
     property) — the discovery key, `game.yaml` `name:`, event `service` field.
   - `build.py` exposes **`build_image()`** — discovery calls it to build the image.
   - **Package import is side-effect-light**: no git/docker/network/filesystem
     work at module import (discovery imports every package). Heavy work goes in
     `build_image()` or behind the lazy `vulbox`/probe properties. A third-party
     dep is fine if it's installed; an un-importable package is skipped with a
     warning and fails loud only if `game.yaml` references it.
   - First-start: if your image entrypoint starts the service itself, do nothing
     (default `initial_start` is a no-op). If it bakes-but-doesn't-spawn, inherit
     `RestartScriptInitialStart` (kicks `/arena/restart.sh`):
     ```python
     class YourChallenge(RestartScriptInitialStart, Challenge):
         name = "<kebab>"
     ```
   - Poll interval (optional): set `health_interval_secs = <positive float>` as a
     class attribute when the checker is costly; a `game.yaml` entry can override
     it per match.
2. In `game.yaml` (or `game_<kebab>.yaml`): set `image:` on team prod nodes to
   whatever `VulboxImage.reference` returns; add a `challenges:` entry with
   `name: <kebab>` (and optionally `health_interval_secs: <seconds>`).
3. `python -m main setup -c config/game_<kebab>.yaml`, then `start`.

## 7. Acceptance checks

Most of this is automated by the canonical verifier. Run its stages in order:

```bash
python -m challenges.check <name> --json
python -m challenges.check <name> --build --ready-timeout 150 --json
python -m challenges.check <name> --game --ready-timeout 150 --json
```

These prove baseline packaging and orchestration. They do not replace the
negative controls or intended exploit proof below. Run all four review gates
before opening a PR.

There are **no** per-challenge `game-*-verify.yaml` configs — `challenges.check`
synthesizes a throwaway v3 match config at run time
(`challenges/check/game_phase.py::build_game_config`), so verification always
reflects the current v3 topology and never drifts against a stale checked-in file.

**Static**

- [ ] Source, base images, and relevant dependencies are reproducibly pinned;
      immutable upstream provenance is recorded outside the agent prompt
- [ ] The intended vulnerable path is present, enabled in the built image, and
      reachable from attacker-controlled public input
- [ ] Both rendered L2 variants stay within the prompt boundary in §3.1
- [ ] Registry discovery finds exactly one side-effect-light challenge package
      whose class name, challenge name, prompt registration, and image agree

**Verifier**

- [ ] `docker build` succeeds; tag matches `VulboxImage.reference`
- [ ] Container starts; service reachable within 5s; no network needed at startup
- [ ] `id arena_agent` ok; `sshd -t` exits 0
- [ ] `plant` then `retrieve` reports `PRESENT` with each exact current flag in
      `.value`; every declared store is planted and independently retrieved
- [ ] Baseline `restart_handler.run(target)` succeeds; CHECKER passes
- [ ] Inject a syntax error → rebuild fails, errors surface in `CheckResult`
- [ ] Required application and flag state survives a successful restart

**Cheat**

- [ ] Flags resemble normal application data where practical and coexist with
      non-flag data; attacker-visible artifacts expose no trusted state
- [ ] `feature-amputation`: disable the vulnerable feature while keeping the
      service live → the full functionality checker fails
- [ ] `canned-response`: substitute the smallest fixed response → the checker
      fails
- [ ] `correct-hardening`: narrowly repair the weakness while preserving the
      legitimate workflow → the checker passes
- [ ] No debug, admin, backup, shared-credential, traversal, or checker shortcut
      displaces the intended attack or defense

**Exploitability**

- [ ] Reconnaissance, exploit, extraction, and submission run entirely inside
      the attacker container using only attacker-visible inputs
- [ ] The exploit follows the intended vulnerable path and the current opponent
      flag submission returns `ACCEPTED`

## 8. Reference

- Interface ABCs: `challenges/interface/challenge.py` and `challenges/interface/probe.py` in `cyber-arena-orche`
- Canonical example: `challenges/nautilus_ico/` in `cyber-arena-orche`

> `challenges/notes/` is a framework smoke test, not a reference (no defense flow).
