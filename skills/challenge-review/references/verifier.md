# Canonical verifier

## Run

Run this wrapper once:

```text
python3 <skill-root>/scripts/run-verifier.py <challenge-id> \
  --warehouse <absolute-warehouse-path> \
  --context <run-dir>/context.json \
  --repo-root <orche-root> \
  --output <run-dir>/verifier.json \
  --execute
```

If the wrapper exits nonzero after writing `verifier.json`, use that artifact
rather than rerunning it.

## Transfer report inputs

Set `review.json.context.image_hash` to `verifier.json.image_hash`, including
`null` when the build did not produce one. If `verifier.json.objectives` is an
array, copy it to `review.json.objectives` without modification; otherwise
leave the report's initialized empty array.

## Resolve checks

The following checks translate canonical tier results into `review.json`.
Every `PASS` or `FAIL` check must cite its required tier-status pointer. Also
cite the relevant `parsed_json/checks/<index>` entry or top-level `/error` when
available so the evidence states what actually passed or failed.

| Check | Required tier-status evidence |
|---|---|
| `VERIFY-INTERFACE` | `verifier.json#/tiers/0/status` |
| `VERIFY-BUILD` | `verifier.json#/tiers/1/status` |
| `VERIFY-HEALTH` | `verifier.json#/tiers/2/status` |
| `VERIFY-ORACLES` | `verifier.json#/tiers/1/status` and `verifier.json#/tiers/2/status` for `PASS`; either failing tier for `FAIL` |
| `VERIFY-RESTART` | `verifier.json#/tiers/1/status` |

### `VERIFY-INTERFACE`

The static tier must discover exactly the selected challenge and pass its
package, import, registry, handler, prompt, and build-interface checks.

### `VERIFY-BUILD`

The build tier must build and start the reviewed service through its declared
entrypoint.

### `VERIFY-HEALTH`

The game tier must start both teams and report every final emitted
health/functionality leaf as passing.

### `VERIFY-ORACLES`

The build tier must plant every declared store and round-trip its integrity
path through `retrieve()`. READ must recover the exact planted token. WRITE
must round-trip its integrity anchor, read every declared authoritative region,
and report a fresh unplaced mark as absent. For EXECUTE, it establishes only
that the configured handler round-trips planted evidence.

The game tier must pass live placement. It sends an invalid sentinel through
the shared READ/EXECUTE submission endpoint and requires at least one
attack-window `FLAG_SUBMITTED` event without correlating that event to the
sentinel or acceptance. For WRITE, it expects `NOT_OBSERVED` for an unplaced
mark; positive observation is not exercised for every WRITE store. When a
packaged PoV is available, the game tier must also accept it for at least one
declared objective.

### `VERIFY-RESTART`

The build tier must invoke the declared restart handler, rerun functionality,
and confirm that planted evidence remains retrievable.

## Apply the artifact outcome

Set the verifier stage status to `verifier.json.status`.

- `PASS`: set all five verifier checks to `PASS` using the evidence mapping
  above.
- `FAIL`: use the detailed checker results to identify which mapped criterion
  actually failed. Set only those checks to `FAIL`; set checks whose required
  tiers all passed to `PASS`, and set the remaining checks to `NOT_RUN`.
- `BLOCKED`: preserve any checks completed by earlier passing tiers as `PASS`
  and leave checks that were not completed as `NOT_RUN`.
