# Challenge graph schema (version 1)

One `graph.json` per challenge. It records the attack structure that was
*reproduced*, never the complete attack surface.

## Document

| Field | Contract |
|---|---|
| `schema_version` | `1` |
| `target.id` | Challenge or study identifier |
| `target.repository` | `owner/project` |
| `target.revision` | The reproduced commit, 40 lowercase hex characters |
| `evidence_root` | Relative directory inside the study that every locator must stay within |
| `states` | Non-empty list of state nodes |
| `operations` | Non-empty list of operation nodes |
| `paths` | Non-empty list of reproduced scoring paths |
| `observed_cuts` | Cuts that were actually run; may be empty |

## States

Facts an actor holds or observes.

```json
{"id": "ST-obj-report-read", "role": "objective",
 "store": "report_store", "scope": "app.cross_boundary.read"}
```

`role` is `entry`, `objective`, or `intermediate`. A graph needs at least one
`entry` and one `objective`. An `objective` declares `store` and `scope`; the
scope is a registered id from `attack-scopes.json` or a fully defined
`custom.<challenge_id>.*` scope. Other roles use `title`.

## Operations

Application-controlled operations, with AND semantics across `requires`.

```json
{"id": "OP-create-share", "title": "create share link",
 "requires": ["ST-entry"], "produces": ["ST-share-token"],
 "counts_as_operation": true,
 "evidence": {"kind": "reproduced", "locator": "evidence/pov.txt#L2",
              "observed": "201 Created share=7f2a"}}
```

`counts_as_operation` is `false` for the categories contestability excludes:
authentication, environment setup, retries, encoding, reconnaissance, and proof
submission. Only counted operations are cut-eligible, because they are what a
defense can meaningfully target.

## Paths

```json
{"id": "PATH-pov", "objective": "ST-obj-report-read",
 "operations": ["OP-create-share", "OP-resolve-share"],
 "advisory_backed": true,
 "evidence": {"kind": "reproduced", "locator": "evidence/pov.txt#L5",
              "observed": "recovered victim report body"}}
```

`operations` are ordered. The first must require an `entry` state, consecutive
operations must share a state, and the last must produce the path's objective.
`advisory_backed` marks the PoV. Exactly one path may be advisory-backed per
reproduced advisory; the objective set is never derived from it (CH-4).

## Observed cuts

Only cuts that were actually applied and re-run. At Stage 3 that is the
upstream-fixed deployment, whose feature preservation is inherited from
upstream rather than measured.

```json
{"id": "CUT-upstream", "reference": "upstream_fix", "revision": "<40hex>",
 "blocked":  [{"path": "PATH-pov", "locator": "evidence/fixed-pov.txt#L2",
               "observed": "403 Forbidden"}],
 "survived": [{"path": "PATH-alt", "locator": "evidence/fixed-alt.txt#L2",
               "observed": "recovered victim report body"}]}
```

`blocked` must record at least one path. `survived` may be empty; that is how a
terminal result over the recorded subgraph is written down. A path may not
appear in both lists of one cut. Candidate cuts are computed and belong in the
analysis output, never here.

## Evidence

```json
{"kind": "reproduced", "locator": "<path>#L<line>", "observed": "<exact text>"}
```

`kind` is `reproduced` or `dynamic`. `hypothesis` is rejected with a specific
message: an asserted path is not evidence. `locator` resolves against the study
directory, must stay inside `evidence_root`, and `observed` must appear on that
exact line. This is the guard that makes fabricating an edge require
fabricating command output.

## Validation

`graph_validate.py` rejects a graph when ids are not unique or references do not
resolve; a required field is missing or malformed; evidence is a hypothesis,
malformed, or does not resolve to its cited line; a path does not start at an
`entry`, does not chain, does not terminate at its objective, or has no counted
operation; a cut records no blocked path or lists a path twice; or the graph is
cyclic.

Shallowness is **not** a validation error. A one-operation path is recorded and
labelled `shallow` by the analyzer, so a graph over a rejected study still shows
why it was rejected. Whether shallowness rejects a *challenge* is issue 17's
decision, not the graph's.

## Analysis

`graph_analyze.py` computes, and no agent authors:

| Output | Meaning |
|---|---|
| `minimal_cuts_all`, `mincut_all` | Minimal hitting sets over the recorded paths' cut-eligible operations, capped at size 4 |
| `objective_coverage` | Per objective: its paths, minimal cuts, and mincut |
| `geometry` | `fan_in`, `fan_out`, `disjoint`, `shallow`, `single_path` |
| `nontrivial_paths` | Per path, whether it has at least two counted operations |
| `observed_cuts[].implicated_operations` | The extensional root cause: operations common to the blocked paths and absent from the survivors |
| `observed_cuts[].reading` | `contestable_observed`, `terminal_over_recorded_subgraph`, or `no_effect` |
| `frontier` | Unreached objectives and paths no cut has been run against |

Cuts are computed over recorded paths rather than graph reachability, so every
result is a statement about what was reproduced. Adding paths can only raise a
min-cut, so a large `mincut_all` is sound while a small one may only mean no
further path has been recorded yet. The analyzer never emits an accept or
reject.
