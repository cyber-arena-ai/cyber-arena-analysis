# Graph document template (schema version 2)

Copy this shape for each fragment. Replace every `<...>` value, add nodes and
paths as needed, and remove `advisory_cut` unless a repaired build was tested.

```json
{
  "schema_version": 2,
  "target": {
    "id": "<short-kebab-case challenge or study id>",
    "repository": "<owner/project>",
    "revision": "<40-lowercase-hex reproduced commit>"
  },
  "nodes": [
    {
      "id": "N-entry",
      "role": "entry",
      "title": "<identity and access granted to the attacker>"
    },
    {
      "id": "N-function-1",
      "role": "function",
      "title": "<application function, route, or handler used>",
      "symbol": "<code symbol or endpoint>",
      "predecessors": ["N-entry"],
      "evidence": {
        "source": "<request sent to the vulnerable build>",
        "excerpt": "<returned response excerpt containing the observation>",
        "observed": "<literal response text carrying the claim>"
      }
    },
    {
      "id": "N-objective-1",
      "role": "objective",
      "store": "<short_snake_case witness name>",
      "scope": "<registered or custom challenge scope>",
      "predecessors": ["N-function-1"]
    }
  ],
  "paths": [
    {
      "id": "PATH-1",
      "objective": "N-objective-1",
      "nodes": ["N-entry", "N-function-1", "N-objective-1"],
      "advisories": ["<CVE or fix commit; use an empty list when none>"],
      "witnesses": [
        {
          "source": "<request that reached the objective>",
          "excerpt": "<returned response excerpt containing the observation>",
          "observed": "<literal response text proving the objective was reached>"
        }
      ]
    }
  ],
  "advisory_cut": {
    "advisory": "<CVE or fix commit>",
    "nodes": ["N-function-1"],
    "refused": [
      {
        "path": "PATH-1",
        "tried": "<materially different payload shapes attempted>",
        "source": "<request sent to the repaired build>",
        "excerpt": "<returned refusal containing the observation>",
        "observed": "<literal response text showing refusal>"
      }
    ],
    "survived": []
  }
}
```

For a filled multi-route document, see
[example-graph.json](example-graph.json).

## Rules the template cannot express

- The graph records only routes reproduced in this run. Nodes are defender-side
  targets: the granted entry, application functions, and reached objectives.
- The response observed by the attacker, reconnaissance, and proof submission
  are not nodes. A function node is an application function that advances a
  recorded route to its objective.
- `predecessors` is OR by default. Add `"conjunctive": true` only when all
  listed predecessors are required. The graph must be acyclic.
- A function has a unique `symbol`. Model separately guardable functions as
  separate nodes; use one node when guarding it necessarily guards every named
  use.
- Use one objective for each confirmed witness-and-scope pair. Its `scope`
  comes from the supplied registry or is a fully defined
  `custom.<challenge_id>.*` scope. Before Stage 4, `store` names the trial
  witness.
- A path is a minimal confirmed route from an entry through at least one
  function to its objective. Its required node ids are distinct and
  topologically ordered; do not record the same ordered route twice. Fragments
  may use `"paths": []`; a finalized graph must have a route. A replay adds a
  witness to that route rather than another route.
- Fragment route ids are unique local references. Merge assigns `PATH-1`,
  `PATH-2`, and so on in SEED-then-EXPAND order. The ordered route in `nodes`,
  not the local id, identifies the route.
- Every function evidence object, path witness, and cut result is a response
  recorded in `<run>/probes.log`. `observed` is at least eight characters and
  appears literally in `excerpt`; `source` identifies the request.
- `advisory_cut.nodes` lists the function nodes the supplied upstream fix
  guarded. A repaired-build probe goes in `survived` only when it still reaches
  the objective; a refusal goes in `refused` and states the payload shapes in
  `tried`. When a repaired case exists, classify every path in the fragment and
  do not place one on both sides. Omit the whole cut only when the supplied
  target has no repaired case or the fragment has no path.
- `advisories` only identifies what a route reproduced; it does not affect
  analysis. Geometry and objective coverage are computed later, never authored
  here.

The role contract supplies the validation command. Validation enforces the
shape, ids, references, scopes, evidence containment, path reachability and
minimality, advisory-cut references, and acyclicity.
