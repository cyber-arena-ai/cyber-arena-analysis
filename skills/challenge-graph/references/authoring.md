# Authoring

Shared live-work procedure for SEED and EXPAND. The role contract owns task
responsibility and output; [graph-schema.md](graph-schema.md) owns the fragment
format and semantic invariants.

## Use the target

Use the supplied `target.json`. Each build's `base_url` and `auth_header` are
the reachable service and entry principal; `seeded` identifies the protected
result. Do not change the target or substitute another identity.

## Probe HTTP

```text
python3 <scripts>/probe.py --target <run>/target.json --build <name> \
  --path </path> [--method GET] [--param NAME=VALUE]... [--header "NAME: VALUE"]... \
  [--data '<json body>' | --form NAME=VALUE... | --data-file <path>] \
  [--note "<what this is for>"] [--observed "<text carrying the claim>"]
```

One invocation sends one request without following redirects and appends the
effective request and response to `<run>/probes.log`. HTTP responses, including
denials and redirects, are results; a request that never arrives is a failure.
Use only one body form. `--header` may add context but cannot replace the entry
principal; an added cookie is merged with the granted cookie, which wins.

When `--observed` occurs in the response body or headers, the command prints the
evidence object to place in the graph. Otherwise it exits non-zero after logging
the exchange and produces no evidence claim.

## Record another client

For a protocol or multi-request exchange that `probe.py` cannot send, run the
appropriate client and record its result:

```text
python3 <scripts>/probe.py --target <run>/target.json --build <name> --record \
  --request "<the request you sent, verbatim>" --response-file <path> \
  --status <code> [--note "..."] [--observed "<text carrying the claim>"]
```

This performs the same containment check and marks the evidence `attested`.
Every observation in a fragment must match a record in `probes.log`, regardless
of which client produced it.

## Build the fragment

1. Read the study to learn what to test, but never cite its prose or retained
   evidence as a fact established by this run.
2. Probe every node and route you intend to record. Anything you cannot
   establish on the target is not a graph element; handle it under the role's
   reporting or failure contract.
3. Model the confirmed result under the role's ownership and the graph schema.
   Use one objective for each confirmed witness-and-scope pair. A function node
   must name an application function, route, or handler. Split two functions
   when a mitigation can stop one without stopping the other; otherwise model
   one node.
4. Record each route as the shortest confirmed walk from the entry to an
   objective. A replay is another witness for that route, not another route.
5. When the study supplies a repaired case and your fragment records routes,
   read the supplied fix and set `advisory_cut.nodes` to the function nodes it
   guarded. Run every route in your fragment against the repaired build and
   classify each one. Put a route in `survived` only when it still reaches the
   objective. For a refusal, try materially different payload shapes and state
   them in `tried`; refusal does not prove closure. If testing is incomplete,
   return failure rather than omitting a route. Omit `advisory_cut` only when
   there is no repaired case or your fragment has no route.
6. Validate and correct the fragment using the command in the role contract.
