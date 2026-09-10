# Authoring

How either role builds its fragment. Role-specific ownership and procedure live
in [seed.md](seed.md) and [expand.md](expand.md); the format, and why each rule
exists, is in [graph-schema.md](graph-schema.md).

## Target

`target.json` names each build's `base_url` and `auth_header`, plus what the
facility seeded:

```json
{"builds": {"<name>": {"base_url": "http://127.0.0.1:<port>",
                       "auth_header": "<header name>: <value>"}},
 "seeded": "<what the facility planted, and how you recognise it>"}
```

`auth_header` is the entry principal and nothing more. `none: true` means the
study has no runnable bundle; `probe.py` refuses it rather than reaching for
something else. `seeded` must make the protected value recognisable; without
that, a role cannot distinguish a disclosure from an error message.

## Probing

```text
python3 <scripts>/probe.py --target <run>/target.json --build <name> \
  --path </path> [--method GET] [--param NAME=VALUE]... [--header "NAME: VALUE"]... \
  [--data '<json body>' | --form NAME=VALUE... | --data-file <path>] \
  [--note "<what this is for>"] [--observed "<the string carrying the claim>"]
```

Sends one request as that build's entry principal, appends it to
`<run>/probes.log` with the effective extra headers, the request body it sent,
the response's own headers and a UTC timestamp, and prints it. A request has
one body: `--data` is JSON, `--form` is form-encoded, `--data-file` is bytes,
for a payload that is not text. Binary bodies are retained as
`base64:<encoded bytes>` in the log's `sent` field and the evidence `source`,
so neither depends on the original file. The record grows with the file size.

`--header` adds a header; it may not replace the entry principal's, though a
cookie is merged into it, the granted one winning. Extra headers are recorded
after cookie merging and case-insensitive request-header normalization, then
named in the evidence `source`, so a route opened by a second header is not
read as one the entry principal walked alone. **One invocation is one
request**: redirects are not followed, and a 302 is returned as the result it
is, with its `Location` among the response headers. With `--observed`, it
prints the graph evidence for it — and refuses when the response does not
contain that string, which is the one thing hand-assembled evidence cannot
check about itself; when the claim lands deeper than the excerpt the log keeps,
the evidence excerpt follows the match rather than the start, and a claim
carried by a response header rather than the body is quotable too. A 403 is a
result, not a failure; a request that never arrived is logged too, and exits 1.
A rejected `--observed` also exits 1, after logging and printing the completed
exchange without an evidence claim.

```text
python3 <scripts>/probe.py --target <run>/target.json --build <name> --record \
  --request "<the request you sent, verbatim>" --response-file <path> \
  --status <code> [--note "..."] [--observed "<the string carrying the claim>"]
```

Records an exchange **you** performed, for a request this script cannot send —
another protocol, a client the study ships, a chain it cannot hold. It runs the
same containment check and writes the same log line, and its evidence `source`
says `attested`, so a reader can see which claims rest on a client other than
this one.

`probe.py` sends HTTP. It is the fast path and not a fence: what the graph rests
on is that **every observation it cites matches a record in `probes.log`**, not
which client obtained it.

## Evidence

Every node, witness and cut entry carries one observation. The shape, rules and
rationale live in [graph-schema.md](graph-schema.md) §Evidence; do not restate
them.

Every observation is a response this run received, and the build belongs in
`source`, because two runs against different builds are otherwise the same
record.

## Fragments

- **Neither role writes `graph.json`.** Each writes one fragment; the root
  merges them with `graph_merge.py`.
- **A fragment is a whole graph.** It carries the terminals it touches and its
  own function nodes, and it passes `graph_validate.py` alone before the role
  returns. Its role contract says which terminals and routes it owns.
- Everything in a fragment was reproduced — by the study, or by you. A route
  with no citable line is not a route.

## Procedure

1. **Draft nodes.** Follow the role contract for terminals. Declare one
   `objective` per confirmed witness and scope, and a `function` for each
   application function the route passes through.

   Every function node is something you can point at in the application — a
   route, a handler, a named function. Record it in `symbol`. If you cannot
   name it, it is not a node.

2. **Decide granularity by what a defender can cut.**

   > **Name a mitigation that stops this link and not its neighbour.**
   > If you cannot, they are one node.

   Decide it against the application, not against `reproduce.py`'s output
   format.

3. **Wire `predecessors`.** They are OR by default — a route arrives through
   one of them. Set `conjunctive: true` only for a node that needs all of them.

4. **Establish every node and route against the running target.** Reach for
   `probe.py` above first and paste what it prints under `evidence:`.
   It builds the three fields from the response and refuses a claim the response
   does not carry, which is the one thing hand-assembled evidence cannot check
   about itself — and it is faster than doing that by hand.

   Where it cannot send the request, **use a client that can.** A broker
   protocol, a WebSocket, a packfile, a redirect chain you must follow: reach
   the target however the target is reached, then bring the exchange back with
   `probe.py --record`, which runs the same containment check and writes the
   same log line. What the graph rests on is `probes.log`, not which client
   spoke: **every observation you cite must match a record there.** A record you
   attested says so in its own `source`, so the root knows to check it hardest;
   an observation with no record behind it is not evidence at all.

   **Do not cite the study.** Its prose and its retained `evidence/` files say
   where to look; they are not facts this run established, and nothing in the
   graph may rest on them. A node you cannot reach on the target is not a node —
   it is an unsettled claim.

5. **Draft routes.** Each is one walk from the entry to an objective, listing
   every node it passes through and nothing it could have skipped. When the
   validator names a node the route did not need, either record the shorter
   route or narrow the `predecessors` that made the shortcut possible.

   Give routes fragment-local ids `PATH-1`, `PATH-2`, and so on, in document
   order. The merger assigns the final sequence across both fragments; the id
   is only a reference, while `nodes` records the ordered walk — see
   graph-schema.md.

   A chain reproduced twice is better evidence for one route, not a second
   route: add the replay to that route's `witnesses`. Record `advisories`.

6. **Record the cut the advisory accepted.** Name the advisory in
   `advisory_cut.advisory` — the CVE, or the upstream commit where the fix
   shipped without one. Read the fix and name the nodes it guarded in
   `advisory_cut.nodes` — that is the one cut here anyone has judged
   admissible, so it is the exemplar. Then run each route against the repaired
   build and record what it achieved. `survived` needs one witness. `refused`
   cannot be proved at all, so it records only what you sent, and its `tried`
   field names the payload **shapes** you attempted. Vary the shape, not just the
   value: a run recorded three routes closed on thirteen probes that all named
   the protected table directly, and a fourth shape — the query carried as a
   string literal — opened every one of them. If the only shape you tried is the
   study's own, say so in `tried`: that is the commonest way a run mistakes a
   payload for a route. Leave the cut out only when the study ships no fix.

7. **Validate, fix, repeat until clean.**
