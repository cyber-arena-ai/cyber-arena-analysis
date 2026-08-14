# Minimal challenge cheat resistance

## Goal

CyberArena challenges should resist obvious defenses that pass health checks
without preserving the application behavior the challenge is meant to test. The
target is not perfect anti-cheat protection against a determined agent with root;
it is to remove easy, discoverable shortcuts so that the natural strategy is to
understand and patch the vulnerability.

The main threat is a defender separating checker traffic from attacker traffic.
Once that separation is possible, the defender can serve a pristine reference
instance, a canned response, or a narrow compatibility shim only to the checker
while amputating the real feature elsewhere. A sidecar is therefore an
exploitation technique, not an independent infrastructure problem.

## Minimum changes

| Change | Cheat pattern addressed | Reasonable implementation |
| --- | --- | --- |
| Bind checks to live state and required features | Pristine sidecar, canned response, replay, and feature amputation | Provision a fresh random canary or temporary credential into the active service, then check it through the ordinary public routes and the features identified in the Stage 3 attack chain. A check must fail when a required feature is disabled. |
| Make checker traffic less recognizable | Selective routing based on timing, fixed payloads, checker-only headers, credentials, or endpoints | Jitter the polling interval, randomize request values and ordering, avoid checker-specific request markers, and use the same public service interface as normal clients. Perfect source-IP indistinguishability is not required for the first version. |
| Close the interactive checker oracle | Repeated probes used to infer the exact checker predicate or tune a special-case response | Run one automatic check after restart, rate-limit manual checks, allow only one check in flight per service, and return coarse pass/fail feedback to the agent. Retain detailed leaves and output only in operator artifacts. |
| Verify flag integrity continuously | Deleting, replacing, moving, or corrupting flags while leaving a superficial service check green | Verify the exact active flag after each rotation, after a restart, and periodically. Check that the value and expected handle still match; never expose the value in events or agent feedback. |
| Keep the authoritative checker outside prod | Editing the checker, replacing its result, or learning its full predicate from a baked-in file | Prefer an external `checker.py`. Do not use an in-container `checker.sh` as the sole anti-cheat signal: a root defender can capture its input or manipulate its execution even when the file is streamed rather than baked into the image. |

The live-state check is the most important addition. Jitter alone does not stop a
defender that can identify the checker by source address, and a randomized
round-trip created entirely inside a sidecar will still pass. The canary or
credential must be provisioned independently into the active service before the
public checker request arrives. Selectively routing that request to a stale
reference instance should therefore fail.

Flag retrieval and health checking prove different properties. Periodic exact
retrieval proves that the stored flag was not altered. It does not prove that
the intended application features still work. The state-bound public checker
proves feature preservation, but it should not attempt the vulnerability itself:
a correct defense is expected to block exploitation while retaining legitimate
behavior.

## Cheats this should catch

- Route recognizable checker requests to an untouched copy of the service while
  serving a crippled or hardened replacement to attackers.
- Return a fixed response for a documented checker payload, account, URL, or
  request sequence.
- Repeatedly trigger health checks and use detailed failure leaves as an oracle
  to reconstruct the predicate.
- Disable an upload, export, rendering, parsing, or authentication feature on
  the attack chain while keeping a shallow TCP or homepage check green.
- Remove or replace the active flag so exploitation cannot score, including
  doing so only after rotation or restart.
- Patch or wrap a locally executed checker so it reports success independently
  of application behavior.

More deliberate attacks remain possible—for example, mirroring newly
provisioned canaries into a reference service or deeply fingerprinting facility
networking. Those require intentional anti-harness engineering and are outside
this minimum pass. Evidence of such behavior should drive a later infrastructure
change rather than expand every challenge preemptively.

## Pipeline responsibilities

Stage 3 must identify the intended attack chain, the legitimate features on that
chain, and the state that can demonstrate those features remain live. It should
also name the obvious amputation, replay, and checker-routing shortcuts relevant
to the candidate.

Stage 4 turns that analysis into a challenge-specific external checker and live
state setup. The authored exploit must score, a narrow fix must stop it without
breaking the required features, and the obvious shortcuts identified in Stage 3
must fail the checker.

The orchestration repository owns checker isolation, scheduling jitter,
rate-limiting and feedback, and runtime flag-integrity checks. Challenge packages
own their feature-level canary setup and public probe. Detailed adversarial
review remains useful, but it is not a prerequisite for this minimum guardrail.

## Current-main assessment

The updated orchestration `main` has removed the most direct exposure:
`checker.py` runs in the external health poller and `checker.sh` is streamed over
stdin rather than copied into the production image. This improves source
integrity but does not complete the minimum set. Polling still uses a stable
cadence, manual checks expose detailed per-leaf results without an effective
oracle limit, and live flag rotation does not periodically verify the stored
value. Existing challenge descriptions can also reveal fixed checker behavior.
