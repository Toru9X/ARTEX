---
name: event-driven-attacks
description: "Invoke this skill when the target is an event-driven or microservice system: Kafka/queue consumers, event envelopes, dead-letter queues, webhook receivers (GitLab and similar), gRPC between services, server-sent events streams, and BFF-to-service identity propagation. Source-first method for forged or replayed events, missing producer checks, trust in client identity headers, unauthenticated internal APIs, and live-safe probes of SSE endpoints."
---

# Event-driven and service-to-service attack surface

Most of this surface is NOT reachable from outside: the gateway publishes only the BFF/REST routes. Decide first what is reachable, then say plainly what is source-only. Never send write requests to a live system to prove a source-only issue.

## 1. Map the surface from source
- Consumers: grep for `kafka`, `Consume`, `Subscribe`, `topic`, `DLQ`, `Reader`; list topic names, group ids, and what each handler does with a message.
- Producers and bridges (`external-bridge`, webhook handlers): who can write to the topic or POST the webhook, and what authenticates them (shared secret, HMAC, mTLS, network policy only).
- Envelope types (shared libraries such as `eventenvelope`, `checkerevents`, `changeevent`): which fields carry identity or authorization (actor, org/unit, approver, request id).
- gRPC servers: `reflection.Register`, interceptors, a static service token, what an empty token does (does it pass?).

## 2. Questions that find real bugs
1. Producer trust: does the consumer check that the producer may emit this event type, or does it trust any message on the topic? Is the event bound to the object it claims (does the finding id match the request's owner)?
2. Identity in the payload: if the event carries an `approver`, is separation of duties enforced, and what happens when the field is empty? An empty value that skips a check is a bypass.
3. Replay and idempotency: can the same event be applied twice, or out of order, to flip a state? Is there an id or nonce check?
4. DLQ and retries: poison messages that stop a partition; retries that re-run side effects (emails, status changes).
5. Webhook receivers: is the secret compared in constant time and checked BEFORE the body is read, with a body size cap?
6. Header-trusting BFFs: find where `X-User-Id`, `X-Org-Id`, `X-User-Permissions` (or similar) are read. Check the mode flag that decides whether they are trusted (`Mode: off|log|enforce`, `InsecureTrustHeaders`) and whether the shipped config enables trust. A live test needs a LOWER-privilege token than the one you hold: with only an admin token, spoofed headers prove nothing.
7. Fail-open scoping: an empty scope string, or org `0`/missing/`1` treated as "all units". Check whether that is the platform org by design before calling it a bug.

## 3. Live-safe probes (GET only)
- Server-sent events (`Accept: text/event-stream`): `curl -s -m 6 -H "accept: text/event-stream" "$BASE/events?sub=<kind>:<uuid>"` returns a `hello` frame listing accepted and `dropped` subscriptions. CONTROL: subscribe with a random non-existent UUID. If a foreign id and a random id are treated the same, there is no existence oracle: NEGATIVE. Report only if a foreign id yields data or a different reply from a random one.
- Never open many streams; one stream, capped with `-m`.
- Spoofed identity headers on a GET list endpoint: compare status and result size with and without the header. A 400 on a conflicting duplicate header means it is not blindly trusted.

## 4. Reporting
Source-only items go in as facts with file:line and the exact precondition ("needs write access to topic X", "needs a token without an org claim"). Only reproduced behaviour becomes a finding.
