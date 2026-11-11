---
name: api-security
description: "Invoke this skill when the task is authorized offensive testing of a REST, GraphQL, WebSocket, or SOAP API beyond recon: authentication and authorization flaws (BOLA, IDOR, BFLA), JWT and OAuth weaknesses, GraphQL-specific abuse, input validation, business logic, rate-limit trust confusion, and excessive data exposure."
mcps: ScopeSentry, browser
---

# API Security Testing (REST, GraphQL, WebSocket, SOAP)

This is the hunting counterpart of api-recon. api-recon maps the API surface and stops; this skill attacks the mapped surface under an authorized engagement. The standing finding quality gates and the adversarial gate in your system prompt apply throughout, and an access-control finding only exists once a second account or role has proven the boundary is real.

Attribution: adapted from the `api-security` playbook of [zhaoxuya520/reverse-skill](https://github.com/zhaoxuya520/reverse-skill) (MIT License).

## Boundaries

- Rate-limit and load tests only within the engagement's written impact budget. Most bounty programs forbid denial of service outright; volume that degrades the service for other users is out of bounds. Race-condition tests use a handful of concurrent requests, never load tools.
- Do not exfiltrate real user data to prove a BOLA. One record you are authorized to touch, or your own second account, is sufficient evidence.
- Destructive payloads (deletion, mass assignment on write endpoints) only against accounts and resources created for the test.
- Every confirmed finding needs a replayable artifact: the exact request, the exact response, and the authorization context that produced it.

## Phase checklists

### Phase 1: discovery (handoff from api-recon)

- Spec sources: `/swagger.json`, `/openapi.json`, `/api-docs`, `/graphql`, JS bundles, robots.txt.
- Undocumented path brute force, low rate: `kr scan https://host -A=apiroutes-210228:20000 -x 2 --delay 200ms -H "Authorization: Bearer $TA"` (kiterunner, route-aware), or `ffuf -u https://host/api/FUZZ -w "$ARTEX_WORDLISTS/Discovery/Web-Content/api/api-endpoints.txt" -x "$HTTP_PROXY" -rate 10 -mc all -fc 404` (fall back to a short hand list when `$ARTEX_WORDLISTS` is unset). kr has no proxy flag: replay each hit once with curl so the proxy records it.
- GraphQL introspection, three tiers: the full introspection query; a trimmed query if the full one is blocked; minimal `__schema { types { name } }` as the last probe.

### Phase 2: authentication

JWT (python; jwt_tool is not installed — use the `jwt_forge.py` helper in the auth-session-sso skill, or pyjwt via `pip3 install --target ./py pyjwt`):

- [ ] `alg: none`: header rewritten, signature stripped.
- [ ] key confusion: RS256 public key accepted as an HS256 secret.
- [ ] weak HMAC secret: offline python HMAC loop over `"$ARTEX_WORDLISTS/Passwords/scraped-JWT-secrets.txt"`.
- [ ] expired or tampered claims: `exp`, `iat`, `sub`, `role`.
- [ ] `kid` injection: path traversal inside the key id.

OAuth 2.0:

- [ ] `redirect_uri` manipulation leading to authorization-code theft.
- [ ] missing `state` (CSRF on the authorization flow).
- [ ] token leakage via `Referer` or platform logs.
- [ ] missing PKCE on public clients.

GraphQL auth:

- [ ] mutation reachable through GET (CSRF).
- [ ] batched queries bypassing per-operation authorization.

### Phase 3: authorization (BOLA / IDOR / BFLA)

BOLA, object level:

- [ ] enumerate numeric ids: `/user/1` to `/user/2`.
- [ ] enumerate UUIDs harvested from other responses.
- [ ] substitute usernames or emails in paths and bodies.
- [ ] two-session replay: user A's session requesting user B's objects (replay-and-diff script below; Burp/Autorize is not available).

Two-session replay-and-diff (GET/POST/PUT/PATCH only; `reqs.txt` = `METHOD URL [json-body]` lines taken from A's traffic, `$TA`/`$TB` = tokens of A and B):

```bash
mkdir -p az; while read -r m u b; do k=$(printf %s "$m $u" | md5sum | cut -c1-8)
  for who in A B NONE; do case $who in A) a="Authorization: Bearer $TA";; B) a="Authorization: Bearer $TB";; NONE) a="X-Anon: 1";; esac
    curl -s -X "$m" -H "$a" -H 'Content-Type: application/json' ${b:+--data "$b"} "$u" -o "az/$k.$who" -w "$k $who %{http_code} %{size_download} $m $u\n"
  done; done < reqs.txt | tee az/summary.txt
```
For every key where B (or NONE) gets the same 2xx and a similar size as A, `diff az/$k.A az/$k.B` and confirm the body carries A's owner/tenant fields; then run the attribution control (own id, nonexistent id, invalid id) before reporting.

BFLA, function level:

- [ ] standard user calling admin endpoints.
- [ ] HTTP method swap: GET to PUT, PATCH (the DELETE method is blocked by the platform; skip it).
- [ ] version downgrade: `/v2/admin` to `/v1/admin`.
- [ ] batch-operation injection: append an admin id to the bulk body.

### Phase 4: GraphQL-specific

- [ ] introspection exposing schema details it should hide.
- [ ] alias overload (dozens of aliases in one query) and batched queries as compute amplification, within the impact budget.
- [ ] field-suggestion error messages leaking schema names.
- [ ] GraphiQL or a playground exposed unauthenticated.
- [ ] deep nesting as a resource-exhaustion vector, within the impact budget.
- [ ] trace or debug mode returning metadata.

### Phase 5: REST input validation

- [ ] HTTP method swap on every endpoint.
- [ ] Content-Type tampering: JSON to XML to multipart (XXE where XML is accepted).
- [ ] NoSQL operator injection: `{"username": {"$gt": ""}}`.
- [ ] SSRF through URL-taking parameters (webhooks, avatar imports, fetchers).
- [ ] HTTP parameter pollution: `?role=user&role=admin`.
- [ ] mass assignment: `is_admin: true` added to request bodies.

### Phase 6: business logic and differential testing

- [ ] diff v1 against v2 of the same API: status-code changes, removed fields, latency regressions.
- [ ] role matrix: admin, user, readonly through the same workflow.
- [ ] coupon, credit, and price manipulation on test accounts.
- [ ] TOCTOU races with a few concurrent requests.

### Phase 7: WebSocket

- [ ] endpoint discovery (upgrade handshakes).
- [ ] message injection, prototype pollution through frames.
- [ ] oversized-message handling.
- [ ] type confusion in frame payloads.
- [ ] cross-site WebSocket hijacking (CSWH).

### Phase 8: rate-limit trust confusion

- [ ] header spoofing: `X-Forwarded-For`, `X-Real-IP`, reported as a trust-boundary finding, never scaled into volume.
- [ ] path variants: `/api/`, `/api`, `/Api/`, `/API/` bypassing a path-keyed limiter.
- [ ] the finding is the bypass mechanism itself; do not demonstrate it under load.

### Phase 9: data exposure

- [ ] response fields beyond what the UI renders (diff the API response against the page).
- [ ] pagination enumeration: `?page=1&limit=10000`.
- [ ] error messages leaking stack traces, internal paths, or SQL.
- [ ] GraphQL nested traversal reaching unauthorized data.
- [ ] spec files exposing internal endpoints.

### Phase 10: regression handoff

- [ ] persist every confirmed finding as a replayable request (curl command or HAR artifact) so retests and the reporter can re-verify.
- [ ] mark which findings are safe to re-run and which are one-shot (nonce or state dependent).

## Tools

| Tool | Use | Notes |
|---|---|---|
| curl + jq | request replay and diffing | always available |
| python (+ pyjwt) | JWT decode, forge, offline secret check | jwt_tool is not installed |
| ffuf, kiterunner (`kr`) | endpoint and API-route brute force | installed; low rate; replay kr hits via curl for proxy capture |
| arjun | hidden parameter discovery | installed |
| bash replay-and-diff (Phase 3) | two-session authorization diffing | Burp/Autorize is not installed |

The upstream playbook also names Vespasian, Entropy, Escape DAST, FireTail, and api.sh; treat those as references until verified in this environment, and prefer the manual checklists over unverified tooling.

## Completion self-check

- [ ] every executed phase produced artifacts (requests, responses, diffs) in the work dir.
- [ ] each access-control finding was confirmed with a second session or role.
- [ ] nothing in the report relies on a tool or output you did not actually run.
