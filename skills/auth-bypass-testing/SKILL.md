---
name: auth-bypass-testing
description: "Authentication and 2FA bypass hunting — OTP brute-force with time-to-exhaust proof, 2FA step skipping, password-reset poisoning via Host header, session fixation, and credential-stuffing chains. Use when testing login, MFA enrolment, password reset, or any session-issuing endpoint, especially on fintech and SaaS admin panels where 2FA bypass rates Critical."
---

# Authentication & 2FA Bypass Techniques

## Crown Jewel Targets

- **Fintech / banking apps** with SMS-OTP 2FA -- highest payout for 2FA bypass (often Critical)
- **SaaS admin panels** where 2FA disable lacks CSRF/re-auth -- chain to full ATO
- **E-commerce platforms** using email-based password reset -- Host header injection = token theft
- **Legacy enterprise portals** (ASP.NET, Java) with session fixation -- predictable session IDs
- **OAuth/SSO providers** (Okta, Auth0 self-hosted) -- redirect_uri bypass = mass ATO
- **Multi-tenant apps** where IDOR on 2FA endpoints lets you disable other users' 2FA
- **Mobile-first apps** with weak remember-me tokens -- base64(username:md5(password)) patterns
- **Government/healthcare portals** with sequential password reset tokens -- low entropy = predictable

## Attack Surface Signals

- **URL patterns**: `/login`, `/signin`, `/auth/`, `/2fa/verify`, `/mfa/`, `/otp/validate`, `/forgot-password`, `/reset-password`, `/api/auth/`, `/oauth/authorize`
- **Response headers**: `Set-Cookie: session=`, `X-Auth-Token:`, `WWW-Authenticate:`
- **Tech signals**: TOTP QR codes in 2FA setup, SMS-based OTP, `backup-codes` endpoints, `remember-me` cookies with base64 structure
- **JS indicators**: `otpLength`, `maxAttempts`, `lockoutDuration`, `mfaRequired`, `skipMfa`

Quick reference for bug bounty hunting. Sources: Intigriti blog.

---

## 2FA Bypass Methods

### 1. Forced Browsing (Direct Navigation)
After entering valid creds (step 1), session may already be `authenticated` before 2FA (step 2).
- Skip 2FA page entirely, navigate to `/dashboard`, `/profile`, `/api/me`
- Check if session cookie grants access without completing 2FA
- **Test**: Login → intercept 2FA redirect → change URL to authenticated endpoint

### 2. Response Manipulation
- Intercept 2FA verification response, change `{"success": false}` → `{"success": true}`
- Change HTTP status `403` → `200`
- Modify response body: `"authenticated": false` → `"authenticated": true`
- Look for client-side JS that checks response fields and routes accordingly

### 3. Status Code Bypass
- Some apps only check if 2FA endpoint returns `200 OK`, not the response body
- Submit any request that returns 200 to the validation endpoint
- Path traversal in token parameter: `1234/../../../../` to hit a different endpoint returning 200

### 4. Brute Force (No Rate Limiting)
- 4-digit OTP = 10,000 combinations, 6-digit = 1,000,000
- **Must prove**: time-to-exhaust < OTP expiry window
- Tools: Burp Intruder, ffuf, turbo-intruder
- Check: no lockout, no rate limit, no CAPTCHA after N failures
- Try: IP rotation via `X-Forwarded-For` header cycling

### 5. Token Reuse & Weak Tokens
- **Reuse**: Does a valid OTP remain valid after use? Try same code twice
- **Cross-account**: Generate OTP for account A, apply to account B
- **Predictable tokens**: Try `000000`, `111111`, `123456`, null, empty string
- **Leaked in response**: Check response headers, cookies, hidden fields for OTP value
- **Backup codes**: Test if backup codes can be reused after consumption

### 6. Race Conditions
- Send multiple parallel requests with same OTP before invalidation
- Send valid OTP + account change request simultaneously
- Window between OTP validation and session upgrade may allow replay

### 7. CSRF on 2FA Disable
- If disabling 2FA doesn't require password re-entry or CSRF token
- Craft page that auto-submits 2FA disable request for victim
- Chain: CSRF disable 2FA → credential stuffing without 2FA

### 8. IDOR on 2FA Endpoints
- Change user ID in 2FA disable/verify requests
- Replace `"account": "current"` with target user ID
- Disable another user's 2FA via parameter manipulation

### 9. Password Reset Disables 2FA
- Initiate password reset → complete reset → 2FA silently removed
- Some apps: even *initiating* reset (before completing) disables 2FA
- **Test**: Request reset link → login with old password → 2FA gone

---

## HTTP Basic authentication

Basic auth still appears on admin panels, staging environments, and appliance interfaces, and it carries structural weaknesses worth checking rather than dismissing:

- The credential is `base64(user:pass)` in the `Authorization` header — **encoding, not encryption**. Anything that logs, caches, or reflects headers (proxy logs, error pages, referrer leakage, an SSRF response) discloses the password directly.
- It is sent on **every request**, so a single instance of that header leaking anywhere is a full credential compromise.
- It carries no session state and no logout, which means it is generally not covered by anti-CSRF measures — a Basic-auth-protected state-changing endpoint may be CSRF-able even though it "requires authentication".
- Brute-force protection is often absent because the check happens at the web-server layer rather than in application code. Test rate limiting explicitly instead of assuming it exists.

```bash
curl -sI https://target/admin | grep -i 'WWW-Authenticate: Basic'      # detect
printf 'admin:password' | base64                                       # craft
curl -s https://target/admin -H "Authorization: Basic YWRtaW46cGFzc3dvcmQ="
```

Basic auth in front of an application does not mean the application behind it is out of reach — check whether the same paths are reachable on another vhost, on the origin IP, or via a route the proxy does not cover (`403-bypass`, `origin-ip-discovery`).

## Password Reset Flaws

### Predictable Reset Tokens
- Tokens based on: timestamp, user ID, sequential counter, weak hash
- Collect multiple tokens → analyze pattern → predict next token
- Tools: Burp Sequencer for entropy analysis

### Host Header Injection
- Change `Host:` header in reset request → reset link sent with attacker domain
- `Host: attacker.com` → email contains `https://attacker.com/reset?token=xxx`
- Also try: `X-Forwarded-Host`, `X-Host`, `X-Original-URL`
- Victim clicks link → token leaked to attacker server

### Token Expiration Issues
- Test if reset tokens expire (try after 1h, 24h, 7d)
- Test if token survives password change (use same token twice)
- Test if requesting new token invalidates previous one

---

## OAuth & SSO Misconfigurations

### Redirect URI Manipulation
- Open redirect in `redirect_uri` → steal authorization code
- Partial matching: `redirect_uri=https://legit.com.attacker.com`
- Path traversal: `redirect_uri=https://legit.com/callback/../attacker-page`
- Subdomain: `redirect_uri=https://evil.legit.com/steal`

### State Parameter Issues
- Missing `state` → CSRF login to attacker's account
- Predictable `state` → forge cross-site requests
- State not bound to session → replay across sessions

### Token Leakage
- Authorization code in URL → leaked via Referer header
- Implicit flow tokens in URL fragment → accessible to JS on page
- Check: does app use `response_type=code` (safer) or `token` (risky)?

---

## Session & Token Attacks

### Session Fixation
- Set session ID before authentication via URL param or cookie injection
- Victim authenticates → attacker's pre-set session now authenticated
- **Test**: Note session ID before login → check if same ID persists after login

### Predictable Session/Remember-Me Tokens
- Analyze token structure: base64-decode, look for username/timestamp/userID
- Weak patterns: `base64(username:timestamp)`, `md5(username)`
- Collect tokens from multiple accounts → compare structure

### JWT Issues
- Algorithm confusion: change `RS256` → `HS256`, sign with public key
- `alg: none` → remove signature entirely
- Weak HMAC secret → brute force with jwt-cracker
- Missing expiration (`exp`) claim → tokens valid forever

---

## IP & Rate Limit Bypasses

### Header Spoofing
```
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Originating-IP: 127.0.0.1
X-Client-IP: 127.0.0.1
True-Client-IP: 127.0.0.1
```
- Rotate IP values to reset rate limit counters
- Some WAFs/proxies trust these headers blindly

### Parameter Pollution
- Add spaces/null bytes to username: `admin `, `admin%00`
- Case variation: `Admin`, `ADMIN`, `aDmIn`
- Unicode normalization: `adm%C4%B1n` (dotless i)

---

## SQL Injection Auth Bypass

### Classic Payloads
```
' OR 1=1; --
' OR '1'='1
admin'--
' UNION SELECT 'admin','password_hash' --
```
- Test both username and password fields
- Try on login, registration, password reset, 2FA verification

---

## Forced Browsing & Access Control

### Authentication Check Gaps
- `/admin/` blocked but `/admin/GetResource.aspx` accessible
- Different HTTP methods: GET blocked, POST allowed (or vice versa)
- API versioning: `/api/v1/admin` blocked, `/api/v2/admin` open
- Content-type switching: `application/json` vs `application/xml`

### Default Credentials
- `admin:admin`, `admin:password`, `test:test`
- Company-specific: `{company}:{company}`, `{company}:password`
- Resource: SecLists default-credentials (2.8K+ entries)

---

## Attack Chains (High Impact)

1. **2FA Bypass → ATO**: Skip 2FA + credential stuffing = full account takeover
2. **Password Reset + Host Injection → ATO**: Steal reset token via header injection
3. **OAuth Redirect + XSS → Token Theft**: Open redirect in OAuth flow chains with stored XSS
4. **CSRF Disable 2FA + Brute Force**: Remove 2FA protection then brute force password
5. **Session Fixation + Social Engineering**: Fix session → trick victim into authenticating

---

## Testing Checklist

- [ ] Login with valid creds, skip 2FA page, access protected resources
- [ ] Manipulate 2FA response (status code, body, headers)
- [ ] Brute force OTP with rate limit analysis
- [ ] Test OTP reuse, cross-account, predictable values
- [ ] Check CSRF protection on 2FA disable endpoint
- [ ] IDOR in 2FA management endpoints
- [ ] Password reset: token entropy, expiration, host header injection
- [ ] OAuth: redirect_uri validation, state parameter, token leakage
- [ ] Session: fixation, token predictability, JWT weaknesses
- [ ] IP bypass headers on rate-limited endpoints
- [ ] SQLi on all auth input fields
- [ ] Default credentials on admin panels
- [ ] Remember-me token analysis (entropy, structure, expiration)

## PortSwigger Academy — Advanced Techniques

- **Timing-based username enum via long passwords**: Submit 10000-char password — valid usernames trigger hashing, measurable latency increase
- **Counter-reset brute-force**: Interleave valid credentials in wordlist — successful logins reset failed-attempt counter
- **2FA bypass via forced browsing**: After step 1, navigate directly to `/my-account` — skip 2FA page entirely
- **2FA identity swap via cookie**: Change `account` cookie from your username to victim's on 2FA POST — brute-force victim's code
- **Remember-me cookie reverse engineering**: Decode persistent cookie (Base64), identify formula (e.g., `base64(username:md5(password))`), generate for targets
- **Password reset token deletion**: Initiate reset, capture URL, submit change form with token parameter REMOVED
- **Password reset Host header poisoning**: Modify Host header → reset URL points to attacker server → victim clicks → token captured
- **Hidden username manipulation**: Modify hidden `username` field in password change form to target username

## Operator Notes (Battle-Tested)

1. **Run every request twice, once per identity** -- this is mandatory; the tooling is not. Burp's Autorize extension automates it (set it up with User B's cookie before browsing as User A, green rows = instant BOLA/BAC), but it is a separate BApp and is not driveable from Burp's MCP tools, so do not plan around it. Without it, replay each request with the second identity's session and diff the bodies — `mcp__Burp__send_http1_request` or plain curl both do this. A 200 is not a pass: confirm the body actually contains the other user's data.
2. **Always check if password reset disables 2FA silently** -- this is the most overlooked 2FA bypass. Initiate reset (do not even complete it), then try logging in. Many apps clear MFA state on reset initiation, not completion.
3. **OTP brute-force: prove time-to-exhaust < OTP expiry** -- "no rate limit" alone is REJECTED (MEMORY.md rule). 4-digit OTP = 10K combos, measure req/s, calculate wall-clock time, compare to OTP TTL. If time-to-exhaust > expiry, it is not exploitable.
4. **Playwright for OAuth/SSO flows, never curl** -- redirect chains, cookie setting, JS challenges all break in curl. Proxy Playwright through Burp for full capture. Save storageState after login for reuse ().
5. **Remember-me cookie reverse engineering** -- base64-decode persistent cookies immediately. Common formula: `base64(username:md5(password))`. If predictable, generate for any target user. Use Burp Sequencer for entropy analysis on tokens.

## Related Skills & Chains

| When | Go to |
|------|-------|
| SAML/SSO detected on login | `references/saml-bypass-techniques.md` |
| OAuth flow in auth chain | `oauth-testing` |
| JWT used as session token | `jwt-testing` |
| Host header reflected in password reset email | `host-header-attacks` |
| Rate limiting blocks brute-force attempts | `rate-limit-bypass` |
| CSRF on 2FA disable endpoint | `csrf-testing` |

## Reference files

Read these when the situation calls for the depth they carry — they are not loaded automatically.

- `references/saml-bypass-techniques.md` — **saml bypass techniques** — related_patterns: ["auth-bypass-techniques", "oauth-token-theft-chain", "xxe-techniques", "csrf-advanced"]
