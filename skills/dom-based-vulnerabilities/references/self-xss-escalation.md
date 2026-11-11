---
name: self-xss-escalation
pattern: Self-XSS to Universal/Stored XSS Escalation
description: "Escalate self-XSS to exploitable XSS via CSRF chain, OAuth login_hint injection, invitation flow, admin panel view, login CSRF, or shared resource rendering vectors"
triggers: ["/test-xss", "self xss", "self-xss escalation", "login_hint xss", "xss chain", "csrf to xss", "invitation xss", "oauth xss"]
tech: [generic, javascript, oauth]
severity: High
related_patterns: [postmessage-exploitation, csrf-advanced, oauth-token-theft-chain, dom-based-vulnerabilities, auto-chain-discovery, clickjacking-framebusting]
sources: ["Jack Whitton — Uber self-XSS via OAuth state", "Geekboy — AirBnb invitation flow", "Paulos Yibelo — Facebook Moves OAuth XSS"]
---

# Self-XSS to Universal/Stored XSS Escalation

## Crown Jewel Targets

- **OAuth login_hint reflection** — XSS payload in `login_hint` parameter reflected unencoded in login page HTML (Facebook Moves pattern)
- **Admin panel rendering user content** — profile name/bio with XSS payload rendered when admin views user management
- **Invitation flow XSS** — invitation page renders inviter's profile name/message with XSS payload when invitee opens link
- **Login CSRF + self-XSS chain** — force victim to log into attacker's account where self-XSS fires in victim's browser context
- **Support chat/ticket XSS** — attacker submits ticket with XSS in body, fires when support agent views ticket
- **Analytics dashboard injection** — user-controlled data (UTM params, user-agent) rendered in analytics view with XSS

## Attack Surface Signals

- Self-XSS confirmed (payload fires when YOU view your own content)
- CSRF protection missing on the endpoint where self-XSS payload is submitted
- OAuth flows with `login_hint`, `email`, or `display_name` parameters
- Invitation/sharing features that render sender's profile data
- Admin/support panels that display user-submitted content
- Analytics dashboards rendering user-controlled data (referrer, user-agent)
- Login CSRF possible (no CSRF token on login form)

## Detection
```bash
# Check for any user-controlled field rendered in shared contexts
curl -s TARGET/profile/USERNAME | grep -i "innerHTML\|document.write\|eval("
# Check OAuth login_hint reflection
curl -s "OAUTH_URL?login_hint=<script>alert(1)</script>" | grep -i "login_hint\|email"
```

**Positive indicators:**
- User-controlled content (profile name, bio, comment) rendered in a context viewable by others (admin panel, invitation page, shared resource)
- OAuth `login_hint` or `email` parameter reflected without encoding in login page HTML
- Invitation flows, support chat, or analytics dashboards that render attacker-supplied content

## Exploitation
1. Find self-XSS (payload fires when YOU view your own content)
2. Identify sharing vector (invite link, admin view, OAuth login_hint, shared resource)
3. Chain: victim visits sharing URL → victim's browser renders attacker's XSS payload
4. For OAuth chain: set login_hint/email to XSS payload → OAuth provider reflects in login page

## PoC Template
```html
<!-- OAuth login_hint chain -->
<a href="https://TARGET/oauth/authorize?client_id=CLIENT&login_hint=%3Cscript%3Ealert(document.cookie)%3C/script%3E">Click to login</a>
```

## Important Notes
- Self-XSS alone = REJECT. Must prove sharing vector exists
- Check invitation flows, admin panels, support chat, analytics dashboards
- OAuth login_hint parameter often reflected without encoding (Facebook Moves bug)
- Always verify the XSS fires in the victim's browser context, not just the attacker's own session

## Reference Writeups
- [God-like XSS, Log-in, Log-out, Log-in (Uber)](https://whitton.io/articles/uber-turning-self-xss-into-good-xss/) by Jack Whitton — OAuth state parameter chain
- [AirBnb Bug Bounty: Turning Self-XSS into Good-XSS #2](http://www.geekboy.ninja/blog/airbnb-bug-bounty-turning-self-xss-into-good-xss-2/) — invitation flow chain
- [Facebook's Moves - OAuth XSS](http://www.paulosyibelo.com/2015/12/facebooks-moves-oauth-xss.html) by PAULOS YIBELO

---

## Operator Notes (Battle-Tested)

- **Self-XSS alone = ALWAYS REJECT** — MEMORY rule and triage auto-reject. No exceptions. Must prove sharing vector exists and victim's browser executes the payload
- **OAuth login_hint is the most common chain** — test `login_hint=<script>alert(1)</script>` on every OAuth authorize endpoint. Often reflected unencoded in login page
- **Invitation flows are underexplored** — invitation pages rendering inviter's name/message are common in SaaS. Test with XSS in profile name, then send invitation
- **Login CSRF enables self-XSS escalation** — if login form lacks CSRF token, force victim to log into attacker's account where self-XSS payload is already planted
- **Admin/support panel rendering is HIGH impact** — support ticket with XSS in body fires when agent views it. Admin panel showing user profiles fires when admin browses users
- **Always verify XSS fires in VICTIM's browser context** — not just your own session. Use two browser profiles to demonstrate cross-user execution
- **Playwright verification is mandatory** — curl/Burp cannot prove browser-rendered XSS. Must use Playwright to demonstrate actual JS execution

## Related Skills & Chains

| Situation | Pattern / Skill |
|-----------|----------------|
| postMessage as sharing vector | `postmessage-exploitation` |
| CSRF needed for chain | `csrf-advanced` |
| OAuth flow exploitation | `oauth-token-theft-chain` |
| DOM XSS in target page | `dom-based-vulnerabilities` |
| Clickjacking to trigger self-XSS | `clickjacking-framebusting` |
| Chain escalation matrix | `auto-chain-discovery` |
