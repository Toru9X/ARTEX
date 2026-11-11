---
name: cors-testing
description: "Test CORS for arbitrary or null Origin reflection combined with Access-Control-Allow-Credentials:true, then prove cross-origin theft of authenticated responses. Use when testing authenticated APIs, intranet endpoints, or any response carrying Access-Control-Allow-Origin — subdomain-only reflection is not reportable alone, so check whether evil.com reflects."
---

# CORS Origin Reflection with Credentials

## Crown Jewel Targets

- **Authenticated API endpoints reflecting arbitrary origin** with `Access-Control-Allow-Credentials: true` — cross-origin data theft of PII/tokens
- **Internal/intranet APIs with CORS wildcard** — victim browser acts as proxy to steal internal resource data
- **Null origin allowed** — sandboxed iframe exploit bypassing CORS for data exfiltration
- **Trusted subdomain XSS + CORS** — XSS on any ACAO-trusted subdomain enables credentialed cross-origin data theft
- **pekko-http/akka-http default CORS** — framework defaults reflecting all origins (Pokemon, target-corp pattern)
- **OAuth token endpoints** with CORS misconfig allowing cross-origin token theft

## Attack Surface Signals

- `Access-Control-Allow-Origin` header reflecting the sent `Origin` header value
- `Access-Control-Allow-Credentials: true` combined with reflected origin
- pekko-http or akka-http server header (default CORS is permissive)
- API endpoints serving JSON with authentication cookies
- SPA applications with cross-origin API communication patterns
- CDN/proxy layer that may add its own CORS headers overriding application settings

## Detection
```bash
curl -sI -H "Origin: https://evil.com" TARGET_URL | grep -i "access-control"
```

**Positive indicators:**
- `Access-Control-Allow-Origin: https://evil.com` (reflected)
- `Access-Control-Allow-Credentials: true`

**False positive indicators:**
- `Access-Control-Allow-Origin: *` without `Credentials: true` = limited impact
- CORS on public/unauthenticated endpoints = informational only

## Exploitation
1. Confirm reflected origin + credentials on authenticated endpoint
2. Craft PoC HTML page that makes cross-origin request
3. Prove session cookie is sent and response data is readable
4. Demonstrate specific sensitive data accessible (PII, tokens, etc.)

## PoC Template
```html
<script>
fetch('https://TARGET/api/user/profile', {credentials: 'include'})
  .then(r => r.json())
  .then(d => document.write(JSON.stringify(d)));
</script>
```

## Report Notes
- Always show the specific data accessible (not just "CORS is misconfigured")
- Include both request and response headers
- Mention `pekko-http` or server header if applicable — helps triager understand root cause

## Historical Results
- Pokemon data-analytics API: 4 endpoints, pekko-http 1.3.0, zero WAF — ACCEPTED
- target-corp customer.target-corp.com: High severity — CONFIRMED
- target-corp management API: CORS on management endpoint — CONFIRMED

## PortSwigger Academy — Advanced Techniques

- **Whitelist regex bypass**: `hackersnormal-website.com` (no dot) or `normal-website.com.evil-user.net` (subdomain)
- **Null origin via sandboxed iframe**: `<iframe sandbox="allow-scripts allow-top-navigation allow-forms" src="data:text/html,<script>...</script>">`
- **TLS bypass via HTTP subdomain trust**: MitM intercepts HTTP, redirects to trusted HTTP subdomain, injects CORS exfil targeting HTTPS main domain
- **XSS on trusted subdomain → CORS exfil**: XSS on any ACAO-trusted subdomain enables credentialed cross-origin data theft
- **Intranet CORS `ACAO: *`**: Victim browser acts as proxy to internal resources

---

## Origin parsing errors

Most CORS misconfigurations that survive on real targets are not wildcard reflection — they are **flawed matching logic** in code that tries to allow a set of related origins. Test each shape explicitly, because a naive `startswith`/`endswith`/`contains` check fails differently:

```
Origin: https://target.com.evil.com      suffix-match flaw (validator checks "starts with target.com")
Origin: https://eviltarget.com           prefix-match flaw (validator checks "ends with target.com")
Origin: https://target.com.evil.com      substring/contains flaw
Origin: https://sub.target.com           only useful if that subdomain is XSS-able or takeover-able
Origin: null                             sandboxed iframe / data: URL can send this
```

An origin you control being reflected together with `Access-Control-Allow-Credentials: true` is the reportable case. If only a legitimate subdomain reflects, the finding depends on chaining an XSS or takeover on that subdomain — on its own, per project policy, it is not submitted.

Also check the `http://` variant of an allowed origin: if `http://target.com` is accepted, an attacker positioned on the network can break TLS protections for the whole API.

## Operator Notes (Battle-Tested)

- **MEMORY: ALL CORS findings are FP on Intigriti** — stop hunting/reporting CORS entirely on Intigriti programs. Only report if evil.com (not *.target.com) is reflected
- **MEMORY: subdomain-only reflection = reject** — `*.target.com` reflection requires XSS chain on a subdomain to be exploitable. Only report if arbitrary origin is reflected
- **MUST show specific data in PoC** — "CORS is misconfigured" alone = rejected. PoC must demonstrate specific PII/token theft via `fetch(..., {credentials: 'include'})`
- **pekko-http/akka-http default = easy win** — these frameworks reflect all origins by default. Check server header for identification
- **Null origin via sandboxed iframe** — `<iframe sandbox="allow-scripts" srcdoc="...">` sends origin: null. Some CORS configs accept null
- **XSS on trusted subdomain enables CORS exfil** — if any ACAO-trusted subdomain has XSS, chain it to steal data from CORS-protected API
- **Always test authenticated endpoints** — CORS on public/unauthenticated endpoints = informational only. Must show credentialed cross-origin read

## Related Skills & Chains

| Situation | Pattern / Skill |
|-----------|----------------|
| Need XSS on trusted subdomain for chain | `xss-testing` |
| postMessage alternative for cross-origin | `postmessage-exploitation` |
| OAuth flow with CORS implications | `oauth-testing` |
| CSRF angle on same endpoints | `csrf-testing` |
| API security testing methodology | `api-security-testing` |
| Chain escalation matrix | `auto-chain-discovery` |
