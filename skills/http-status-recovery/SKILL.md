---
name: http-status-recovery
description: "Decision tree for recovering from HTTP status codes, curl/libcurl exit codes, TLS/HTTP2 errors, DNS failures and timeouts during recon/fuzzing -- what to retry, what to back off, and what to abandon immediately. Classifies 401 as interesting (application auth, keep testing) vs 403 as usually a network/CDN/WAF dead end, flags SPA catch-all routers before you waste a fuzzing run on them, and tells you when to slow down (429, Akamai) instead of retrying harder. Use this before and during any recon/fuzzing/scanning pass, whenever a tool call returns a non-200, a non-zero exit code, or no response at all. Does not cover WAF/403 bypass payloads themselves -- see 403-bypass and waf-bypass for that."
---

# HTTP Status & Error Recovery

A fast, deterministic answer to "I just got a non-200 / non-zero exit code -- what now?" Read this *before* deciding to retry, back off, switch tooling, or give up on a host/path. It is a triage step, not a bypass technique library -- once a 403/429/WAF is classified, hand off to `403-bypass` or `waf-bypass` for the actual payloads.

## The decision tree (work top to bottom, stop at first match)

1. **No response / connection-level failure** -- check the client's exit code first (curl exit codes table below). DNS failure and TLS/HTTP2 errors are client/network conditions, not findings; resolve them before touching the target again.
2. **HTTP 401** -- interesting. This is application-level auth, not an infra block. Keep testing: check token expiry, try other credentials/roles, try the request unauthenticated vs authenticated and diff the responses. A 401 on one path never means "the whole site is locked" -- fuzz for paths that return something other than 401.
3. **HTTP 403** -- classify before doing anything else (see "403 classification" below). Most 403s you'll see in bulk recon are network/CDN-level and are dead ends; a minority are application-level and worth a bypass attempt.
4. **HTTP 404 / 405** -- 404 is normal, move on. 405 means the path exists under a different verb: retry with GET/POST/PUT/PATCH/DELETE/OPTIONS before giving up on it.
5. **HTTP 429** -- you are being rate limited, not blocked. Honor `Retry-After` if present, otherwise back off exponentially and halve your request rate for that host. Treat this as a signal to slow the whole scan down, not just the one request.
6. **HTTP 5xx** -- usually transient (upstream overload/restart). Retry once or twice with a short delay; a 500 that reproduces on a specific payload (not just "flaky server") is worth a closer look, not an auto-retry-and-forget.
7. **Cloudflare 520-530** -- these are Cloudflare-specific edge errors, not your target's application responding. 523/525/530 mean the origin is effectively unreachable from the edge -- skip the host rather than retrying it repeatedly.
8. **TLS / HTTP2 errors** (handshake failure, cert errors, HTTP/2 stream error) -- retry once with `--tls-max 1.2` or `-k` (testing only) for TLS issues, or drop to `--http1.1` for HTTP/2 stream errors, before concluding the host is unreachable.
9. **Timeout** -- retry with a longer timeout (2x) up to 2 times. A host that times out on every single request (not just slow endpoints) is more likely geo-blocked, VPN-gated, or dead than "just slow" -- see step 10.
10. **Everything above passed but the target still behaves oddly** (every path "works", every path 403s identically, or the whole site is unreachable except one country-specific redirect) -- check for a geo-block or VPN requirement before concluding the target is broken: a 403 with a body containing "region"/"country"/"not available", a 301/302 to a country-specific path, or HTTP 451 are all geo-block signals, not network-level-403 signals.

## 403 classification: application-level vs network-level

**The 10-second test**: request the real path, then two random nonexistent paths, and compare `Content-Length` on all three.

```bash
curl -s -o /dev/null -w '%{http_code} %{size_download}\n' "$URL"
curl -s -o /dev/null -w '%{http_code} %{size_download}\n' "$URL/random-nonexistent-path-1"
curl -s -o /dev/null -w '%{http_code} %{size_download}\n' "$URL/random-nonexistent-path-2"
```

- **Same status + same Content-Length for all three** -> **network-level 403. Dead end. Stop immediately** -- this is a CDN/LB/WAF edge rejecting the connection before it ever reaches the application; no path-traversal, header, or encoding trick changes that.
- **Different Content-Length per path, or a JSON/HTML body with application branding** -> **application-level 403**. Worth a bypass attempt -- hand off to `403-bypass`.

### Known network-level 403 fingerprints (dead ends -- do not attempt bypass)

| Signature | Platform | Why it's a dead end |
|---|---|---|
| `Content-Length: 15` | AWS ELB | Fixed-size edge rejection, identical for every path |
| `Content-Length: 1484` | Azure Front Door | Fixed-size edge rejection |
| `Content-Length: 23` | AWS CloudFront | Fixed-size edge rejection |
| `{"message":"Forbidden"}` | AWS API Gateway | Fixed JSON body, no application routing happened |
| `~33KB` body containing a JS challenge | Vercel challenge | Browser-only bot challenge, not a path-based block |
| `cf-mitigated: challenge` | Cloudflare managed challenge | Browser-only; curl always gets 403 here regardless of path |
| Turnstile widget / `challenges.cloudflare.com` | Cloudflare Turnstile | Blocks automated login/registration, not path-specific |
| `X-L11-Trace: sgp1-lb*` + status 472/473 | Limelight CDN | CDN-level restriction, equivalent to the AWS/Azure cases above |
| Status 471 on POST | Limelight CDN (POST block) | Form submissions blocked at the CDN, not the app |
| Status 247 + a Reblaze challenge script in the body | Reblaze WAF | Bot-detection layer; everything behind it is also typically auth-gated |

These fingerprints are also available programmatically from `knowledge.InfraSignatures()` in this repo's `knowledge` Go package, so a worker can check a captured response against them without re-deriving the table.

## Detect the SPA catch-all before you fuzz

Before running any directory/path fuzz (`ffuf`, `feroxbuster`, `gobuster`, ...), probe 2-3 random nonexistent paths first:

```bash
curl -s -o /dev/null -w '%{http_code}\n' "$URL/this-path-does-not-exist-$RANDOM"
```

If that returns `200` (often with the same HTML shell/bundle every time), the app is an Angular/React/Vue SPA with a client-side router serving a catch-all 200 for any path -- raw status-code fuzzing is useless there and will produce a wall of false "found" paths. Switch strategy: fuzz for distinct response *size/title/JS-bundle references* instead of status code, or enumerate routes from the JS bundle / API calls instead of brute-forcing the path space.

## Curl / libcurl exit codes

| Exit code | Meaning | Action |
|---|---|---|
| 0 | success | none |
| 3 | malformed URL | fix the URL, don't retry as-is |
| 6 | could not resolve host (DNS failure) | check VPN/DNS, not a target-side finding |
| 7 | connection refused | port closed/firewalled; retry once, then skip |
| 22 | HTTP error (>=400 with `--fail`) | parse the actual status code, follow the tree above |
| 28 | timeout | retry with 2x `--connect-timeout`/`--max-time`, up to 2 times |
| 35 | TLS handshake failure | retry once with `--tls-max 1.2`, or `-k` for testing only |
| 47 | too many redirects | redirect loop -- skip this URL |
| 51 / 60 | certificate problem | retry once with `-k` for testing only |
| 52 | empty reply from server | may be a WAF silently dropping the connection; retry once |
| 56 | recv failure / connection reset mid-transfer | WAF or network issue; retry with delay, max 2 |
| 92 | HTTP/2 stream error | retry once with `--http1.1` |

## Rate limiting and WAF pacing -- slow down, don't retry harder

A fixed global retry policy is wrong for every WAF -- the right move on 429 (or a WAF challenge) is almost always to go slower on that host, not to hammer it with the same request again:

- **429 anywhere**: honor `Retry-After` if present; otherwise exponential backoff (5s -> up to ~300s) and halve the request rate for that host afterward.
- **Akamai** (`AkamaiGHost`, `X-Akamai-Transformed`, `akamai` in headers/cookies): drop to roughly 1 request per 5 seconds. Curl/httpx without a real browser TLS fingerprint gets blocked outright; a real browser session (Playwright) is usually required, not just a slower curl.
- **Cloudflare** (`cf-ray`, `cf-cache-status`, `__cfduid`): moderate pace (around 2 req/s) is usually fine for plain responses; a JS challenge page means you need a real browser, no amount of curl pacing fixes that.
- **Imperva/Incapsula** (`incap_ses_*`, `visid_incap_*`): low rate (~1 req/s), prefer browser-based testing.
- **ModSecurity / generic WAF**: moderate pace (~3 req/s) is usually tolerated; blocks here are payload-based, not rate-based -- see `waf-bypass` for the actual evasions.

## Related Skills & Chains

| Situation | Go to |
|---|---|
| 403 classified as application-level, need an actual bypass | `403-bypass` |
| Specific WAF identified (Cloudflare, Akamai, Imperva, F5, ...), need vendor-specific evasion | `waf-bypass` |
| Network-level 403/CDN confirmed, want to reach the origin directly | `origin-ip-discovery` |
| Sustained 429s across a whole engagement, need a pacing/queueing strategy | `rate-limit-bypass` |
| SPA catch-all detected, need to enumerate real routes from the bundle | `hidden-param-discovery` |
