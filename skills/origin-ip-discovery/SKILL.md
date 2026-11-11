---
name: origin-ip-discovery
description: "Find the real origin IP behind a WAF/CDN using DNS history, email headers, favicon hashing, Shodan/Censys certificate pivots, and F5 cookie decoding, then reach the admin panels and actuators the edge was hiding. Use when a target is fronted by Cloudflare/Akamai/CloudFront and edge rules are blocking testing."
---

# Origin IP Discovery Behind WAF/CDN

> Reference: Intigriti blog + H1 #1536299 (SMTP2GO Cloudflare bypass)

## Crown Jewel Targets

- **Unprotected admin panels** accessible directly on origin IP without WAF filtering
- **Internal services** (management ports, debug endpoints) exposed on origin but blocked by CDN rules
- **Spring Boot actuators** (`/actuator/env`, `/actuator/heapdump`) reachable after WAF bypass
- **Swagger/API docs** endpoints blocked by WAF rules but open on direct origin
- **Database admin interfaces** (phpMyAdmin, Adminer) hidden behind CDN-only access control
- **Development/staging environments** sharing origin IP with production

## Attack Surface Signals

- Multiple CDN providers in CNAME chain (Akamai -> EdgeOne = multi-CDN bypass potential)
- SPF records with `ip4:` entries that differ from CDN ranges
- `mail.`, `smtp.`, `direct.` subdomains resolving to non-CDN IPs
- F5 BIG-IP `BIGipServer` cookies in responses (decode to origin IP:port)
- `X-Backend-Server`, `X-Real-IP`, `X-Served-By` headers leaking origin
- Favicon hash on Shodan matching target with non-CDN IP
- Pre-CDN DNS history on SecurityTrails showing old A records

## CDN IP Ranges (exclude these — they're NOT origin)
- Cloudflare: https://www.cloudflare.com/ips/ (`103.21.244.0/22`, `104.16.0.0/13`, etc.)
- Akamai: varies by region, check `nslookup` → `a]N].akamai.net`
- AWS CloudFront: https://ip-ranges.amazonaws.com/ip-ranges.json (service=CLOUDFRONT)
- Fastly: https://api.fastly.com/public-ip-list
- Azure CDN: check for `azureedge.net` in CNAME

## Technique 1: DNS History (PASSIVE)
- SecurityTrails API: `curl "https://api.securitytrails.com/v1/history/TARGET.COM/dns/a" -H "apikey: KEY"`
- Look for A records BEFORE CDN onboarding
- crt.sh: `curl -s "https://crt.sh/?q=%25.TARGET.COM&output=json" | jq -r '.[].name_value' | sort -u`

## Technique 2: Subdomain Resolution (PASSIVE)
Common non-proxied subdomains:
- `mail.`, `smtp.`, `webmail.`, `mx.` (email infrastructure)
- `direct.`, `origin.`, `backend.`, `real.` (direct access)
- `staging.`, `dev.`, `test.`, `uat.` (pre-production)
- `vpn.`, `ftp.`, `cpanel.`, `whm.` (management)
- `api.` (sometimes not behind CDN)

Compare: CDN subnet IPs vs unique IPs from subdomains. Unique = potential origin.

## Technique 3: Email Header Analysis (PASSIVE)
1. Trigger email from target (signup, password reset, contact form)
2. Inspect `Received:` headers for origin IP
3. Check SPF: `dig TXT TARGET.COM` → `ip4:` entries may reveal origin
4. Check MX: `dig MX TARGET.COM` → mail server may share IP with web
5. NOTE: If using SendGrid/SES/Mailgun → email IP ≠ web server IP

## Technique 4: Favicon Hash (PASSIVE)
```bash
# Get favicon hash
curl -s 'https://TARGET.COM/favicon.ico' | python3 -c "
import mmh3, sys, codecs
print(mmh3.hash(codecs.encode(sys.stdin.buffer.read(),'base64')))
"
# Search Shodan: http.favicon.hash:<HASH>
# Search Censys: services.http.response.body_hash:<HASH>
```

## Technique 5: Unique String Search (PASSIVE)
- Copyright text: `"© 2024 TARGET Corp"` → Shodan/Censys
- Google Analytics: `UA-XXXXXX` or `G-XXXXXX` → search other IPs with same tag
- Custom headers: `X-Custom-Header` unique to target
- HTML comments, meta tags, unique CSS class names

## Technique 6: Error Page / Debug Headers (LOW NOISE)
- Malformed requests → verbose errors with IP
- `X-Backend-Server` header
- F5 BIG-IP cookie decode:
```python
import struct
cookie = "1677787402.36895.0000"  # BIGipServer cookie
(host, port, _) = cookie.split(".")
(a, b, c, d) = struct.pack("<I", int(host))
print(f"{a}.{b}.{c}.{d}:{struct.unpack('<H', struct.pack('<H', int(port) >> 8 | (int(port) & 0xff) << 8))[0]}")
```

## Technique 7: SSRF/XXE/Webhook Chain
- If SSRF exists → probe internal metadata for outbound IP
- Register webhook → target calls back → reveals origin IP
- XXE with external entity → callback to attacker server

## Validation
```bash
# Once candidate IP found:
curl -sI -H "Host: TARGET.COM" http://CANDIDATE_IP/
# Compare response with CDN response — same content = confirmed origin
```
- Use Burp: add hostname resolution (TARGET.COM → CANDIDATE_IP)
- ALWAYS verify: same content, not shared hosting neighbor

## Impact
- Origin IP exposed = bypass WAF entirely
- Direct attacks without WAF filtering
- DDoS directly to origin (mention, don't demonstrate)
- Access internal services not exposed through CDN

## Case Study: SMTP2GO (H1 #1536299)
- Cloudflare protected web server
- Email service exposed origin IP in SMTP headers
- Researcher found origin → accessed admin panel directly → bypassed WAF
- Bounty awarded for WAF bypass + exposed admin panel

---

## Operator Notes (Battle-Tested)

- **Email headers are the #1 passive technique** — trigger signup/reset/contact form email and check `Received:` headers. Works even when all other methods fail
- **SPF records often leak origin** — `dig TXT target.com` reveals `ip4:` entries that may be the origin server, not email-only
- **F5 BIG-IP cookie decoding is free wins** — `BIGipServer` cookie in response = instant origin IP decode. Use the struct.pack script
- **Favicon hash search on Shodan is underrated** — compute mmh3 hash of `/favicon.ico`, search `http.favicon.hash:HASH` on Shodan/Censys for non-CDN IPs serving same favicon
- **Always validate with Host header** — `curl -sI -H "Host: TARGET.COM" http://CANDIDATE_IP/` must return matching content. Same favicon but different content = shared hosting neighbor
- **Multi-CDN = bypass outer WAF** — CNAME chain like Akamai -> EdgeOne means inner CDN IP bypasses outer WAF (MEMORY: EdgeOne CDN bypass pattern)
- **After origin found, check /actuator, /swagger, /v2/api-docs** — these are commonly blocked by WAF but wide open on origin

## Related Skills & Chains

| Situation | Pattern / Skill |
|-----------|----------------|
| Origin found, need to bypass WAF on it | `waf-bypass` → `references/waf-generic-evasion.md` |
| 403 responses on origin — classify first | `403-bypass` |
| WAF fingerprinted, need per-WAF bypass | `waf-bypass` |
| Host header attacks on discovered origin | `host-header-attacks` |
| SSRF to probe internal from origin | `ssrf-testing` |
| Admin portal found on origin IP | `internal-portal-discovery` |
