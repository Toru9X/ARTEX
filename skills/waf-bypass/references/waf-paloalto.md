# Palo Alto Next-Generation Firewall

### Detection Signals
| Signal | Where |
|--------|-------|
| Block page: "Virus/Spyware Download Blocked" | Response body |
| Block page: "Palo Alto Next Generation Security Platform" | Response body |
| Block page: "Web Page Blocked" with PA branding | Custom block page |
| `X-PAN-*` headers | Sometimes in response |
| URL filtering category page | Redirect to block page |

### Bypass Strategy
- **Recommended tool**: curl/Burp. Palo Alto is primarily network firewall with URL filtering.
- **Key insight**: PA is NOT a traditional WAF — it's a next-gen firewall with URL filtering + threat prevention. App-layer inspection is less sophisticated than dedicated WAFs.
- **SSL decryption**: PA must decrypt TLS to inspect. If certificate pinning is in place or HSTS preloaded, inspection may be bypassed.
- **URL category bypass**: PA blocks by URL category. Try IP direct access or alternate domains.

### XSS/SQLi Bypass
```
# PA's threat prevention signatures are network-layer, not web-app-aware:
# Standard encoding bypasses usually work:
<svg/onload=alert`1`>
' /*!UNION*/ /*!SELECT*/ 1,2,3--

# Double encoding effective:
%253Cscript%253Ealert(1)%253C%252Fscript%253E

# PA primarily detects known exploit signatures (CVE-based), not generic payloads
```

### Rate Limiting
- Not primarily a rate-limiting device. Focus is on threat prevention.
- URL filtering may block categories but not rate-limit.
- If DoS protection enabled: configurable thresholds.

---

