---
name: encoding-obfuscation
description: "Obfuscate attack payloads to slip past input filters and WAFs by exploiting decoding discrepancies between layers — URL and double-URL encoding, HTML entities, XML character references, unicode escapes, hex and octal escapes, layered multi-encoding, and SQL CHAR()/CHR() construction. Use when a payload is blocked but the underlying parameter still reaches a sink, when a proxy or gateway decodes before the application does, or before concluding an injection point is not exploitable."
---

# Encoding and Obfuscation

A filter and the code behind it rarely see the same string. Every layer a request passes through — proxy, gateway, framework, template engine, database driver — may decode, normalize, or re-interpret the value. **Obfuscation is not about hiding a payload; it is about landing it in a form that is inert where the filter looks and live where it executes.**

That framing matters, because it tells you what to test. A payload that is simply "more encoded" usually fails. A payload encoded so that it survives the validator's view and is decoded exactly once more before the sink is what works.

## Crown Jewel Targets

- **Anything behind a sanitizing proxy or API gateway** — two parsers, two decoding schedules, one discrepancy (see `parser-differential-attacks`)
- **Legacy stacks with multiple decode passes** — Classic ASP, older Java servlet containers, and CGI wrappers frequently decode twice
- **WAF-protected injection points where the quote already passes** — the filter is keyword-based, so encoding the keyword is the whole exploit
- **Template-rendered pages** — the template engine adds a decode step the validator never modelled
- **Windows/IIS with PHP-CGI** — best-fit Unicode conversion creates characters out of nothing (see `windows-unicode-attacks`)

## Context-specific decoding — the core idea

Before encoding anything, work out **which decoders sit between your input and the sink**, and in what order. Each context has its own:

| Context | Decoder that runs | Consequence |
|---|---|---|
| URL path / query | URL decoding by the server, sometimes twice | `%2527` becomes `%27` becomes `'` |
| HTML body | HTML entity decoding by the browser | `&lt;` becomes `<` after the server's filter has passed |
| HTML attribute | HTML decode, then the attribute's own context | `&apos;` becomes `'` inside an event handler, then JS parses it |
| Inline event handler | HTML decode **then** JavaScript parse | two decoders, so two layers of encoding are available |
| JavaScript string | JS unicode/hex/octal escape processing | `alert` is `alert` to the engine, not to a keyword filter |
| XML / SOAP body | XML character-reference decoding | `&#x27;` becomes `'` at the parser, invisible to a body-scanning WAF |
| SQL query | no decoding — but the engine offers construction functions | `CHAR(39)` builds a quote without ever transmitting one |

**Decoding discrepancies** are what you are hunting: a place where one component decodes and another does not, or where one decodes *more times* than the other. When a single layer of encoding is rejected, the question is not "encode harder" — it is "which component decoded it, and can I make the *next* one do the decoding instead?"

## The encodings

### URL encoding, and double URL encoding
```
'            →  %27
<script>     →  %3Cscript%3E
'            →  %2527        (double — survives one decode, becomes %27, then ')
```
Double encoding is the highest-yield technique against a proxy that decodes once and forwards, because the proxy sees a harmless literal while the application performs the second decode.

Also test **partial** encoding — encoding only the character the filter keys on (`%2e%2e/` rather than the whole traversal) often passes where full encoding fails, since some filters normalise fully-encoded input but not mixed input.

### HTML encoding
```
<     &lt;    &#60;    &#x3c;    &#060;    &#x0003c;
'     &apos;  &#39;    &#x27;
```
Decimal and hex both accept **leading zeros** and the trailing semicolon is optional in many parsers — `&#x3c` and `&#0000060;` both work, and both defeat filters matching the exact string `&lt;`. Critically useful in **inline event handlers**, where HTML decoding happens before JavaScript parsing, so `&apos;);alert(1)//` becomes live syntax.

### XML encoding
```xml
<query>&#x27; OR 1=1--</query>
<user>&#x61;&#x64;&#x6d;&#x69;&#x6e;</user>
```
The XML parser resolves character references before the value reaches application code, so a WAF inspecting the raw body sees nothing injectable. This is the standard bypass for SOAP and XML-RPC endpoints, and it is what makes an XML-accepting variant of a JSON endpoint worth finding.

### Unicode escaping (JavaScript)
```javascript
alert(1)          // alert(1)
\u{61}lert(1)          // ES6 form
```
Applies inside JavaScript string and identifier positions. Useful where the filter blocks the literal token `alert`, `eval`, or `cookie`.

### Hex and octal escaping
```javascript
'\x61\x6c\x65\x72\x74'      // "alert"   — JS hex escape
'\141\154\145\162\164'      // "alert"   — JS octal escape
```
```bash
$'\x63\x61\x74' /etc/passwd    # shell hex
$'\143\141\164' /etc/passwd    # shell octal
```
Octal is the more useful of the two in practice, precisely because filters and WAF signatures model hex far more often than octal. Also valid in IP addresses (`0177.0.0.1` for `127.0.0.1`) — see `ssrf-testing`.

### Multiple / layered encodings
Combine schemes so each layer is stripped by a different component:
```
%2526lt%253Bscript%2526gt%253B      URL(URL(HTML))
&#x25;3Cscript&#x25;3E              HTML-encoded percent, decoded to %3C, then URL-decoded
```
Layering only works if you have mapped the decode order. Guessing produces noise; testing one layer at a time and observing which component strips it produces the working combination.

### SQL CHAR() / CHR() construction
```sql
-- build a string without a single quote anywhere in the request
SELECT CHAR(97,100,109,105,110)                    -- MySQL/MSSQL → 'admin'
SELECT CHR(97)||CHR(100)||CHR(109)                 -- Oracle/PostgreSQL → 'adm'
SELECT 0x61646d696e                                -- MySQL hex literal → 'admin'
```
This is the answer when quotes are blocked outright rather than escaped. Pair it with the operator-based payloads in `sql-injection-testing` when keyword filtering is also in play.

## Method

1. **Establish the sink and the decoders between you and it.** Do not encode before you know what decodes.
2. **Send each character class separately** (`'`, `<`, `>`, `(`, `;`, space) and record which are blocked, which are stripped, and which pass. A filter that blocks `<` but allows `&#x3c;` has told you exactly what to do.
3. **Test one encoding layer at a time.** If single-URL fails and double-URL works, you have located a proxy decode. That fact is reusable across the whole target.
4. **Insert a canary through each encoding** so you can tell "the payload was blocked" from "the payload arrived mangled" — these look identical in a response and lead to opposite conclusions.
5. **Re-test the working encoding on the sink you actually care about.** An encoding that passes the WAF on a harmless endpoint may be normalised differently on the injectable one.

A tooling note that has cost real findings on this project: verify your **wordlist and shell encoding** before blaming the target. A list saved as UTF-16 or carrying CR characters produces zero hits against every payload, which reads exactly like a well-defended target. Zero hits across a large list means suspect your tooling first.

## Using Burp Scanner during manual testing

Scanner is worth pointing at a single request rather than the whole site when you have found something interesting but cannot get a payload through:

- **Scan a specific request** — right-click in Repeater/Proxy → Scan, to audit just that one endpoint with full payload coverage
- **Custom insertion points** — mark the exact position inside a nested, encoded, or serialized value so Scanner injects *there* rather than at the top-level parameter. This is how you scan a value that is base64-inside-JSON-inside-a-parameter
- **Non-standard data structures** — define insertion points manually where Scanner cannot parse the format (custom serialization, proprietary encodings)

This complements manual work; it does not replace the character-class mapping above, which is what tells you *why* something is blocked.

## Impact Requirements

Obfuscation is never the finding. The finding is whatever the payload reached:
- A WAF bypass demonstrated in isolation is reportable only where the WAF is the stated security control (see `waf-bypass`)
- Otherwise the report is the underlying injection, with the encoding documented as the step that made it reachable
- Always include both the blocked and the working request, so the triager can see the filter and the bypass

## Related Skills & Chains

| When | Go to |
|------|-------|
| Vendor-specific WAF evasion needed | `waf-bypass` |
| Two parsers disagree on the same body | `parser-differential-attacks` |
| Encoding to reach an XSS sink | `xss-testing` |
| Encoding around SQL keyword filters | `sql-injection-testing` |
| Traversal sequence encoding | `lfi-path-traversal` |
| Windows best-fit / fullwidth conversion | `windows-unicode-attacks` |
| Alternative IP encodings for SSRF filters | `ssrf-testing` |
| Path/delimiter encoding against caches | `cache-poisoning` |

---

## Skill metadata

- **Pattern**: Encoding & Obfuscation (Essential Skills)
- **Severity**: N/A (enabling technique)
- **Tech**: generic, php, java, aspnet, nodejs, xml, soap, mysql, mssql, oracle, postgresql
- **Triggers**: `obfuscate payload`, `encoding bypass`, `double url encoding`, `html entity bypass`, `unicode escape`, `octal escape`, `hex escape`, `char()`, `filter bypass encoding`, `decoding discrepancy`
- **Related skills**: waf-bypass, parser-differential-attacks, xss-testing, sql-injection-testing, lfi-path-traversal, windows-unicode-attacks, ssrf-testing, cache-poisoning
- **Sources**: portswigger-academy (essential-skills/obfuscating-attacks-using-encodings, using-burp-scanner-during-manual-testing)
