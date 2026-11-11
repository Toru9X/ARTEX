# PART 1: AJAX / Hidden Endpoint Discovery

### 1.1 Why External JS Grep Is Insufficient

Modern web apps split logic across:
- **External JS files** (`.js` loaded via `<script src="...">`) -- what we typically grep
- **Inline `<script>` blocks** in HTML -- what we missed
- **HTML event attributes** (`onclick="..."`, `onchange="..."`, `onsubmit="..."`)
- **Dynamically generated JS** (server-rendered, template-injected)
- **Lazy-loaded chunks** (webpack code-split, imported on user action)
- **Web Workers / Service Workers**

The `xoxo_fetch_buyusedcars_filtersearch` action was in an **inline script block** inside the HTML page. Grepping only external `.js` files will NEVER find it.

### 1.2 Systematic AJAX Endpoint Discovery Checklist

#### Step 1: Capture the FULL HTML source (not just JS files)

```bash
# Get full HTML source with all inline scripts
curl -sk "https://TARGET/page" -o page.html

# With browser rendering (captures dynamic HTML):
# Playwright: page.content() after load
# Or: view-source: in browser DevTools

# CRITICAL: Also fetch with AJAX headers to see alternate responses
curl -sk "https://TARGET/page" -H "X-Requested-With: XMLHttpRequest" -o page_xhr.html
```

#### Step 2: Extract ALL AJAX calls from HTML (inline + external)

```bash
# --- INLINE JS in HTML pages ---
# Extract inline script blocks
grep -oP '<script[^>]*>[\s\S]*?</script>' page.html | grep -v 'src=' > inline_scripts.txt

# Find $.ajax / jQuery.ajax calls
grep -oP '\$\.ajax\s*\(\s*\{[^}]+\}' page.html
grep -oP 'jQuery\.ajax\s*\(\s*\{[^}]+\}' page.html

# Find fetch() calls
grep -oP "fetch\s*\(\s*['\"][^'\"]+['\"]" page.html

# Find XMLHttpRequest.open
grep -oP "\.open\s*\(\s*['\"](?:GET|POST)['\"],\s*['\"][^'\"]+['\"]" page.html

# Find action= patterns (WordPress AJAX, custom handlers)
grep -oP "action[=:]\s*['\"]?\w+['\"]?" page.html

# Find data: { action: ... } patterns (jQuery AJAX)
grep -oP "data\s*:\s*\{[^}]*action\s*:\s*['\"][^'\"]+['\"]" page.html
grep -oP "'action'\s*:\s*'[^']+'" page.html
grep -oP '"action"\s*:\s*"[^"]+"' page.html

# Find URL patterns in inline JS
grep -oP "url\s*:\s*['\"][^'\"]+['\"]" page.html

# Find form action attributes
grep -oP 'action="[^"]+"' page.html
grep -oP "action='[^']+'" page.html

# --- EXTERNAL JS FILES ---
# Same patterns on each .js file
for jsfile in *.js; do
  echo "=== $jsfile ==="
  grep -oP "url\s*:\s*['\"][^'\"]+['\"]" "$jsfile"
  grep -oP "action[=:]\s*['\"]?\w+['\"]?" "$jsfile"
  grep -oP "fetch\s*\(\s*['\"][^'\"]+['\"]" "$jsfile"
done
```

#### Step 3: WordPress-specific AJAX discovery

WordPress AJAX handlers use `admin-ajax.php` (or WP REST API) with an `action` parameter. The action name maps to a PHP function registered with `add_action('wp_ajax_ACTION', ...)` or `add_action('wp_ajax_nopriv_ACTION', ...)`.

```bash
# Find WordPress AJAX actions in HTML and JS
grep -oP "action[=:]\s*['\"]?wp_ajax_[^'\"&\s]+|action[=:]\s*['\"]?[a-z_]+['\"]?" page.html *.js

# Common WordPress AJAX patterns
grep -oP "action=\w+" page.html *.js
grep -oP "admin-ajax\.php" page.html *.js
grep -oP "wp_ajax_\w+" page.html *.js
grep -oP "ajaxurl\s*[+,]" page.html *.js

# Custom AJAX action prefixes (like xoxo_ in our case)
# Look for ANY custom prefix patterns
grep -oP "action[=:]\s*['\"]?\w{2,}_\w+" page.html *.js

# WordPress REST API
grep -oP "/wp-json/[^'\"\s]+" page.html *.js
grep -oP "wp\.apiFetch|wp\.ajax" page.html *.js
```

#### Step 4: Playwright network interception (GOLD STANDARD)

```javascript
// Capture ALL XHR/Fetch requests during page interaction
const requests = [];
page.on('request', req => {
  if (req.resourceType() === 'xhr' || req.resourceType() === 'fetch') {
    requests.push({
      url: req.url(),
      method: req.method(),
      headers: req.headers(),
      postData: req.postData()
    });
  }
});

// Load page and interact with ALL interactive elements
await page.goto('https://TARGET/page');
await page.waitForLoadState('networkidle');

// Click every filter, dropdown, search, button, tab
const interactiveElements = await page.$$('select, input, button, [onclick], [data-action]');
for (const el of interactiveElements) {
  try { await el.click(); } catch(e) {}
  await page.waitForTimeout(1000);
}

console.log(JSON.stringify(requests, null, 2));
```

#### Step 5: Katana with XHR flag

```bash
# katana -xhr captures AJAX calls during headless crawl
katana -u "https://TARGET/" -duc -jc -kf all -fx -xhr -ef woff,css,png,svg,jpg,gif -o crawled.txt

# Filter for AJAX endpoints
grep -iE 'ajax|action=|api/|fetch|xhr' crawled.txt
```

### 1.3 Common AJAX Action Naming Patterns to Search For

| Platform | Pattern | Example |
|----------|---------|---------|
| WordPress | `action=prefix_verb_noun` | `action=xoxo_fetch_buyusedcars_filtersearch` |
| WordPress | `action=wp_verb_noun` | `action=wp_ajax_heartbeat` |
| WordPress | `action=pluginname_action` | `action=woocommerce_apply_coupon` |
| Laravel | `/api/verb-noun` | `/api/fetch-products` |
| Django | `/ajax/verb/` | `/ajax/search/` |
| Custom PHP | `action=verb_noun` | `action=get_filtered_results` |
| Custom PHP | `handler=name` | `handler=product_search` |
| ASP.NET | `/api/Controller/Action` | `/api/Cars/FilterSearch` |
| Node.js | `/api/resource/action` | `/api/cars/filter` |

**KEY INSIGHT**: The action name `xoxo_fetch_buyusedcars_filtersearch` follows the WordPress pattern `{prefix}_{verb}_{context}_{action}`. Always grep for `action=` in ALL HTML and JS sources, not just `url:`.

### 1.4 Tools That Would Have Caught This

| Tool | How | Command |
|------|-----|---------|
| **Playwright network capture** | Intercepts actual XHR during interaction | `page.on('request')` |
| **Burp Spider/Crawler** | Parses inline JS for URLs | Passive crawl with Burp proxy |
| **Katana -xhr** | Headless Chrome + XHR interception | `katana -u URL -xhr -jc` |
| **grep on HTML source** | Pattern match `action=` | `grep -oP "action[=:]\s*['\"]?\w+" page.html` |
| **GAP (Burp extension)** | Passive parameter collection | Auto from proxy history |
| **ParamSpider** | Wayback URL param mining | `paramspider -d target.com` |
| **Burp Traffic Logger** | Records ALL requests during manual browsing | Proxy History filter on XHR |

---

