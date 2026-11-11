---
name: subdomain-enum-protocol
description: "Coverage protocol for subdomain enumeration on large multinational targets — enumerate every root domain and legacy brand, batch subfinder with crt.sh and passive sources, cover country TLDs, and audit for enumeration bias. Use at the start of any engagement with more than a handful of roots, and again whenever recon is about to be declared complete."
---

# Subdomain Enumeration Coverage Protocol

> **Origin**: target-corp recon failure — only 22/169 (13%) root domains had subdomain enumeration.
> `example.target.com` (confirmed SQLi, PHP/MariaDB) was never discovered because
> `example.target.com` was never fed to subfinder. Cost: missed HIGH+ finding on a low-competition asset.

---

## Part 1: Root Cause Analysis

### Why 13% Coverage Happened

The recon pipeline had a structural gap between **root domain discovery** (SecurityTrails keyword search) and **subdomain enumeration** (subfinder/crt.sh). SecurityTrails returned 10,199 domains containing "target-corp", including 169 unique `target-corp.*` root domains across 50+ country TLDs. The hunter manually selected 22 "important" roots and ran subfinder on those. Nobody checked whether the other 147 were enumerated.

### Cognitive Biases That Caused the Miss

| Bias | How It Manifested | Correction |
|------|-------------------|------------|
| **Selection bias** | Picked "major market" TLDs (.com, .de, .co.uk) because they seemed most important | ALL root domains get enumerated, regardless of perceived importance |
| **Availability heuristic** | example.target.com returned 3000+ subdomains, so it felt like "enough recon" | Volume on one root says nothing about coverage of other roots |
| **False equivalence** | Treated "root domain responds to httpx" as "this TLD is covered" | httpx on root != subdomain enumeration. Root may 301 to example.target.com while subdomains host unique apps |
| **Country TLD blindness** | Assumed example.target.com is "just the Indonesian homepage" | Country sites have local dev teams, different stacks, unique features, weaker security |
| **Anchoring** | Anchored on the "big" domains because SecurityTrails showed them first | Sort by coverage gap, not by familiarity |

### Why Country TLDs Are Actually HIGH Priority

Country-specific domains for multinational corporations consistently exhibit:

1. **Different technology stacks** — HQ runs AEM/Angular/Akamai; example.target.com runs PHP/MariaDB with no WAF. Local agencies choose their own stack.
2. **Weaker security posture** — Local dev teams have smaller budgets, less security review, no dedicated AppSec.
3. **Custom features** — Used car portals, dealer locators, finance calculators, parts ordering, booking systems. These are bespoke applications.
4. **Hidden subdomains** — admin.*, api.*, dealer.*, staging.*, legacy.* — not linked from main site, not discoverable without subdomain enumeration.
5. **Lower hunter competition** — 90% of hunters target example.target.com. Almost nobody checks example.target.com, example.target.com, example.target.com.br.
6. **Legacy applications** — Country sites may still run ASP, PHP 5.x, WordPress, Joomla, custom CMS. Easy targets.
7. **PROVEN pattern** — target-corp Indonesia: `example.target.com` = PHP/MariaDB custom app with confirmed SQLi. target-corp Korea: `example.target.com` = separate platform. target-corp China: `example.target.com`, `afc.com.cn` = unique apps.

**The "Country TLD Goldmine" heuristic**: For any multinational target, sort root domains by:
1. Asia-Pacific TLDs (.co.id, .co.kr, .co.jp, .com.cn, .co.th, .com.my, .com.ph) — highest probability of unique legacy apps
2. Latin America (.com.br, .com.ar, .com.mx, .cl, .co) — often outsourced to local agencies
3. Eastern Europe (.pl, .cz, .ro, .hu, .bg, .hr, .rs) — smaller markets, less security investment
4. Africa/Middle East (.co.za, .com.tr, .co.il, .ae) — unique regional features
5. Western Europe (.de, .fr, .it, .es, .nl, .at, .ch) — may share HQ platform but often have unique dealer portals

---

## Part 2: Subdomain Enumeration Coverage Protocol

### Step 1: Root Domain Extraction

After ANY domain discovery phase (SecurityTrails, Amass, manual scope, ASN lookup), extract ALL unique root domains:

```bash
# From SecurityTrails keyword search output
# Input: raw domain list (one per line)
# Output: unique root domains accounting for ccTLDs

python3 -c "
import sys
from collections import defaultdict

# Known 2-part ccTLDs
CC2 = {'co.id','co.kr','co.jp','co.uk','co.nz','co.za','co.th','co.il','co.in',
        'com.au','com.br','com.cn','com.my','com.ph','com.sg','com.tr','com.tw',
        'com.ar','com.mx','com.co','com.hk','com.vn','com.pk','com.eg','com.ng',
        'com.sa','com.ae','com.kw','com.qa','com.om','com.bh','com.ec','com.pe',
        'com.uy','com.py','com.bo','com.gt','com.sv','com.hn','com.ni','com.cr',
        'com.pa','com.do','com.cu','com.jm','com.tt','com.bd','com.np','com.lk',
        'com.mm','com.kh','com.la','or.kr','or.jp','ne.jp','ac.uk','org.uk',
        'gov.uk','net.au','org.au','co.at','or.at','gv.at'}

roots = set()
for line in sys.stdin:
    d = line.strip().lower().rstrip('.')
    if not d: continue
    parts = d.split('.')
    if len(parts) < 2: continue
    # Check 2-part ccTLD
    suffix2 = '.'.join(parts[-2:])
    if len(parts) >= 3 and suffix2 in CC2:
        root = '.'.join(parts[-3:])
    else:
        root = '.'.join(parts[-2:])
    roots.add(root)

for r in sorted(roots):
    print(r)
" < all_discovered_domains.txt > all_root_domains.txt

echo "[*] Total unique root domains: $(wc -l < all_root_domains.txt)"
```

### Step 2: Tiered Prioritization

When root domain count is large (>50), process in tiers. ALL tiers MUST be completed — tiering is about ORDER, not about skipping.

```bash
# Tier 1: Country/regional TLDs (HIGHEST VALUE — run first)
grep -E '\.(co\.|com\.)[a-z]{2}$' all_root_domains.txt > tier1_country.txt
# Also grab single ccTLDs for the brand
grep -E '^(target-corp|mini|rollsroyce)\.[a-z]{2}$' all_root_domains.txt >> tier1_country.txt
sort -u -o tier1_country.txt tier1_country.txt

# Tier 2: Corporate/product domains (known brands)
grep -vf tier1_country.txt all_root_domains.txt | \
  grep -E '(group|usa|finance|financial|bank|credit|leasing|insurance|motorsport|dealer|fleet)' > tier2_corporate.txt

# Tier 3: Everything else
cat tier1_country.txt tier2_corporate.txt | sort -u > tiers_12.txt
grep -vf tiers_12.txt all_root_domains.txt > tier3_remaining.txt

echo "Tier 1 (country TLDs, HIGHEST VALUE): $(wc -l < tier1_country.txt)"
echo "Tier 2 (corporate/product): $(wc -l < tier2_corporate.txt)"
echo "Tier 3 (remaining): $(wc -l < tier3_remaining.txt)"
```

### Step 3: Batch Subdomain Enumeration (ALL tiers)

```bash
# === subfinder — parallel, 5 at a time ===
# WSL Kali with VPN (some DNS resolvers are geo-restricted)

enumerate_roots() {
    local input_file="$1"
    local tier_name="$2"
    local output_dir="recon/subdomains"
    
    echo "[*] Enumerating $tier_name: $(wc -l < $input_file) roots"
    
    while read domain; do
        outfile="${output_dir}/subfinder_${domain}.txt"
        if [ -s "$outfile" ]; then
            echo "[SKIP] $domain — already enumerated ($(wc -l < $outfile) subs)"
            continue
        fi
        echo "[ENUM] subfinder -d $domain"
        subfinder -d "$domain" -all -silent > "$outfile" 2>/dev/null
        # Respect rate limits
        sleep 1
    done < "$input_file"
}

enumerate_roots tier1_country.txt "Tier 1 — Country TLDs"
enumerate_roots tier2_corporate.txt "Tier 2 — Corporate"
enumerate_roots tier3_remaining.txt "Tier 3 — Remaining"

# === crt.sh batch — sequential with rate limiting ===
while read domain; do
    outfile="recon/subdomains/crtsh_${domain}.txt"
    if [ -s "$outfile" ]; then continue; fi
    curl -s "https://crt.sh/?q=%25.${domain}&output=json" 2>/dev/null | \
        jq -r '.[].name_value' 2>/dev/null | \
        grep -v '^\*\.' | sort -u > "$outfile"
    sleep 3  # crt.sh rate limit
done < all_root_domains.txt

# === dnsx verification (resolve all discovered subdomains) ===
cat recon/subdomains/subfinder_*.txt recon/subdomains/crtsh_*.txt | \
    sort -u | \
    dnsx -silent -a -resp > recon/subdomains/dnsx_resolved.txt

# === Final merge ===
cat recon/subdomains/subfinder_*.txt recon/subdomains/crtsh_*.txt | \
    sort -u > recon/subdomains/merged_subdomains.txt

echo "[*] Total unique subdomains: $(wc -l < recon/subdomains/merged_subdomains.txt)"
```

### Step 4: Coverage Audit (MANDATORY — blocks pipeline if incomplete)

```bash
#!/bin/bash
# recon_coverage_audit.sh — Run after subdomain enumeration
# Exit 0 = complete, Exit 2 = gaps found

ROOT_FILE="all_root_domains.txt"
SUB_DIR="recon/subdomains"
TOTAL_ROOTS=$(wc -l < "$ROOT_FILE")
ENUM_ROOTS=0
MISSING_ROOTS=()
ZERO_RESULT_ROOTS=()

while read domain; do
    sf="${SUB_DIR}/subfinder_${domain}.txt"
    ct="${SUB_DIR}/crtsh_${domain}.txt"
    
    if [ -s "$sf" ] || [ -s "$ct" ]; then
        ENUM_ROOTS=$((ENUM_ROOTS + 1))
        # Check for zero results
        sf_count=$([ -f "$sf" ] && wc -l < "$sf" || echo 0)
        ct_count=$([ -f "$ct" ] && wc -l < "$ct" || echo 0)
        if [ "$sf_count" -eq 0 ] && [ "$ct_count" -eq 0 ]; then
            ZERO_RESULT_ROOTS+=("$domain")
        fi
    else
        MISSING_ROOTS+=("$domain")
    fi
done < "$ROOT_FILE"

COVERAGE=$((ENUM_ROOTS * 100 / TOTAL_ROOTS))

echo "═══ SUBDOMAIN ENUM COVERAGE AUDIT ═══"
echo "Root domains discovered: $TOTAL_ROOTS"
echo "Root domains enumerated: $ENUM_ROOTS"
echo "Coverage: ${COVERAGE}%"
echo ""

if [ ${#MISSING_ROOTS[@]} -gt 0 ]; then
    echo "NOT ENUMERATED (${#MISSING_ROOTS[@]} roots):"
    printf '  %s\n' "${MISSING_ROOTS[@]}"
    echo ""
fi

if [ ${#ZERO_RESULT_ROOTS[@]} -gt 0 ]; then
    echo "ZERO RESULTS (${#ZERO_RESULT_ROOTS[@]} roots — verify DNS resolves):"
    printf '  %s\n' "${ZERO_RESULT_ROOTS[@]}"
    echo ""
fi

if [ "$COVERAGE" -lt 100 ]; then
    echo "STATUS: INCOMPLETE — ${#MISSING_ROOTS[@]} roots need enumeration"
    echo "ACTION: Run subfinder + crt.sh on missing roots before proceeding"
    exit 2
else
    echo "STATUS: COMPLETE — all root domains enumerated"
    exit 0
fi
```

### Step 5: Time/Rate Limit Management

For large root domain sets (100+), estimated times:

| Tool | Rate | 169 domains | Mitigation |
|------|------|-------------|------------|
| subfinder | ~5-15s/domain | ~15-45 min | Parallel 5x = 3-9 min |
| crt.sh | ~3s + 3s sleep | ~17 min | No parallelism (rate limited) |
| dnsx | batch mode | ~2-5 min total | Single batch on merged file |

**Total for 169 roots: ~25-60 minutes.** This is negligible compared to the testing phase (hours/days). There is NO valid time excuse for skipping roots.

**If rate limited:**
- subfinder: reduce parallelism to 2, add `-timeout 30`
- crt.sh: increase sleep to 5s, retry on 429
- Use alternating DNS resolvers: `subfinder -rL resolvers.txt`

---

## Part 3: Pipeline Integration

### Where This Check Fits

```
SecurityTrails / Amass / Scope Discovery
    ↓
Extract root domains (all_root_domains.txt)        ← NEW STEP
    ↓
Tiered subdomain enumeration (ALL roots)           ← NEW STEP
    ↓
Coverage audit (100% root coverage required)        ← NEW GATE
    ↓
Alive probing (httpx on merged_subdomains.txt)
    ↓
Tech fingerprinting
    ↓
[... rest of pipeline ...]
```

### Integration with recon_enforcer.py

The existing `check_subdomain_discovery()` function in `tools/recon_enforcer.py` validates:
- Minimum 2 tools used
- Minimum 5 unique subdomains
- merged_subdomains.txt exists

**It does NOT validate root domain coverage.** Add a new check:

```python
# In check_subdomain_discovery(), add after existing checks:

# Check 4: Root domain coverage
root_file = target_path / "recon" / "subdomains" / "all_root_domains.txt"
if root_file.exists():
    total_roots = _count_lines(root_file)
    enumerated_roots = 0
    with open(root_file, "r") as f:
        for line in f:
            root = line.strip()
            if not root:
                continue
            sf = sub_dir / f"subfinder_{root}.txt"
            ct = sub_dir / f"crtsh_{root}.txt"
            if (sf.exists() and sf.stat().st_size > 0) or \
               (ct.exists() and ct.stat().st_size > 0):
                enumerated_roots += 1
    
    coverage_pct = (enumerated_roots / total_roots * 100) if total_roots > 0 else 100
    
    if coverage_pct < 95:
        checks_passed -= 1  # Fail the stage
        issues.append(
            f"Root domain coverage: {enumerated_roots}/{total_roots} ({coverage_pct:.0f}%). "
            f"MUST enumerate ALL root domains. Run: "
            f"comm -23 <(sort all_root_domains.txt) "
            f"<(ls subfinder_*.txt | sed 's/subfinder_//;s/.txt//' | sort)"
        )
```

### Concrete Recon Coverage Audit Step

Add to the recon pipeline (after subfinder/crt.sh, before httpx):

```bash
# === RECON COVERAGE AUDIT (BLOCKING) ===
# This runs automatically after subdomain enumeration

echo "[GATE] Checking subdomain enum coverage..."

# 1. Count root domains
if [ ! -f "recon/subdomains/all_root_domains.txt" ]; then
    echo "[WARN] all_root_domains.txt missing — cannot audit coverage"
    echo "[ACTION] Generate it from SecurityTrails/scope data first"
    exit 2
fi

TOTAL=$(wc -l < recon/subdomains/all_root_domains.txt)
DONE=$(ls recon/subdomains/subfinder_*.txt 2>/dev/null | wc -l)
PCT=$((DONE * 100 / TOTAL))

echo "[COVERAGE] $DONE/$TOTAL root domains enumerated ($PCT%)"

if [ "$PCT" -lt 95 ]; then
    echo "[BLOCKED] Subdomain enumeration incomplete. Fix before proceeding."
    comm -23 \
        <(sort recon/subdomains/all_root_domains.txt) \
        <(ls recon/subdomains/subfinder_*.txt | sed 's/.*subfinder_//;s/\.txt$//' | sort) \
    | head -20
    exit 2
fi

echo "[PASS] Root domain coverage >= 95%"
```

### How to Detect Incomplete Enumeration

Signs that subdomain enumeration is incomplete:
1. `all_root_domains.txt` has more entries than `subfinder_*.txt` files
2. Recorded facts/assets show only one platform type (e.g., only AEM/Angular — missing legacy stack variants)
3. merged_subdomains.txt dominated by subdomains of 2-3 roots (coverage skew)
4. Zero results for entire country TLD group (e.g., no `.co.*` results)
5. httpx alive list lacks geographic diversity (all English-language sites)

---

## Part 4: Anti-Pattern Documentation

### Anti-Pattern 1: "Only Enumerate Major-Market TLDs"

**Fallacy**: "example.target.com and target-corp.de are the important ones. example.target.com is just a redirect."

**Reality**: Major-market sites are the MOST hardened (dedicated AppSec teams, WAF, modern stack). Country TLDs run by local agencies with PHP/ASP/WordPress = easy targets. The competition is lowest on country TLDs because every hunter makes this same mistake.

**Fix**: Enumerate ALL roots. Sort by country TLD tier (Asia-Pacific first), not by "perceived importance."

### Anti-Pattern 2: "Root Domain Responded to httpx = No Need for Subdomain Enum"

**Fallacy**: "httpx shows example.target.com returns 200/301. It's just the country homepage. Done."

**Reality**: The root domain tells you NOTHING about subdomains. `example.target.com` may be a simple redirect, but `example.target.com`, `dealer.example.target.com`, `api.example.target.com`, `admin.example.target.com` could each be entirely different applications. httpx on the root is NOT subdomain discovery.

**Fix**: httpx on root domain is for alive-probing, not discovery. Subdomain enumeration (subfinder + crt.sh) is a separate, mandatory step for EVERY root domain.

### Anti-Pattern 3: "SecurityTrails Already Found Everything"

**Fallacy**: "SecurityTrails returned 10,199 domains. That's comprehensive enough."

**Reality**: SecurityTrails keyword search finds domains containing "target-corp" in existing DNS records. It does NOT perform subdomain brute-forcing. It misses:
- Subdomains not in its database (staging-*, internal-*, legacy-*)
- Recently created subdomains
- Subdomains on less-monitored roots
- Wildcard DNS subdomains

**Fix**: SecurityTrails is Phase 1 (root domain discovery). subfinder/crt.sh is Phase 2 (subdomain enumeration per root). They serve different purposes. Both are mandatory.

### Anti-Pattern 4: "Small Country Site = Low Value"

**Fallacy**: "target-corp Indonesia is a small market. Not worth the effort."

**Reality**: "Small market" = small security budget = highest vulnerability density. The ROI formula is:

```
ROI = P(vuln) * Bounty / Time
```

For country TLDs:
- P(vuln) is HIGHER (weaker security, legacy tech, custom code)
- Bounty is the SAME (same bug bounty program)
- Time is LOWER (less WAF, simpler apps, fewer auth gates)
- Competition is LOWER (most hunters skip these)

This makes country TLDs the HIGHEST ROI targets in any multinational program.

**Fix**: Prioritize country TLDs ABOVE the main domain. Enumerate them first. Test them first.

### Anti-Pattern 5: "I'll Get to the Other Roots Later"

**Fallacy**: "Let me finish testing example.target.com first, then I'll enumerate the other 147 roots."

**Reality**: "Later" never comes. Subdomain enumeration is a batch operation that takes 30-60 minutes. It should run at the START as a batch job, not be deferred. By the time you finish testing example.target.com, you've forgotten about the other roots.

**Fix**: Enumerate ALL roots in a single batch at the beginning of the engagement. It runs in background. Zero reason to defer.

---

## Appendix: Quick-Reference Commands

```bash
# Full pipeline for a new multinational target
# 1. SecurityTrails keyword search
curl -s "https://api.securitytrails.com/v1/domain/search" \
  -H "apikey: $ST_KEY" \
  -H "Content-Type: application/json" \
  -d '{"query":"keyword_contains:target-corp"}' | jq -r '.records[].hostname' > st_keyword.txt

# 2. Extract root domains
python3 extract_roots.py < st_keyword.txt > all_root_domains.txt

# 3. Tier + batch enumerate (ALL roots)
# (see Step 2 and Step 3 above)

# 4. Coverage audit
bash recon_coverage_audit.sh

# 5. Merge + alive probe
cat recon/subdomains/subfinder_*.txt recon/subdomains/crtsh_*.txt | sort -u > recon/subdomains/merged_subdomains.txt
cat recon/subdomains/merged_subdomains.txt | httpx -td -sc -title -o recon/probe/httpx_alive.txt
```

## Operator Notes (Battle-Tested)

- **13% coverage cost a HIGH+ finding**: target-corp Indonesia `example.target.com` (PHP/MariaDB, confirmed SQLi) was never discovered because `example.target.com` was never fed to subfinder. This protocol exists to prevent that.
- **Country TLDs are HIGHEST ROI**: Local agencies choose their own stack (PHP/ASP/WordPress instead of AEM/Angular/Akamai). Smaller budgets, less security review, lower hunter competition. Enumerate them FIRST.
- **30-60 minutes for 169 roots**: Subdomain enumeration is a batch operation that runs in background. There is ZERO valid time excuse for skipping roots.
- **httpx on root domain is NOT subdomain discovery**: Root may 301 to main site while subdomains host completely different applications. Subdomain enumeration is a separate mandatory step.
- **SecurityTrails is Phase 1, subfinder is Phase 2**: SecurityTrails finds root domains via keyword search. subfinder/crt.sh discovers subdomains per root. They serve different purposes and both are mandatory.
- **Coverage audit BLOCKS pipeline**: If audit returns < 95% coverage, the hunting pipeline is blocked until missing roots are enumerated.

## Related Skills & Chains

| Pattern | Chain Potential |
|---------|---------------|
| `wildcard-scope-dive` | Methodology after coverage is complete |
| `internal-portal-discovery` | Internal portal hunting on discovered subs |
| `origin-ip-discovery` | CDN bypass on discovered hosts |
| `subdomain-takeover` | Takeover check on all discovered subs |
| `403-bypass` | Bypass classification on discovered hosts |
