---
name: waf-bypass
description: "Per-WAF detection signals and bypass playbooks for 16 WAFs (Cloudflare, Akamai, AWS WAF, ModSecurity, Imperva, F5, Sucuri, Barracuda, FortiWeb, DotDefender, Wordfence, NetScaler, Palo Alto, NAXSI, WebKnight, Reblaze) with sqlmap tamper selection, rate-limit behaviour, and origin-IP fallback. Use when payloads start returning 403/406/429 before concluding an endpoint is not injectable, and to identify the unprotected hosts that need no evasion at all."
---

# WAF Bypass Matrix

## Crown Jewel Targets

- **"No WAF" hosts** -- `grep "none" waf_mapping.txt` finds unprotected hosts. These are goldmines: no encoding needed, raw payloads work, fastest path to findings
- **Akamai Kona targets** -- hardest WAF but highest-value enterprise targets (banks, Fortune 500). EXEC() wrapper + stacked queries is the proven MSSQL bypass (target-corp DealerNet pattern)
- **Cloudflare free/pro plan sites** -- weaker rule sets than Enterprise. Mutation XSS, SVG+use, and double-encoding bypass standard rules
- **Sucuri / Reblaze targets** -- DNS-level proxy WAFs. Find origin IP = complete WAF bypass. Origin IP discovery is the primary strategy, not encoding
- **F5 BIG-IP targets** -- BIGipServer cookie LEAKS internal IP. Decode cookie for origin IP. HPP bypass is highly effective for SQLi
- **ModSecurity PL1 (default)** -- many known bypasses. MySQL version comments pass. Detect paranoia level by sending increasingly suspicious payloads
- **Legacy WAFs** (DotDefender, WebKnight) -- EOL products with basic regex rules. Standard case-toggling and comment injection work reliably

## Attack Surface Signals

- **WAF detection flow**: `nuclei` WAF templates (shipped) then manual header check; `wafw00f TARGET` is faster but is not installed in this image
- **Key cookies**: `_abck`/`ak_bmsc` (Akamai), `__cf_bm`/`cf-ray` (Cloudflare), `incap_ses_*` (Imperva), `BIGipServer*` (F5), `sucuri_cloudproxy_uuid_*` (Sucuri)
- **Key headers**: `x-amzn-RequestId` (AWS), `x-cnection` (F5 typo), `nnCoection` (NetScaler), `X-dotDefender-denied` (DotDefender)
- **Internal IP leak indicators**: F5 BIGipServer cookie, NetScaler NSC_ cookie, `x-backend-server` headers

Per-WAF detection signals, bypass techniques, and tool recommendations for bug bounty hunting.

> **Tooling note for the per-WAF references below**: several of them reach for
> `uncover` to find origin IPs. It is not installed here, and it is an API client
> for Shodan/Censys/Fofa, so it needs keys even once installed — treat it as
> optional. The origin-IP techniques that work with what ships are in
> `origin-ip-discovery`: historical DNS, SPF/MX records, certificate transparency
> via crt.sh, and `-H Host:` probing of candidate IPs with curl.

**Usage**: When httpx/curl returns WAF-specific headers or cookies, look up the WAF below and adjust tooling + payloads accordingly.

---

## Quick Reference: WAF Detection — Optimal Flow

### Fastest Detection (recommended order)
```bash
# Step 1: nuclei WAF detection — shipped, templates already on disk
nuclei -u https://TARGET -t /opt/nuclei-templates/http/technologies/ -tags waf -silent

# Step 2 (optional): wafw00f — 300+ WAF signature DB, 1-2 requests, but NOT
# installed in this image. `pip install wafw00f` first if you want it; skip
# straight to the header/cookie check below if you would rather not install.
wafw00f https://TARGET
wafw00f -l targets.txt -o waf_results.csv  # batch mode

# Step 3: nuclei WAF detection (batch, multiple hosts)
nuclei -l alive_hosts.txt -t http/technologies/waf-detect.yaml -silent

# Step 3: Manual header check (khi wafw00f inconclusive)
curl -sI https://TARGET | grep -iE "cf-ray|cloudflare|incap_ses|x-sucuri|x-amzn|BigIP|ModSecurity|akamai|FORTIWAFSID|barracuda|WebKnight|naxsi|rbzid|dotDefender|wordfence|ns_af=|NSC_"

# Step 4: httpx tech-detect (enrichment)
httpx -u https://TARGET -tech-detect -sc -cl -server -title

# Step 5: identYwaf — blind WAF detection (khi standard tools fail)
pip install identywaf  # one-time
python identywaf.py --random-agent https://TARGET
```

### wafw00f Batch Workflow (optimized for bug bounty)
```bash
# Probe all alive hosts → detect WAF → group by WAF type
cat alive_hosts.txt | while read host; do
  waf=$(wafw00f "$host" 2>/dev/null | grep -oP 'behind \K[^)]+' || echo "none")
  echo "$host|$waf"
done | tee waf_mapping.txt

# Filter by WAF type for targeted bypass
grep "Cloudflare" waf_mapping.txt | cut -d'|' -f1 > cloudflare_hosts.txt
grep "Akamai" waf_mapping.txt | cut -d'|' -f1 > akamai_hosts.txt
grep "none" waf_mapping.txt | cut -d'|' -f1 > no_waf_hosts.txt  # goldmine!
```

## Quick Reference: Tool Selection by WAF

| WAF | curl | curl-cffi | Playwright | Burp |
|-----|------|-----------|------------|------|
| Akamai | NO | Maybe (with session) | YES (primary) | After Playwright session |
| Cloudflare | NO (if challenged) | YES (impersonate) | YES (solve Turnstile) | After session |
| Imperva | NO | Maybe | YES (primary) | After session |
| AWS WAF | YES (often works) | YES | If blocked | YES |
| ModSecurity | YES | YES | Not needed | YES |
| F5 ASM | Careful | YES | If blocked | YES (HPP) |
| Sucuri | YES (if origin found) | YES | If blocked | YES (origin) |
| Barracuda | YES | YES | If blocked | YES |
| FortiWeb | Careful | YES | If blocked | YES |
| DotDefender | YES | YES | Not needed | YES |
| Wordfence | Careful | YES | YES (WP flows) | YES |
| NetScaler | YES | YES | If blocked | YES (chunked) |
| Palo Alto | YES | YES | Not needed | YES |
| NAXSI | YES | YES | Not needed | YES |
| WebKnight | YES | YES | Not needed | YES |
| Reblaze | NO | Maybe | YES (behavioral) | After session |

## Quick Reference: sqlmap Tamper Scripts by WAF

| WAF | Recommended Tamper Scripts |
|-----|---------------------------|
| Akamai | `between,randomcase,space2comment` |
| Cloudflare | `charencode,between,space2mssqlblank,unionalltoinunionall` |
| Imperva | `space2comment,between,charencode,equaltolike` |
| AWS WAF | `space2randomblank,percentage,unionalltoinunionall` |
| ModSecurity CRS | `space2comment,between,charencode,equaltolike,greatest` |
| F5 ASM | `space2mssqlhash,sp_password,between` + HPP |
| Sucuri | `between,space2comment` |
| Barracuda | `space2comment,between,charencode` |
| FortiWeb | `space2comment,charencode,between,randomcase` |
| DotDefender | `between,space2comment` |
| Wordfence | `space2comment,between,charencode` |
| NetScaler | `space2comment,between,charencode,equaltolike` |
| NAXSI | `space2comment,between,charencode` |
| WebKnight | `space2comment,between,randomcase` |
| Reblaze | `charencode,between,space2comment` |

## Operator Notes (Battle-Tested)

1. **wafw00f first, ALWAYS** -- `wafw00f https://TARGET` runs in 1-2 requests and identifies 300+ WAFs. Do not skip this step. Batch mode: `wafw00f -l targets.txt -o waf_results.csv`. Group hosts by WAF type for targeted bypass campaigns.
2. **Akamai = Playwright mandatory ()** -- raw curl, httpx, and any tool without browser TLS fingerprint gets instantly blocked. Get `_abck` cookie via Playwright first, then reuse in curl-cffi or Burp. Rate limit: 1 request per 5 seconds.
3. **Origin IP = complete bypass for cloud proxy WAFs** -- Sucuri, Cloudflare, Reblaze, Imperva are all DNS-level proxies. Finding origin IP means the WAF does not exist. Priority: DNS history (SecurityTrails), Shodan cert search, MX records, non-proxied subdomains.
4. **F5 BIGipServer cookie decode is a free finding** -- `BIGipServerPool=1677787402.36895.0000` contains encoded internal IP. Decode it. This is an information disclosure finding AND gives you the origin IP for direct access bypassing F5 ASM.
5. **"No WAF" hosts are your highest ROI** -- after batch WAF detection, immediately focus on hosts with no WAF detected. Raw payloads work, no encoding needed, fastest path to SQLi/XSS/RCE. Filter: `grep "none" waf_mapping.txt`.

## Related Skills & Chains

| When | Go to |
|------|-------|
| Need generic WAF bypass techniques | `references/waf-generic-evasion.md` |
| Finding origin IP behind WAF/CDN | `origin-ip-discovery` |
| HTTP/2 connection state attacks | `request-smuggling` |
| Cache poisoning through WAF | `cache-poisoning` |

## Per-WAF playbooks

Identify the WAF using the detection flow above, then read **only that vendor's file**. Each carries its own detection signals, working bypasses, rate-limit behaviour, and tooling notes. Loading all sixteen wastes context and blurs payload syntax between vendors.

| WAF | File |
|---|---|
| Akamai Bot Manager | `references/waf-akamai.md` |
| Cloudflare | `references/waf-cloudflare.md` |
| Imperva / Incapsula | `references/waf-imperva.md` |
| AWS WAF | `references/waf-aws.md` |
| ModSecurity / OWASP CRS | `references/waf-modsecurity.md` |
| F5 BIG-IP ASM | `references/waf-f5-bigip.md` |
| Sucuri | `references/waf-sucuri.md` |
| Barracuda WAF | `references/waf-barracuda.md` |
| Fortinet FortiWeb | `references/waf-fortiweb.md` |
| DotDefender (Applicure) | `references/waf-dotdefender.md` |
| Wordfence (WordPress) | `references/waf-wordfence.md` |
| Citrix NetScaler AppFirewall | `references/waf-netscaler.md` |
| Palo Alto NGFW | `references/waf-paloalto.md` |
| NAXSI | `references/waf-naxsi.md` |
| WebKnight (IIS) | `references/waf-webknight.md` |
| Reblaze | `references/waf-reblaze.md` |
| *WAF unidentified, or vendor file exhausted* | `references/waf-generic-evasion.md` — case toggling, multi-layer encoding, Unicode normalization, comment injection, chunked transfer, HPP |

## Reference files

Read these when the situation calls for the depth they carry — they are not loaded automatically.

- `references/waf-akamai.md` — **Akamai Bot Manager** — | Signal | Where |
- `references/waf-aws.md` — **AWS WAF** — | Signal | Where |
- `references/waf-barracuda.md` — **Barracuda WAF** — | Signal | Where |
- `references/waf-cloudflare.md` — **Cloudflare** — | Signal | Where |
- `references/waf-dotdefender.md` — **DotDefender (Applicure)** — | Signal | Where |
- `references/waf-f5-bigip.md` — **F5 BIG-IP ASM** — | Signal | Where |
- `references/waf-fortiweb.md` — **Fortinet FortiWeb** — | Signal | Where |
- `references/waf-generic-evasion.md` — **waf generic evasion** — related_patterns: ["waf-bypass-matrix", "command-injection-techniques", "ssti-techniques", "dom-based-vulnerab
- `references/waf-imperva.md` — **Imperva / Incapsula** — | Signal | Where |
- `references/waf-modsecurity.md` — **ModSecurity / OWASP CRS** — | Signal | Where |
- `references/waf-naxsi.md` — **NAXSI (Nginx Anti-XSS & SQL Injection)** — | Signal | Where |
- `references/waf-netscaler.md` — **Citrix NetScaler AppFirewall** — | Signal | Where |
- `references/waf-paloalto.md` — **Palo Alto Next-Generation Firewall** — | Signal | Where |
- `references/waf-reblaze.md` — **Reblaze** — | Signal | Where |
- `references/waf-sucuri.md` — **Sucuri** — | Signal | Where |
- `references/waf-webknight.md` — **WebKnight (AQTRONIX — IIS WAF)** — | Signal | Where |
- `references/waf-wordfence.md` — **Wordfence (WordPress WAF)** — | Signal | Where |
