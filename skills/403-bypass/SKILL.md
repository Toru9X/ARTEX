---
name: 403-bypass
description: "Classify a 403 as network-level (AWS ELB/CloudFront/Azure/WAF — abandon immediately) or application-level, then bypass application 403s via path traversal (/./admin, /admin..;/), verb tampering, X-Original-URL / X-Rewrite-URL header override, and encoding tricks. Use when recon returns 403 Forbidden on an admin panel, API route, or any blocked path — run this before spending effort on what may be an edge-blocked dead end."
---

# 403 Response Classification and Bypass

## Crown Jewel Targets

- **Application-level 403 on admin panels** — path traversal (`/./admin`, `/admin..;/`) bypassing servlet-level access control
- **API endpoint 403 with verb tampering** — `GET` blocked but `POST`/`PUT`/`OPTIONS` returns data
- **Header override bypass** — `X-Original-URL: /admin` or `X-Rewrite-URL: /admin` bypassing reverse proxy ACL
- **URL encoding bypass** — `/%61dmin` (encoded 'a') or `/admin%00` bypassing string-match filters
- **Case variation bypass** — `/Admin`, `/ADMIN` on case-sensitive path matching implementations
- **401 endpoints behind 403 facade** — `ffuf -fc 401` finding authenticated endpoints on hosts that appear fully blocked

## Attack Surface Signals

- 403 with different Content-Length per path = application-level (bypass possible)
- 403 with SAME Content-Length for ALL paths = network-level (SKIP immediately)
- CL:15 (AWS ELB), CL:1484 (Azure Front Door), CL:23 (CloudFront), ~33KB (Vercel challenge)
- 401 JSON body = application auth (bypass possible)
- Custom error page with application branding = application-level
- Generic CDN/WAF error page = network-level

## Classification Table (MEMORIZE THIS)

| Signature | Platform | Action |
|-----------|----------|--------|
| 403 CL:15 | AWS ELB | **SKIP** — network-level, never bypassable |
| 403 CL:1484 | Azure Front Door | **SKIP** — network-level |
| 403 CL:23 | AWS CloudFront | **SKIP** — network-level |
| 403 `{"message":"Forbidden"}` | AWS API Gateway | **SKIP** — network-level |
| 403 CL:~33KB JS | Vercel challenge | **SKIP** — browser-only challenge |
| 403 different per path | Application-level | **TEST** — bypass possible |
| 401 JSON body | Application auth | **TEST** — auth bypass possible |

## The Key Test
```bash
# Same response for EVERY path = network-level = SKIP
curl -s TARGET/random1 | wc -c
curl -s TARGET/random2 | wc -c
curl -s TARGET/admin | wc -c
# All same CL? = network-level. Different? = application-level.
```

## Application-Level 403 Bypass Techniques
Only use these when classification = application-level:

1. Path traversal: `//admin`, `/./admin`, `/admin/./`, `/admin..;/`
2. URL encoding: `/%61dmin`, `/admin%00`
3. Verb tampering: `GET` → `POST`, `PUT`, `PATCH`, `OPTIONS`
4. Header override: `X-Original-URL: /admin`, `X-Rewrite-URL: /admin`
5. Case variation: `/Admin`, `/ADMIN`, `/aDmIn`

## Hard Rule
**Network-level 403 = dead end. STOP IMMEDIATELY. Do not waste time.**
Same response for every path = network-level. Period.

---

## Operator Notes (Battle-Tested)

- **HARD RULE #1: Network-level 403 = dead end. STOP IMMEDIATELY** — CL:15 (AWS ELB), CL:1484 (Azure FD), CL:23 (CloudFront), ~33KB (Vercel) = absolute dead ends. Zero exceptions
- **The classification test takes 10 seconds** — `curl -s TARGET/random1 | wc -c` vs `curl -s TARGET/random2 | wc -c`. Same size = network-level. Different size = application-level. Do this FIRST
- **MEMORY: 401 never means whole site locked** — 401 on root does NOT mean entire site is blocked. MUST run `ffuf -fc 401` to find bypassed paths (target-corp-app lesson)
- **Application-level 403 bypass priority order** — (1) path traversal `/admin..;/`, (2) verb tampering GET->POST, (3) header override `X-Original-URL`, (4) URL encoding `/%61dmin`, (5) case variation `/Admin`
- **Semicolon path confusion** — `/admin;.css` or `/admin;.js` may bypass WAF rules that only check file extension for static content exemption
- **After bypass, check /actuator, /swagger, /v2/api-docs** — common endpoints hidden behind 403 that become accessible after bypass

## Related Skills & Chains

| Situation | Pattern / Skill |
|-----------|----------------|
| WAF identified, need specific bypass | `waf-bypass` |
| Generic WAF evasion techniques | `waf-bypass` → `references/waf-generic-evasion.md` |
| Need origin IP to bypass CDN entirely | `origin-ip-discovery` |
| Admin portal found after bypass | `internal-portal-discovery` |
| Auth bypass on discovered endpoint | `auth-bypass-testing` |
| Access control testing after bypass | `access-control-testing` |
