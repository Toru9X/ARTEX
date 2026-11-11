---
name: java-hessian-deserialization
pattern: Java Hessian Deserialization Attacks
description: "Auto-trigger: Java RPC, Hessian/Caucho/Spring remoting, MobileIron MDM, JNDI injection, BeanFactory gadget"
tech: [java, spring, tomcat, mdm, generic]
severity: Critical
triggers:
  - /test-deser
  - hessian deserialization
  - java rpc
  - mobileiron rce
  - jndi injection
  - spring remoting
related_patterns:
  - java-deserialization-rce
  - tomcat-path-normalization-bypass
  - java-matrix-param-auth-bypass
  - dotnet-deserialization-advanced
sources:
  - "Orange Tsai — MobileIron MDM (2020)"
  - "SLCyber — OpenText (2025)"
---

# Java Hessian Deserialization Attacks

## Crown Jewel Targets

- MobileIron/Ivanti MDM (15%+ Fortune 500, path confusion + Hessian = pre-auth RCE)
- Spring-based applications exposing Hessian/Remoting endpoints
- Caucho Resin application servers
- Apache Dubbo RPC services
- OpenText Directory Services (encrypted deser with flawed crypto)
- Any Java app with `/services/`, `/remoting/`, `/hessian/` endpoints

## Attack Surface Signals

- Content-Type: `application/x-hessian`, `application/x-java-serialized-object`
- URL patterns: `/services/*`, `/remoting/*`, `/hessian/*`, `/burlap/*`, `/caucho/*`
- Error messages: "Hessian", "HessianInput", "com.caucho"
- JSESSIONID cookies, Java-style error pages
- Spring Boot indicators with remoting enabled

**Sources:** Orange Tsai (MobileIron MDM, 2020), SLCyber (OpenText, 2025)
**Key CVEs:** CVE-2020-15505 (MobileIron), CVE-2024-4577 chain patterns

## Overview

Hessian is a binary serialization protocol used in Java RPC frameworks (Caucho Resin, Spring, Dubbo). Unlike Java's native serialization, Hessian deserialization triggers `equals()`, `hashCode()`, and `toString()` on reconstructed objects — creating a different gadget chain surface.

## Hessian-Specific Gadget Chains

| Gadget | Effect | Library |
|--------|--------|---------|
| Apache XBean | JNDI Injection | xbean-naming |
| Caucho Resin | JNDI Injection | resin-kernel |
| Spring AOP | JNDI Injection | spring-aop |
| ROME EqualsBean | Arbitrary method call → RCE | rome |

### Spring AOP → JNDI Injection (Most Common)

Hessian triggers `hashCode()` on HashMap key → Spring AOP's `JdkDynamicAopProxy` → eventually calls `InitialContext.lookup()` with attacker-controlled URL.

## JNDI Injection Post-8u181

Java 8u181+ blocks remote class loading via LDAP/RMI. Bypasses:

### BeanFactory Gadget (Tomcat)

Redirect JNDI to LOCAL class instantiation via `org.apache.naming.factory.BeanFactory`:

```java
// Tomcat 8.5+ → ELProcessor
javax.el.ELProcessor.eval("Runtime.getRuntime().exec('cmd')")

// Tomcat 7 → GroovyShell (if Groovy available)
groovy.lang.GroovyShell.evaluate("'cmd'.execute()")
```

### Old Groovy MethodClosure (No Outbound Connection Needed)

Groovy < 2.4.4 (before CVE-2015-3253 fix) has no `readResolve()` check on `MethodClosure`:

```java
// Old Groovy lacks this protection:
private Object readResolve() {
    if (ALLOW_RESOLVE) return this;
    throw new UnsupportedOperationException();
}
```

**Critical for air-gapped targets** (like Facebook) — no outbound connection required.

## MobileIron MDM Attack Pattern

### ACL Bypass

Apache blocks `/mifs/services/` directly. Bypass via path confusion:

```
https://mobileiron/mifs/.;/services/someService
```

Apache doesn't match rewrite rule. Tomcat normalizes `.;` → routes to `/mifs/services/`.

### Exploitation Chain

1. ACL bypass via `/mifs/.;/services/` path confusion
2. Hessian deserialization on Web Service endpoint
3. Spring AOP → JNDI → BeanFactory → GroovyShell (Groovy 1.5.6)
4. RCE without outbound connections

## OpenText Directory Services Pattern

Java deserialization through broken cryptographic validation:

1. Encrypted/signed serialized object in request parameter
2. Crypto implementation flawed → attacker crafts valid encrypted payload
3. Server decrypts → deserializes → triggers gadget chain
4. Pre-auth RCE

## Finding Hessian Endpoints

### URL Patterns

```
/services/*
/remoting/*
/hessian/*
/burlap/*
/caucho/*
```

### Content-Type Indicators

```
application/x-hessian
application/x-java-serialized-object
application/x-hessian2
```

### Detection via Error Messages

Send malformed binary data to suspected endpoints:
```bash
echo -ne '\x48\x02\x00' | curl -X POST -H 'Content-Type: application/x-hessian' --data-binary @- https://target/services/endpoint
```

Error messages containing "Hessian", "HessianInput", or "com.caucho" confirm the protocol.

## Nested Deserialization (Magento CVE-2025-54236 Pattern)

Even when primary deserialization is "safe", nested objects within the deserialized structure may trigger secondary deserialization with different (unsafe) settings:

```
Outer object (safe deserializer) → contains inner object → inner triggers unsafe deserialization
```

Always check the FULL deserialization chain, not just the entry point.

## Testing Methodology

1. **Identify Java backend:** Headers, error pages, cookie names (JSESSIONID)
2. **Find service endpoints:** Probe common paths with Hessian content type
3. **Fingerprint libraries:** Error messages reveal Spring, Tomcat, Groovy versions
4. **Check for path confusion:** Try `;`, `.;/`, `%2e%2e` patterns
5. **Generate payload:** Use ysoserial-hessian or marshalsec for gadget chain
6. **Test OOB:** DNS/HTTP callback to confirm execution

## Bug Bounty Relevance

- **CRITICAL**: Pre-auth RCE on enterprise Java applications
- MobileIron/Ivanti MDM widely deployed (15%+ Fortune 500)
- Spring-based applications commonly expose Hessian endpoints
- Path confusion + deserialization = powerful pre-auth chain

## Operator Notes (Battle-Tested)

- **Hessian triggers `equals()`/`hashCode()`/`toString()`**: Not `readObject()` like native Java deser. This means different gadget chains. Use ysoserial-hessian or marshalsec, not standard ysoserial.
- **Path confusion is the enabler**: MobileIron pattern: `/mifs/.;/services/someService` — Apache does not match the rewrite rule, Tomcat normalizes `.;` and routes to the service. Always try path confusion before Hessian testing.
- **BeanFactory gadget for Java 8u181+**: After JNDI remote class loading was blocked, use Tomcat's `BeanFactory` for local class instantiation. `ELProcessor.eval()` on Tomcat 8.5+, `GroovyShell.evaluate()` with Groovy.
- **Old Groovy MethodClosure = no outbound connection**: Groovy < 2.4.4 has no `readResolve()` check. Critical for air-gapped targets — RCE without any outbound network connection.
- **Send malformed binary to detect**: `echo -ne '\x48\x02\x00' | curl -X POST -H 'Content-Type: application/x-hessian' --data-binary @- https://target/endpoint` — error with "Hessian" = confirmed protocol.
- **Always check nested deserialization**: Even "safe" outer deserialization may trigger unsafe inner deserialization via nested objects.

## Related Skills & Chains

| Pattern | Chain Potential |
|---------|---------------|
| `java-deserialization-rce` | General Java deser reference |
| `tomcat-path-normalization-bypass` | Path confusion to reach Hessian |
| `java-matrix-param-auth-bypass` | Auth bypass to reach service endpoints |
| `dotnet-deserialization-advanced` | .NET deser patterns (cross-reference) |
| `spring-el-injection` | Alternative RCE on Spring targets |
