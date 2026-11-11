---
name: dotnet-loose-type-sqli
pattern: .NET Loose Type SQL Injection
description: "Auto-trigger: ASP.NET API with Dictionary<string,object> or dynamic parameters, type confusion SQL injection"
tech: [dotnet, iis, generic]
severity: High
triggers:
  - /test-sqli
  - dotnet sqli
  - aspnet api injection
  - dictionary string object
  - loose type injection
related_patterns:
  - pdo-prepared-statement-sqli
  - ajax-sqli-waf-bypass-methodology
  - waf-bypass-matrix
sources:
  - "SLCyber — Halo ITSM (2025)"
---

# .NET Loose Type SQL Injection

## Crown Jewel Targets

- Enterprise ITSM/helpdesk platforms (Halo ITSM, ServiceNow clones)
- ASP.NET Web API with `[FromBody] Dictionary<string, object>` controllers
- Internal notification and logging endpoints accepting JSON
- .NET REST APIs using `dynamic` parameter types
- Legacy C# apps migrated from WCF to Web API (loose typing preserved)
- Audit/reporting endpoints with numeric filter fields sent as JSON

## Attack Surface Signals

- URL patterns: `/api/notify`, `/api/v1/`, `/api/sessions`, `/api/logs`
- Headers: `X-Powered-By: ASP.NET`, `Server: Microsoft-IIS`
- JSON body with numeric fields: `{"techid": 1, "sessionid": 42}`
- Error messages: `System.FormatException`, `SqlException`, `Invalid column name`
- Swagger/OpenAPI showing `object` type parameters

**Source:** SLCyber (Halo ITSM, 2025)
**CWE:** CWE-89

## Overview

In C#/ASP.NET APIs, when controller parameters use `Dictionary<string, object>` or `dynamic` instead of strongly-typed models, JSON deserialization accepts strings for fields assumed to be integers. Those strings then get concatenated directly into SQL queries, bypassing the type safety that normally prevents injection.

## Vulnerability Pattern

```csharp
// VULNERABLE: Dictionary<string, object> accepts any JSON type
[HttpPost]
public IActionResult PostNotify([FromBody] Dictionary<string, object> obj)
{
    // obj["techid"] can be "1 OR 1=1" instead of integer 1
    string where = "where ulogmeinid=" + obj["techid"].ToString();
    _db.getOneFieldInt("sessions", "id", where);  // SQLi!
}

// SAFE: Strongly-typed model rejects non-numeric input at deserialization
public class NotifyRequest { public int? techid { get; set; } }
```

## Code Review Detection

Grep for these patterns in C# codebases:
```
Dictionary<string, object>   // In controller parameters
dynamic                       // In controller parameters  
.ToString()                   // Followed by string concatenation into SQL
FromBody.*Dictionary          // API accepting loose-typed input
FromBody.*dynamic             // API accepting dynamic input
```

Use Semgrep rule:
```yaml
rules:
  - id: dotnet-loose-type-sqli
    patterns:
      - pattern: |
          Dictionary<string, object> $VAR
      - pattern-either:
          - pattern: |
              $VAR[$KEY].ToString()
    message: Loose-typed dictionary may enable SQL injection
    languages: [csharp]
    severity: WARNING
```

## Testing

```bash
# If endpoint accepts JSON with a numeric field
curl -X POST https://target/api/notify \
  -H "Content-Type: application/json" \
  -d '{"techid":"1 AND SLEEP(5)"}'
# If it sleeps → SQLi confirmed (type safety bypassed)
```

## Bug Bounty Relevance

- **HIGH**: Common pattern in C#/ASP.NET enterprise apps
- Strongly-typed models protect against SQLi; loose types bypass it
- Often found in notification, logging, and internal API endpoints
- Code review grep is trivial — `Dictionary<string, object>` in controller params

## Operator Notes (Battle-Tested)

- **Type confusion is the root cause**: Strongly-typed models reject `"1 AND SLEEP(5)"` at deserialization. `Dictionary<string, object>` accepts it as a string. This is the entire bug.
- **Test every numeric JSON field as string**: Send `{"id":"1 AND 1=1"}` instead of `{"id":1}`. If the app processes it, type safety is broken.
- **Notification/logging endpoints are goldmines**: Devs use loose typing for "simple" internal APIs. These are the most common vulnerable surface.
- **Semgrep catches this**: The rule in this pattern works. Run it on any C# codebase with API controllers.
- **Combine with IIS shortname**: Discover `.dll` assemblies via shortscan, decompile with dnSpy, grep for `Dictionary<string, object>`.

## Related Skills & Chains

| Pattern | Chain Potential |
|---------|---------------|
| `pdo-prepared-statement-sqli` | Same type-confusion concept in PHP |
| `iis-shortname-exploitation` | Discover DLLs for code audit |
| `aspnet-verbose-errors` | Error pages leak SQL query structure |
| `waf-bypass-matrix` | WAF evasion for SQLi payloads |
| `ajax-sqli-waf-bypass-methodology` | Operator blind SQLi techniques |
