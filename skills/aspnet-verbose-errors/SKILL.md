---
name: aspnet-verbose-errors
description: "Harvest ASP.NET/IIS verbose error pages for stack traces, internal file paths, connection strings, and framework versions, then judge honestly whether the leak is reportable or merely informational. Use when a .NET target throws a yellow-screen-of-death, runs with customErrors Off, or returns a full stack trace on malformed input."
---

# ASP.NET Verbose Error Page Information Disclosure

## Crown Jewel Targets

- ASP.NET apps in production with `customErrors mode="Off"`
- IIS servers returning full stack traces on malformed input
- .NET applications leaking database connection strings in errors
- ASP.NET apps exposing internal file paths (`C:\inetpub\wwwroot\...`)

## Attack Surface Signals

- `Server: Microsoft-IIS`, `X-Powered-By: ASP.NET`
- `.aspx`, `.ashx`, `.asmx` URL extensions
- Yellow Screen of Death (YSOD) on invalid input
- Error messages with `System.Web`, `System.Data` namespaces

## Detection
```bash
# Trigger error with malformed input
curl -s "TARGET/path?param=<invalid>" | grep -E "stack trace|Exception|Server Error"

# Check for custom errors disabled
curl -s "TARGET/nonexistent.aspx" | grep -i "customErrors.*Off"
```

**Positive indicators:**
- Full stack trace in response
- Internal file paths (e.g., `C:\inetpub\wwwroot\...`)
- .NET Framework version details
- Database connection string fragments

## What Leaks
- Internal server paths and file structure
- .NET version and configuration details
- Database server names and connection info
- Third-party library versions (useful for CVE hunting)

## Report Notes
- Stack trace alone = Low (info disclosure)
- Stack trace + DB credentials or internal paths = Medium
- Always include the specific sensitive data found
- Note if `customErrors mode="Off"` in production

## Historical Results
- target-corp: Verbose ASP.NET errors exposing internal paths

## Operator Notes (Battle-Tested)

- **Stack trace alone = Low severity**: Only report if it leaks actual credentials, connection strings, or enables a further attack chain.
- **Grep for connection strings**: Look for `Data Source=`, `Initial Catalog=`, `User ID=`, `Password=` in error responses.
- **Trigger errors with malformed input**: Invalid parameter types, extra long strings, special characters, null bytes in parameters.
- **Combine with IIS shortname**: Discover hidden files via shortname, then trigger errors to reveal internal paths and configs.

## Related Skills & Chains

| Pattern | Chain Potential |
|---------|---------------|
| `iis-shortname-exploitation` | File discovery + error exploitation |
| `sql-injection-testing` → `references/dotnet-loose-type-sqli.md` | SQL errors reveal query structure |
| `deserialization-testing` → `references/dotnet-deserialization-advanced.md` | Error info helps craft deser payloads |
| `windows-unicode-attacks` | Windows/.NET specific attacks |
