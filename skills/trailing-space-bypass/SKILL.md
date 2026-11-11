---
name: trailing-space-bypass
description: "Bypass authentication and account filters by appending trailing spaces, exploiting MySQL/MSSQL collation that ignores them where application-layer string comparison does not. Use when a MySQL/MSSQL-backed app blocks specific accounts (SYSTEM, admin) by name comparison, or when login logic relies on equalsIgnoreCase-style checks."
---

# Trailing Space Authentication Bypass (Database Collation Mismatch)

## Crown Jewel Targets

- Enterprise apps with MySQL backend blocking SYSTEM/admin accounts by name check
- Java apps using `equalsIgnoreCase()` for account filtering with MySQL queries
- Quality management systems (ETQ Reliance), ERP, ITSM platforms
- Any login form where specific usernames (admin, root, SYSTEM) are software-blocked
- C#/.NET APIs with string comparison in application layer but MySQL `=` in DB layer
- PHP apps using `===` strict comparison with MySQL `utf8_general_ci` collation

## Attack Surface Signals

- Login pages with "account locked" or "forbidden" for `admin`/`SYSTEM` usernames
- MySQL/MariaDB backend (check error messages, `SQLSTATE` codes)
- SQL Server backend (also ignores trailing spaces in `=`)
- Application-layer account blocking (not DB constraint)

**Source:** SLCyber (ETQ Reliance CVE-2025-34143, 2025)

## Overview

MySQL's default collation (`utf8_general_ci`, `utf8mb4_general_ci`) treats trailing spaces as equal in string comparisons. When the application layer uses exact match (`equalsIgnoreCase`, `==`, `===`) but the database uses collation-aware comparison, a trailing space creates a mismatch exploitable for authentication bypass.

## Core Vulnerability

```java
// Application layer: exact match (space matters)
if (username.equalsIgnoreCase("SYSTEM")) {
    throw new ForbiddenException("SYSTEM account blocked");
}

// Database layer: collation match (space ignored)
SELECT * FROM users WHERE username = 'SYSTEM '
// Returns SYSTEM user record because MySQL ignores trailing space!
```

Login with `{"username": "SYSTEM ", "password": "anything"}`:
1. App check: `"SYSTEM " != "SYSTEM"` → passes
2. DB query: `WHERE username = 'SYSTEM '` → returns SYSTEM user
3. User constructor: sets `this.system = true`, skips password validation
4. Result: full SYSTEM access

## Affected Databases

| Database | Trailing space behavior |
|----------|----------------------|
| MySQL (default collation) | Ignores trailing spaces in `=`, `LIKE` |
| SQL Server | Ignores trailing spaces in `=` |
| PostgreSQL | Does NOT ignore trailing spaces |
| Oracle | Pads with spaces for `CHAR`, not `VARCHAR2` |
| SQLite | Does NOT ignore trailing spaces |

## Testing

```bash
# Test with trailing space on admin/system accounts
curl -X POST https://target/api/login \
  -d '{"username":"admin ", "password":"test"}'

curl -X POST https://target/api/login \
  -d '{"username":"SYSTEM ", "password":"anything"}'

# Also try: leading space, tab character, Unicode spaces
curl -X POST https://target/api/login \
  -d '{"username":" admin", "password":"test"}'
```

## Code Review Pattern

```
equalsIgnoreCase    // Java exact match
strcmp / strcasecmp  // C exact match
===                  // JS/PHP strict comparison
== (string)          // Python exact match
```

Combined with SQL query using `=` on same field → potential bypass.

## Bug Bounty Relevance

- **HIGH**: Any Java/C#/.NET app with MySQL backend blocking specific usernames
- Trivial to test (just add a space), hard to detect with automated scanners
- Particularly dangerous for service accounts, admin accounts, system accounts
- The MySQL behavior is a FEATURE — it will never change in default collation

## Operator Notes (Battle-Tested)

- **Trivial to test, impossible to automate-detect**: Just add a space to `admin` or `SYSTEM`. No scanner checks this.
- **MySQL AND SQL Server both vulnerable**: Default collation ignores trailing spaces in `=` comparisons. PostgreSQL and SQLite do NOT.
- **Application vs DB mismatch is the bug**: `"SYSTEM " != "SYSTEM"` passes app check, but `WHERE username = 'SYSTEM '` returns the SYSTEM row.
- **Try Unicode spaces too**: ` ` (non-breaking space), ` ` (em space), `\t` (tab) — some apps trim ASCII spaces but not Unicode.
- **Service accounts are the prize**: SYSTEM, admin, root, superadmin — these often have elevated privileges or skip password validation entirely.
- **Combine with registration**: Register `"admin "` (with space) — if the app allows it, you may get admin privileges on login.

## Related Skills & Chains

| Pattern | Chain Potential |
|---------|---------------|
| `auth-bypass-testing` | General auth bypass methodology |
| `sql-injection-testing` → `references/dotnet-loose-type-sqli.md` | Type confusion in .NET login APIs |
| `sql-injection-testing` → `references/pdo-prepared-statement-sqli.md` | PHP/MySQL injection patterns |
| `windows-unicode-attacks` | Unicode normalization exploits |
| `access-control-testing` | Post-auth privilege escalation |
