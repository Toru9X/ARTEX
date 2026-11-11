---
name: dotnet-deserialization-advanced
pattern: Advanced .NET Deserialization Attack Patterns
description: "Auto-trigger: .NET BinaryFormatter, ViewState, MSMQ, Sitecore, Veeam, bridge gadget deserialization"
tech: [dotnet, csharp, aspnet]
severity: Critical
triggers:
  - /test-deser
  - dotnet deserialization
  - binaryformatter
  - viewstate
  - sitecore rce
  - veeam rce
related_patterns:
  - java-hessian-deserialization
  - java-deserialization-rce
  - deserialization-gadgets
  - parser-differential-attacks
sources:
  - "WatchTowr Labs — Veeam, Citrix, BMC FootPrints, Sitecore (2024-2026)"
  - "SLCyber — Sitecore, OpenText (2025)"
---

# Advanced .NET Deserialization Attack Patterns

## Crown Jewel Targets

- Sitecore CMS instances (22K+ internet-facing, `ThumbnailsAccessToken` header)
- Veeam Backup & Replication (400K+ customers, .NET Remoting endpoints)
- Citrix Virtual Apps with MSMQ-over-HTTP enabled
- BMC FootPrints (Java+Mono cross-framework ViewState)
- GoAnywhere MFT (`SignedObject` nested deserialization)
- Any .NET app with `__VIEWSTATE` and MAC validation disabled
- Enterprise apps using `BinaryFormatter`, `LosFormatter`, `ObjectStateFormatter`

**Sources:** WatchTowr Labs (Veeam, Citrix, BMC FootPrints, Sitecore, 2024-2026), SLCyber (Sitecore, OpenText, 2025)
**Key CVEs:** CVE-2024-40711, CVE-2024-8068, CVE-2025-23120, CVE-2025-27218, CVE-2025-53691

## Overview

Modern .NET applications often implement type filtering (whitelist/blacklist) around BinaryFormatter deserialization. These techniques bypass those defenses.

---

## 1. Bridge Gadget (Whitelist-to-Blacklist Transition)

When outer deserialization uses a whitelist but inner deserialization uses a blacklist:

**Veeam CVE-2024-40711 pattern:**
- `CDbCryptoKeyInfo` passes whitelist filter on .NET Remoting layer
- Its constructor calls `CProxyBinaryFormatter.Deserialize()` which uses BLACKLIST mode
- `ObjRef` gadget missing from blacklist → RCE as SYSTEM
- Pattern: find whitelisted types whose constructors/properties trigger secondary deserialization with weaker filtering

---

## 2. Blacklist Bypass via Inherited Gadget Classes

**Veeam CVE-2025-23120 pattern:**
- Product blacklists known gadgets like `DataSet`
- Product-internal classes `xmlFrameworkDs` and `BackupSummary` extend `DataSet` but are NOT blacklisted
- `DataSet` parent constructor is the actual gadget — inherited by children
- **Hunt methodology**: enumerate all classes inheriting from known gadgets (`DataSet`, `ObjectDataProvider`, `TypeConfuseDelegate`), check if any are whitelisted or not blacklisted

---

## 3. Deserialize-Before-Validate (Order of Operations)

**Sitecore CVE-2025-27218 pattern:**
- `ThumbnailsAccessToken` header → `Convert.Base64ToObject()` (BinaryFormatter) fires BEFORE `MachineKey.Unprotect()` validates integrity
- Runs in `httpRequestBegin` pipeline before `SiteResolver` — triggered on unauthenticated requests
- **Detection**: `GET /` with `ThumbnailsAccessToken: AAEAAAD/////` (BinaryFormatter magic bytes in base64)
- **Payload**: `ysoserial.exe -f BinaryFormatter -g WindowsIdentity -c "command"`

---

## 4. MSMQ-over-HTTP Deserialization

**Citrix CVE-2024-8068/8069 pattern:**
- MSMQ queue uses `BinaryMessageFormatter` on untrusted messages
- TCP port 1801 (MSMQ native) not exposed, BUT HTTP transport tunnels MSMQ through port 80/443
- Queue grants `GenericWrite` to `AnonymousSid`
- **Detection**: check for MSMQ HTTP transport at `/msmq/<queue_name>`
- **Payload**: ysoserial.net `TypeConfuseDelegate` wrapped in MSMQ-over-HTTP SOAP envelope

---

## 5. Cross-Framework Deserialization Sink

**BMC FootPrints pattern:**
- Java application has Mono/.NET compatibility layer
- `__VIEWSTATE` parameter reaches Java `inputStream.readObject()` with zero filtering
- Gadget: `AspectJWeaver` (arbitrary file write) → drop JSP webshell

---

## 6. Nested Deserialization via SignedObject

**GoAnywhere CVE-2025-10035 pattern:**
- `ValidatingObjectInputStream` only allows `SignedObject.class` + `byte[].class`
- But `SignedObject.getObject()` triggers UNRESTRICTED inner deserialization
- Hard-coded encryption keys allow offline payload crafting
- Pattern: any use of `SignedObject` or similar wrapper types that re-deserialize their contents

---

## Finding .NET Deserialization Sinks

### Code Review Grep Patterns
```
BinaryFormatter.Deserialize
BinaryMessageFormatter
ObjectStateFormatter.Deserialize
LosFormatter.Deserialize
NetDataContractSerializer
SoapFormatter.Deserialize
Convert.Base64ToObject
readObject() // Java cross-framework
```

### Runtime Detection
```bash
# BinaryFormatter magic bytes in base64
echo "AAEAAAD/////" | base64 -d | xxd  # 00 01 00 00 00 FF FF FF FF

# Test headers commonly used for token transport
curl -H "ThumbnailsAccessToken: AAEAAAD/////" https://target/
curl -H "__VIEWSTATE: AAEAAAD/////" -X POST https://target/
```

### Configuration Indicators
- MSMQ HTTP transport: `GET /msmq/` returns MSMQ-related error
- .NET Remoting: check for `RemotingConfiguration` in web.config
- ViewState: `__VIEWSTATE` field in forms without MAC validation

---

## Bug Bounty Relevance

- **CRITICAL**: Pre-auth RCE on enterprise .NET applications
- Sitecore (22K+ instances), Veeam (400K+ customers), Citrix VDI widely deployed
- BinaryFormatter is deprecated but still everywhere in legacy code
- Bridge gadgets and inherited class bypasses defeat modern defenses
- Microsoft WONTFIX on many systemic issues (.NET SOAP proxy, BinaryFormatter in Framework)

## Operator Notes (Battle-Tested)

- **Bridge gadgets are the meta**: Modern .NET apps whitelist types, but whitelisted classes that trigger secondary deserialization with BLACKLIST mode are everywhere. Hunt class hierarchies.
- **`AAEAAAD/////` is the magic**: Base64 of BinaryFormatter magic bytes. Inject in any header/parameter that might reach deserialization.
- **Inherited class bypass**: If `DataSet` is blacklisted, search for any class extending `DataSet` that IS NOT blacklisted. The parent constructor is the gadget.
- **Deserialize-before-validate**: Many .NET apps deserialize BEFORE checking MAC/auth. The Sitecore pattern (fire before `MachineKey.Unprotect`) is extremely common.
- **MSMQ is overlooked**: HTTP transport tunnels MSMQ through 80/443. Look for `/msmq/` paths. Queue ACLs often grant `AnonymousSid`.
- **ysoserial.net is your friend**: `WindowsIdentity`, `TypeConfuseDelegate`, `TextFormattingRunProperties` — test all gadget chains.

## Related Skills & Chains

| Pattern | Chain Potential |
|---------|---------------|
| `java-hessian-deserialization` | Cross-framework (Java↔.NET) deserialization |
| `deserialization-gadgets` | General gadget chain reference |
| `parser-differential-attacks` | Bypass sanitizers before deser sink |
| `backup-mft-attacks` | Veeam/GoAnywhere specific chains |
| `execution-after-redirect` | EAR + deser on admin panels |
