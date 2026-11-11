---
name: sfmc-ssti-crypto-attacks
pattern: Salesforce Marketing Cloud SSTI & Crypto Attacks
description: "Auto-trigger: SFMC/ExactTarget detected, AMPScript injection, cross-tenant crypto attack, email view link exploit"
tech: [sfmc, salesforce, dotnet]
severity: Critical
triggers:
  - /test-ssti
  - sfmc attack
  - exacttarget
  - ampscript injection
  - marketing cloud
related_patterns:
  - ssti-techniques
  - salesforce-lightning
  - oauth-token-theft-chain
  - cache-poisoning-techniques
sources:
  - "SLCyber / Searchlight Cyber — SFMC CVE-2026-22585/22586/22582/22583/2298 (2026)"
---

# Salesforce Marketing Cloud SSTI & Crypto Attacks

## Crown Jewel Targets

- Any company using Salesforce Marketing Cloud / ExactTarget for email campaigns
- SFMC tenants with subscriber data (contacts, emails, SMS tracking)
- "View in browser" email links using encrypted `qs` parameter
- Email signup forms where name/address fields are evaluated in templates
- SFMC subdomains: `click.*`, `view.*`, `cloud.*`, `pages.*`, `images.*`

## Attack Surface Signals

- CNAME chains resolving to `*.exacttarget.com` or `*.sfmc-content.com`
- URLs with `qs=` encrypted parameter on `ftaf.aspx` (Forward to a Friend)
- Subdomains matching SFMC patterns: `click.`, `view.`, `cloud.`, `pages.`, `images.`
- Email source with `%%=` AMPScript or `{{=` GTL syntax
- `MicrositeURL` function references in page source

**Sources:** SLCyber / Searchlight Cyber (2026)
**CVEs:** CVE-2026-22585, CVE-2026-22586, CVE-2026-22582, CVE-2026-22583, CVE-2026-2298
**Affected:** All Salesforce Marketing Cloud (SFMC/ExactTarget) tenants globally

## Overview

Multiple critical vulnerabilities in SFMC allowed cross-tenant access to all emails, contacts, and SMS. Combines server-side template injection with cryptographic weaknesses in email viewing links.

## AMPScript Template Injection

User-controlled fields (name, address) are evaluated when marketing emails render:

```
%%=mul(7,7)=%%    -> AMPScript (primary syntax)
{{=mul(7,7)}}     -> GTL syntax (undocumented, bypasses %% filtering)
```

### Double Evaluation in Subject Lines

Email subjects double-evaluated by default. First pass substitutes user fields, second pass executes injected template code. Trigger: sign up for mailing list with payload in name field.

### Data Exfiltration via Data Views

```
%%=RowCount(LookupRows("_Subscribers","SubscriberKey",_subscriberkey))=%%
```

Accessible: `_Subscribers` (contacts), `_Sent`/`_Job` (emails), `_SMSMessageTracking` (SMS), `_Click` (tracking). OOB exfil via `HttpGet` function.

## Encrypted Query String Attacks

### Single Static Key Across ALL Tenants

"View in browser" links use encrypted `qs` parameter. All tenants shared ONE encryption key.

### Three Encryption Formats

| Format | Crypto | Attack |
|--------|--------|--------|
| Modern | AES-GCM | Secure (authenticated) |
| Classic | CBC unauthenticated | Padding oracle (`padre` tool) |
| Ancient | XOR with static key | Trivially reversible, 1 req/guess |

### CBC Padding Oracle

```bash
./padre -e lhex -b 8 -p 20 -u 'https://view.e.site.com/ftaf.aspx?qs=$' \
  -enc "QXXXXXXX=0&m=MID&ls=LSID&ju=JUID&n=1678"
```

### XOR Format (still accepted for new tenants!)

Simple repeating XOR key with 2-byte checksum prefix. Trivially reversible. Reduces subscriber enumeration to 1 HTTP request per guess.

### MicrositeURL Bypass

```
%%=MicrositeURL(1, "test", "=0&LID=1&j=2&m=3&ls=4")=%%
```

Concatenation bypasses reserved parameter checks. Generates encrypted params for ANY tenant.

### Cross-Tenant Attack Chain

1. Obtain one email from target company
2. Decrypt `qs` via padding oracle
3. Re-encode using ancient XOR format
4. Enumerate subscribers via `ftaf.aspx` (Forward to a Friend, enabled by default)

## Detection

SFMC domains: CNAME chains to `*.exacttarget.com` or `*.sfmc-content.com`.
Subdomains: `click.`, `view.`, `cloud.`, `pages.`, `images.`

## Bug Bounty Relevance

- **CRITICAL**: Cross-tenant data access affecting every SFMC customer
- Template injection via mailing list signup (zero auth needed)
- Shared static encryption keys across SaaS tenants = systemic pattern
- Look for similar patterns in any SaaS with "view in browser" email links
- Legacy crypto formats (XOR, unauthenticated CBC) often still accepted

## Operator Notes (Battle-Tested)

- **GTL syntax `{{=mul(7,7)}}` bypasses `%%` filtering**: Undocumented syntax that many SFMC instances do not filter. Always test both `%%=mul(7,7)=%%` AND `{{=mul(7,7)}}`.
- **Subject line double evaluation**: Email subjects are evaluated twice by default. First pass substitutes user fields, second pass executes injected template code. Trigger via mailing list signup with payload in name field.
- **ALL tenants shared ONE encryption key**: The `qs` parameter encryption key was the same across all SFMC tenants globally. Even after the fix, legacy XOR format is still accepted for backward compatibility.
- **Ancient XOR format is trivially reversible**: Simple repeating XOR key with 2-byte checksum. Reduces subscriber enumeration to 1 HTTP request per guess.
- **CBC padding oracle via `padre` tool**: Classic padding oracle attack on the older CBC format. Works because the encryption is unauthenticated.
- **OOB exfil via `HttpGet`**: AMPScript's `HttpGet` function can send data to attacker-controlled URLs. Combine with Data View access (`_Subscribers`, `_Sent`, `_SMSMessageTracking`) for full cross-tenant data extraction.

## Related Skills & Chains

| Pattern | Chain Potential |
|---------|---------------|
| `ssti-techniques` | General SSTI methodology |
| `salesforce-lightning` | Salesforce Lightning attacks |
| `oauth-token-theft-chain` | OAuth exploitation on SFMC |
| `cache-poisoning-techniques` | CDN poisoning on SFMC domains |
| `csp-bypass-unregistered-domain` | CSP bypass on SFMC subdomains |
