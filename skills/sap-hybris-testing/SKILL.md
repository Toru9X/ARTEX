---
name: sap-hybris-testing
description: "Test SAP Hybris / SAP Commerce Cloud for default OAuth client credentials (mobile_android:secret and siblings) that mint API tokens, plus exposed /occ/v2/ and /api/v2/ storefront endpoints. Use when an e-commerce target fingerprints as Hybris or SAP Commerce Cloud."
---

# SAP Hybris Default OAuth Credentials

## Crown Jewel Targets

- SAP Hybris Commerce Cloud / SAP Commerce deployments
- E-commerce sites with `/occ/v2/` or `/api/v2/` endpoints
- target-corp, retail chains, and enterprise e-commerce on Hybris
- Sites with `grantType` in error messages or JS references

## Attack Surface Signals

- `grantType` in error messages or API responses
- JS bundles referencing `authorizationserver/oauth/token`
- `/occ/v2/` or `/api/v2/{baseSiteId}/` endpoints
- Spartacus frontend with `localStorage spartacus` tokens

## Detection
```bash
# Check for Hybris indicators
curl -s TARGET | grep -E "grantType|authorizationserver|/occ/v2/"
curl -s TARGET/main.*.js | grep "authorizationserver/oauth/token"
```

**Positive indicators:**
- `grantType` in error messages
- `main.*.js` references `authorizationserver/oauth/token`
- `/occ/v2/` or `/api/v2/{baseSiteId}/` endpoints present

## Default Credentials
| Client ID | Secret | Notes |
|-----------|--------|-------|
| `mobile_android` | `secret` | Most common |
| `client-side` | `secret` | Frontend client |
| `trusted_client` | `secret` | Elevated privileges |
| `mobile_ios` | `secret` | iOS app client |

## Exploitation
1. Get baseSiteId from frontend JS
2. Request guest token: `POST /authorizationserver/oauth/token` with `grant_type=client_credentials`
3. With token, access: `GET /api/v2/{baseSiteId}/configParam/global?fields=FULL`
4. Config dump contains: API keys, internal hostnames, 3rd-party credentials

## Important Notes
- **Akamai blocks curl** — must use Playwright with browser session cookies
- `/api/v2/*` and `/authorizationserver/*` are WAF-blocked; `/occ/v2/*` may pass
- `localStorage spartacus⚿⚿auth` stores tokens in plaintext
- OCC API needs Akamai session cookies from frontend page load
- `basePrice` manipulation does NOT work (server recalculates) — skip

## Historical Results
- target-corp Vietnam (target-corp.vn): All 4 default clients confirmed working

## Operator Notes (Battle-Tested)

- **Akamai blocks curl on Hybris sites**: Must use Playwright with browser session cookies. Load the frontend page first, capture Akamai cookies, then use those for API requests.
- **`/occ/v2/*` may bypass WAF**: While `/api/v2/*` and `/authorizationserver/*` are WAF-blocked, `/occ/v2/*` often passes through.
- **Try ALL four default client IDs**: `mobile_android:secret`, `client-side:secret`, `trusted_client:secret`, `mobile_ios:secret`. At least one usually works.
- **Config dump is the prize**: `GET /api/v2/{baseSiteId}/configParam/global?fields=FULL` with the token exposes API keys, internal hostnames, and third-party credentials.
- **`basePrice` manipulation does NOT work**: Server recalculates prices. Skip price manipulation testing on Hybris.

## Related Skills & Chains

| Pattern | Chain Potential |
|---------|---------------|
| `oauth-testing` → `references/oauth-client-id-hunting.md` | OAuth discovery methodology |
| `api-security-testing` | API endpoint testing |
| `auth-bypass-testing` | Auth bypass with default creds |
| `js-bundle-secrets` | JS analysis for Hybris secrets |
