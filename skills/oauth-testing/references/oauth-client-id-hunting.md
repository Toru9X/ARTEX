---
name: oauth-client-id-hunting
pattern: OAuth Client ID Discovery Across Subdomains
description: "Auto-trigger: OAuth/OIDC detected, client_id in JS bundles, cross-subdomain grant type abuse, Okta/Hydra/Azure AD"
tech: [oauth2, oidc, okta, hydra, identityserver4, azure-ad]
severity: Medium-High (depends on grants available)
triggers:
  - /test-auth
  - oauth client id
  - oidc discovery
  - client_id hunting
  - grant type abuse
related_patterns:
  - oauth-token-theft-chain
  - saml-bypass-techniques
  - auth-bypass-techniques
  - js-bundle-secrets
---

# OAuth Client ID Discovery Across Subdomains

## Crown Jewel Targets

- Multi-subdomain applications sharing an OAuth provider
- Okta/Hydra/IdentityServer4/Azure AD deployments
- Applications with `password`/`device_code`/`CIBA` grant types enabled
- Staging OAuth instances with weaker validation

## Attack Surface Signals

- `/.well-known/openid-configuration` accessible
- `client_id`/`clientId` in JS bundles across subdomains
- CSP headers leaking SSO/OAuth provider domains
- `grant_types_supported` listing non-standard grants

## Detection
```bash
# On every host with login/auth:
curl -s TARGET/.well-known/openid-configuration | jq .

# Grep ALL JS bundles across ALL subdomains:
grep -rE "client_id|clientId|client-id" all_js_files/
```

## Key Insight
A single `client_id` found on subdomain A can unlock `password`/`device_code`/`CIBA` grants on the authorization server that aren't available through subdomain A's normal flow.

## Attack Steps
1. Discover OIDC config: `.well-known/openid-configuration`
2. Note: `grant_types_supported`, `token_endpoint_auth_methods_supported`
3. Hunt client_ids in JS across ALL subdomains (not just the auth host)
4. Test each client_id with all supported grant types
5. Check CSP headers on SSO-protected apps — leaks internal infra

## Provider-Specific Notes
| Provider | Notes |
|----------|-------|
| Okta | Proper `redirect_uri` validation. Hard to bypass. Check staging instances. |
| Ory Hydra | Strict allowlist. Test `token_endpoint_auth_method: none`. |
| IdentityServer4 | With PKCE S256 + strict redirect_uri = well-hardened. |
| Azure AD | Test tenant confusion (unvalidated `tid` claim) on multi-tenant apps. |

## Historical Results
- Pokemon: 5 Ory Hydra client_ids found across subdomains (trainer, zendesk, play-league, etc.)
- target-corp: Hybris OAuth clients with default secrets

## Operator Notes (Battle-Tested)

- **Cross-subdomain client_id reuse**: A `client_id` found on subdomain A can unlock `password` grant on the auth server that subdomain A does not normally use. Grep JS across ALL subdomains.
- **Check ALL grant types**: `grant_types_supported` in OIDC config reveals what is available. Test each discovered `client_id` with all supported grants.
- **CSP headers leak SSO infra**: Parse CSP on every SSO-protected app — they reference the OAuth provider and internal services.
- **Azure AD tenant confusion**: Test unvalidated `tid` claim on multi-tenant apps. One client_id may work across tenants.

## Related Skills & Chains

| Pattern | Chain Potential |
|---------|---------------|
| `oauth-token-theft-chain` | Full OAuth exploitation chain |
| `saml-bypass-techniques` | SAML/SSO bypass methods |
| `auth-bypass-techniques` | General auth bypass |
| `js-bundle-secrets` | JS analysis for client_ids |
