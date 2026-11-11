---
name: js-bundle-secrets
description: "Extract hardcoded API keys, passwords, OAuth client secrets, and connection strings from JavaScript bundles and source maps, then prove exploitability with a live authenticated call so the finding escalates from informational to Critical. Use after loading every host's JS tree, or whenever a SPA/Next.js bundle is reachable — public client-side config (Cognito pool IDs, Sentry DSNs) does not count."
---

# Hardcoded Credentials in JavaScript Bundles

## Crown Jewel Targets

- **Server-side API keys** in client JS granting admin/write access to backend services
- **Database credentials** (connection strings, passwords) enabling direct database access
- **OAuth client_secret** enabling token forging or authorization code exchange
- **AWS/GCP/Azure credentials** (`aws_access_key`, `GOOGLE_API_KEY` with server scopes) for cloud account access
- **Admin/service account passwords** hardcoded for internal tools
- **Source maps** (`.js.map`) exposing full original source code with comments containing credentials

## Attack Surface Signals

- SPA frameworks (React, Angular, Vue, Next.js) with large JS bundles
- `REACT_APP_`, `NEXT_PUBLIC_`, `VUE_APP_` prefixed environment variables in JS
- Source map files accessible (`.js.map` URLs, `sourceMappingURL` comments)
- `__NEXT_DATA__` containing build-time environment variables
- Webpack chunk files with configuration objects
- Firebase config objects (`apiKey`, `projectId`, `databaseURL`)
- Internal API URLs and staging endpoints in production bundles

## Detection
```bash
# Grep ALL JS files across ALL subdomains
curl -s TARGET | grep -oP 'src="[^"]*\.js"'
# Then for each JS file:
curl -s JS_URL | grep -iE "password|secret|api_key|token=|Authorization.*Basic|client_secret|private_key|aws_access"
```

## What to Grep For
```
password|passwd|pwd
secret|client_secret
api_key|apikey|api-key
token=|access_token|bearer
Authorization.*Basic
private_key|privateKey
aws_access_key|AWS_SECRET
REACT_APP_|NEXT_PUBLIC_
firebase.*apiKey
```

## Impact Levels
| Finding | Severity | Notes |
|---------|----------|-------|
| API key that grants server-side access | Critical | Must prove access works |
| Database credentials | Critical | Must prove connection works |
| Admin/service account passwords | Critical | Must prove login works |
| OAuth client_secret | High | Depends on grant types available |
| Public client-side API keys (Permutive, Datadog pub*) | Informational | Public by design |
| Staging/dev environment URLs | Low-Medium | Depends on accessibility |

## Important: Credential MUST be proven exploitable
- API key alone = Informational
- API key + proven access = Medium/High/Critical
- Always test the credential: make API calls, try login, prove impact

## False Positives
- Permutive API keys = public by design
- Datadog `pub*` client tokens = write-only by design
- Google Analytics tracking IDs = public
- Sentry DSN = public (but can indicate PII config issues)

## Historical Results
- target-corp Group (target-corp sub): Leaked admin creds in JS → Critical
- Pokemon: Staging URLs in production JS bundles
- WaPo: Google OAuth Client ID, Permutive key in tetro.min.js (both public by design)

---

## Operator Notes (Battle-Tested)

- **MEMORY: Client-side config is NOT secret** — Cognito/Auth0 client IDs, WAF keys, Sentry DSN, Google Analytics IDs, Permutive keys, Datadog `pub*` tokens = public by design. NEVER report these alone
- **MEMORY: JS deep dive is mandatory** — Playwright-load EVERY accessible host, capture full JS tree. This is the highest-ROI technique across all bug bounty
- **Credential MUST be proven exploitable** — API key alone = Informational. API key + proven access (live API call, successful login, data extraction) = High/Critical. Always test the credential
- **MEMORY: Always save full attribution** — save JS bundles permanently + full attribution chain in report. JS can be rebuilt, evidence disappears
- **Source maps are full source code access** — `.js.map` files expose original TypeScript/React source with comments. Grep for `sourceMappingURL` in every JS file
- **target-corp pattern: bypass login -> load JS -> grep secrets** — MEMORY rule. After bypassing login walls, capture all loaded JS bundles and search for secrets/unauth API endpoints
- **REACT_APP_ and NEXT_PUBLIC_ are intentionally exposed** — but developers sometimes put server-side secrets in these variables by mistake. Always check what the variable value grants access to
- **Save bundles to your current working directory** (e.g. a `recon/js/` subfolder) for this intent's own analysis. Record captured bundle locations and findings via record_fact/insert_assets so they're not lost

## Related Skills & Chains

| Situation | Pattern / Skill |
|-----------|----------------|
| Firebase config found in JS | `firebase-misconfig` |
| Salesforce descriptors in JS | `salesforce-testing` |
| Internal URLs found in JS | `internal-portal-discovery` |
| Credential proves API access | `auto-chain-discovery` |
| Mobile app has embedded secrets | `mobile-api-testing` |
| DOM vulnerabilities in JS code | `xss-testing` |
