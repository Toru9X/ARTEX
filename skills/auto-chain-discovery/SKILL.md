---
name: auto-chain-discovery
description: "Escalate Low/Medium findings into High/Critical by walking a chain matrix — open redirect to OAuth token theft, SSRF to cloud metadata credentials, self-XSS to stored XSS via CSRF, IDOR to bulk data breach. Use after any finding is confirmed but before triage, so nothing gets discarded as 'informational' when it actually chains into something reportable."
---

# Auto-Chain Discovery — Exploit Chain Escalation Matrix

> When a Low/Medium finding is discovered, automatically test linked chain targets to escalate impact.

## Crown Jewel Targets

- **Open redirect -> OAuth ATO** — redirect_uri manipulation to steal authorization code/token via attacker domain
- **SSRF -> AWS IAM credentials** — cloud metadata endpoint access for full cloud account takeover
- **Self-XSS -> Stored XSS** — CSRF chain forcing victim to trigger attacker's self-XSS payload
- **IDOR read -> IDOR write** — GET-based data leak escalated to PUT/PATCH/DELETE for data modification
- **Info disclosure -> RCE** — leaked .git repo/source map containing hardcoded credentials enabling server access
- **JWT none algorithm -> Full admin** — forged admin JWT granting complete administrative access
- **File upload -> RCE** — image extension bypass uploading PHP/JSP/ASPX webshell for code execution

## Attack Surface Signals

- Low/Medium finding just discovered (check this matrix BEFORE filing)
- OAuth authorization endpoint present (redirect_uri = open redirect chain target)
- Cloud metadata endpoint reachable from SSRF position (169.254.169.254)
- Multiple API endpoints sharing same authorization pattern (IDOR cascade)
- JWT-based authentication (check algorithm confusion, weak secret)
- File upload endpoints with content-type validation only (no magic byte check)
- CSRF protection missing on state-changing endpoints (self-XSS chain vector)

## How to Use

When `/test-*` commands produce a finding, check this matrix BEFORE filing. If a chain exists, test the chain target. Only file the HIGHEST impact in the chain.

## Chain Matrix

### Open Redirect Chains
| Found | → Auto-test | Chain Impact | Priority |
|-------|-------------|-------------|----------|
| Open redirect (any) | OAuth authorization flow with redirect_uri= | Account Takeover | CRITICAL |
| Open redirect (any) | SSO/SAML relay state parameter | Session hijack | HIGH |
| Open redirect (any) | Password reset link with return_url= | ATO via reset flow | HIGH |
| Open redirect (any) | POST-login redirect → token in URL | Token theft | HIGH |
| Open redirect (any) | Referer header leaks token to attacker domain | Token leak | MEDIUM |

**Test steps for OAuth chain:**
1. Find OAuth authorize endpoint: `/authorize?client_id=X&redirect_uri=Y`
2. Replace redirect_uri with open redirect: `redirect_uri=https://target.com/redirect?url=https://attacker.com`
3. If 302 to attacker with code/token → ATO proven

### SSRF Chains
| Found | → Auto-test | Chain Impact | Priority |
|-------|-------------|-------------|----------|
| SSRF (any) | Cloud metadata: `http://169.254.169.254/latest/meta-data/iam/` | AWS credential theft → RCE | CRITICAL |
| SSRF (any) | GCP metadata: `http://metadata.google.internal/computeMetadata/v1/` | GCP token theft | CRITICAL |
| SSRF (any) | Azure metadata: `http://169.254.169.254/metadata/identity/oauth2/token` | Azure token theft | CRITICAL |
| SSRF (any) | Internal services: `http://localhost:8080/admin`, `http://127.0.0.1:9090/` | Internal access | HIGH |
| SSRF (any) | Redis/Memcached: `http://localhost:6379/`, `gopher://` | Cache poisoning/RCE | CRITICAL |
| SSRF (any) | Kubernetes: `https://kubernetes.default.svc/api/v1/` | Cluster takeover | CRITICAL |
| SSRF to file read | `/etc/passwd` → `/proc/self/environ` → source code → hardcoded creds | RCE via leaked creds | CRITICAL |

### XSS Chains
| Found | → Auto-test | Chain Impact | Priority |
|-------|-------------|-------------|----------|
| Self-XSS | CSRF on same endpoint → force victim to trigger self-XSS | Stored XSS equivalent | MEDIUM→HIGH |
| Self-XSS | Login CSRF → log victim into attacker account → self-XSS fires | Session hijack | HIGH |
| Reflected XSS | Steal admin cookies/tokens → access admin panel | Privilege escalation | HIGH |
| Reflected XSS | Exfiltrate CSRF tokens → chain with state-changing actions | Account modification | HIGH |
| Stored XSS | Keylogger on login page (if same-origin) | Credential theft | CRITICAL |
| DOM XSS | postMessage → trigger DOM XSS from attacker iframe | Cross-origin XSS | HIGH |

### IDOR Chains
| Found | → Auto-test | Chain Impact | Priority |
|-------|-------------|-------------|----------|
| IDOR read (user data) | Write endpoint same pattern (GET→PUT/PATCH/DELETE) | Data modification/deletion | HIGH→CRITICAL |
| IDOR read (user ID) | Use ID in password reset / email change endpoint | ATO | CRITICAL |
| IDOR on file access | Access other users' uploaded documents (PII/financial) | Mass data breach | CRITICAL |
| IDOR on API key | Use leaked API key to access other endpoints | Full API access | HIGH |

### Information Disclosure Chains
| Found | → Auto-test | Chain Impact | Priority |
|-------|-------------|-------------|----------|
| Source map exposed | Extract API keys, internal URLs, auth logic from source | Key abuse / auth bypass | HIGH |
| .git exposed | Clone repo → extract secrets from history | Credential theft → RCE | CRITICAL |
| Stack trace with path | LFI/path traversal using leaked paths | File read → RCE | HIGH |
| Internal hostname leaked | SSRF to internal hostname | Internal network access | HIGH |
| API key in JS | Test key permissions (read/write/admin scope) | Depends on scope | MEDIUM-CRITICAL |
| Debug endpoint found | Access debug panel → RCE/data dump | Admin access | HIGH |

### Authentication Chains
| Found | → Auto-test | Chain Impact | Priority |
|-------|-------------|-------------|----------|
| JWT none algorithm | Forge admin JWT → access admin endpoints | Full admin access | CRITICAL |
| JWT weak secret | Crack secret → forge any user token | Mass ATO | CRITICAL |
| No rate limit on OTP | Brute force OTP within expiry window | ATO | HIGH |
| Password reset token predictable | Generate valid tokens for other users | Mass ATO | CRITICAL |
| Session fixation | Fix session → victim authenticates → attacker uses session | ATO | HIGH |

### CORS Chains
| Found | → Auto-test | Chain Impact | Priority |
|-------|-------------|-------------|----------|
| CORS reflects origin + credentials | Steal API responses containing PII/tokens | Data theft | HIGH |
| CORS null origin allowed | iframe sandbox → null origin → steal data | Data theft | HIGH |
| CORS wildcard + no auth | Probably by design (public API) — verify no sensitive data | Usually N/A | LOW |

### File Upload Chains
| Found | → Auto-test | Chain Impact | Priority |
|-------|-------------|-------------|----------|
| SVG upload allowed | SVG with XSS payload → stored XSS | Session hijack | HIGH |
| PDF upload allowed | PDF with JS → XSS on PDF viewer | XSS | MEDIUM |
| Image upload no validation | Upload .php/.jsp/.aspx with image extension bypass | RCE | CRITICAL |
| Upload path disclosed | Path traversal in filename → overwrite config | RCE | CRITICAL |

## Auto-Chain Logic (for AI agent)

When recording a finding in findings.json, check this matrix:
1. Look up `vuln_type` in "Found" column
2. For each matching chain row, add to finding:
   ```json
   {
     "chain_opportunities": [
       {
         "chain_target": "OAuth token theft via redirect_uri",
         "test_command": "/test-auth (OAuth flow section)",
         "potential_impact": "Account Takeover",
         "priority": "CRITICAL",
         "tested": false
       }
     ]
   }
   ```
3. If `potential_impact` is CRITICAL or HIGH → test IMMEDIATELY before filing the Low/Medium
4. If chain confirmed → file as the CHAIN impact, not the individual vuln

## Chain Priority Order

Always test chains in this order (highest ROI first):
1. **ATO chains** — any path to Account Takeover
2. **RCE chains** — any path to Remote Code Execution
3. **Data breach chains** — mass PII/financial data access
4. **Privilege escalation** — user → admin
5. **Data modification** — read → write/delete

---

## Operator Notes (Battle-Tested)

- **Check this matrix for EVERY finding before filing** — Low/Medium findings that chain to CRITICAL should be reported at the chain severity, not the individual vuln severity
- **Test chain targets IMMEDIATELY** — if potential_impact is CRITICAL or HIGH, test the chain BEFORE filing the Low/Medium. 20 minutes of chain testing can turn a Medium into a Critical
- **ATO chains are the highest ROI** — any path to Account Takeover (open redirect -> OAuth, JWT -> admin, IDOR -> password reset) gets maximum bounty
- **File as the CHAIN impact** — if chain confirmed, report the full chain with CRITICAL impact. Don't report the open redirect separately as Low
- **20-minute chain hunt rule** — HARD RULE from CLAUDE.md. After any finding, spend 20 minutes hunting related chain targets before writing report
- **Add chain_opportunities to findings.json** — structured metadata helps track untested chains across sessions

## Related Skills & Chains

| Situation | Pattern / Skill |
|-----------|----------------|
| Open redirect found | `open-redirect` → OAuth token theft |
| SSRF confirmed | `ssrf-testing` → internal pivot → RCE |
| Self-XSS found | `xss-testing` → `references/self-xss-escalation.md` → CSRF chain |
| JWT auth detected | `jwt-testing` → algorithm confusion |
| File upload available | `file-upload-testing` → RCE |
| CORS misconfig found | `cors-testing` → data theft |
| Duplicate concern | `duplicate-detection` → variant classification |
