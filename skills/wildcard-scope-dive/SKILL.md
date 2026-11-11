---
name: wildcard-scope-dive
description: "Methodology for working a wildcard or open scope without drifting into shallow breadth — partition the surface, choose under-tested branches, exhaust a foothold before moving on, and track coverage so exhausted areas are not re-scanned. Use when scope is *.target.com or open scope with hundreds of hosts, where a defensible plan is needed rather than another scan sweep."
---

# Wildcard / Open Scope Deep-Dive Methodology

> Template từ engagement Coca-Cola (90+ findings, 10+ domains, 7000+ subdomains).
> Áp dụng cho bất kỳ program nào có wildcard (`*.target.com`) hoặc open scope.

---

## Phase 0: Scope Mapping & Domain Inventory

### 0.1 Xác định tất cả root domains
```bash
# Từ scope.json hoặc program page
# Coca-Cola ví dụ: ko.com, coke.com, coca-cola.com, coca-colacompany.com,
#                  testko.com, devko.com, hccb.in, cokeurl.com, tccc-aem.com
```

**Mẹo**: Nhiều enterprise có 5-15 root domains. Mỗi domain có vai trò khác:
- `ko.com` = internal/corporate apps
- `coke.com` = technical/engineering
- `coca-cola.com` = consumer-facing + APIs
- `testko.com` / `devko.com` = pre-production (goldmine!)

### 0.2 Subdomain Discovery (song song tất cả domains)
```bash
# Chạy background
subfinder -d target.com -all -o fresh_target.com.txt
# Bổ sung crtsh
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sort -u > crtsh_target.com.txt
# Merge
cat fresh_*.txt crtsh_*.txt | sort -u > merged_all.txt
```

**Kết quả Coca-Cola**: ~7000 subdomains across 10 domains.

---

## Phase 1: Keyword-Based Prioritization

### 1.1 High-Value Keyword Filter
Subdomain list quá lớn để probe ALL → filter theo keyword priority:

```bash
# Tier 1: API & Dev tools (highest ROI)
grep -iE "^(api|dev|test|stage|stg|uat|qa|sandbox|internal)" subdomains.txt

# Tier 2: Admin & Infrastructure
grep -iE "^(admin|portal|dashboard|monitor|grafana|jenkins|sonar|jira|kibana|splunk)" subdomains.txt

# Tier 3: Data & Integration
grep -iE "^(data|bi|report|analytics|hub|integration|sync|etl|warehouse)" subdomains.txt

# Tier 4: Auth & Identity
grep -iE "^(sso|auth|login|id|oauth|idp|saml|keycloak|okta)" subdomains.txt

# Tier 5: App-specific (dùng sau khi hiểu target)
grep -iE "(bot|ai|ml|chat|intake|nexus|olympian|freestyle)" subdomains.txt
```

### 1.2 Pattern-Based Grouping
Enterprise assets thường có naming patterns:

| Pattern | Ý nghĩa | Ví dụ |
|---------|---------|-------|
| `{app}-dev.target.com` | Dev environment | `fsdatahub-dev.ko.com` |
| `{app}-api-{env}.target.com` | API per-env | `aigendo-api-image-dev.coca-cola.com` |
| `{app}-fe-{env}.target.com` | Frontend per-env | `alpha-zulu-fe-tccc-dev-stage.playground-stage.coke.com` |
| `big-{app}.target.com` | "BIG" prefix = Bottler Integration Group | `big-itsmapi.coca-cola.com` |
| `{app}-tccc-{env}-stage` | TCCC = The Coca-Cola Company | `alpha-zulu-tccc-dev-stage.playground-stage.coke.com` |
| `{region}.{app}.target.com` | Regional deployment | `api.apac.prod.crm.coca-cola.com` |

**Key insight**: Khi tìm 1 app (vd `fsdatahub.ko.com`), LUÔN check `-dev`, `-test`, `-qa`, `-stg`, `-uat` variants. Dev/test thường expose nhiều hơn PROD.

---

## Phase 2: Mass Probing Strategy

### 2.1 Quick Alive Check (batch 5-10 hosts)
```bash
# Loop batch, ghi nhận status code + content-length
for h in host1 host2 host3; do
  r=$(curl -s --proxy socks5://proxy:1080 -o /dev/null -w "%{http_code}|%{size_download}" \
    --connect-timeout 8 --max-time 15 "https://$h/" 2>/dev/null || echo "000|0")
  echo "$h -> $r"
done
```

### 2.2 Response Classification (QUAN TRỌNG)

| HTTP Code | Size | Ý nghĩa | Action |
|-----------|------|---------|--------|
| 000 | 0 | Dead/unreachable | Skip |
| 200 | <100 | Health check / minimal API | Deep probe |
| 200 | 100-1000 | Minimal app / API landing | Deep probe |
| 200 | 1K-10K | SPA / admin portal | JS analysis |
| 200 | 10K-100K | Full app / API docs | High priority deep probe |
| 200 | 100K+ | Full SPA / JS bundle | JS secrets extraction |
| 301/302 | * | Redirect | Follow to final destination |
| 307 | * | Temp redirect (API pattern) | Follow — often leads to /docs |
| 400 | ~341 | Azure Blob invalid params | Test with `?comp=list&restype=container` |
| 401 | * | Auth required (app-level) | **Interesting** — find auth bypass |
| 403 | 15-42 | WAF / network block | Check headers (Cloudflare/Akamai/Azure FD) |
| 403 | 263 | S3 AccessDenied | Test bucket listing |
| 403 | 900+ | CloudFront block | Skip |
| 404 | * | Not found | Skip (unless specific path returns differently) |
| 502/503 | * | Backend broken | Note — may come back online later |

### 2.3 Header Analysis (mỗi host alive)
```bash
curl -s -D- -o /dev/null "https://host/" 2>/dev/null | head -20
```

**Signals cần chú ý**:
- `Server:` → tech stack (IIS, nginx, Apache, Kestrel, gunicorn)
- `X-Powered-By:` → framework (ASP.NET, Express, PHP)
- `Access-Control-Allow-Origin: *` → wildcard CORS (finding nếu có credentials)
- `Content-Security-Policy:` → leak internal domains, Azure services, API hosts
- `WWW-Authenticate:` → auth type + có thể leak internal URLs
- `X-Azure-Ref:` / `X-MS-*` → Azure infrastructure
- `Set-Cookie:` → session type, framework detection

---

## Phase 3: Deep Probe Patterns

### 3.1 API Documentation Endpoints (MANDATORY cho mọi host alive)

```bash
# Swagger / OpenAPI (most common)
/swagger  /swagger/ui  /swagger-ui  /swagger-ui.html
/swagger/index.html  /swagger/v1/swagger.json
/api-docs  /docs  /redoc

# FastAPI specific
/docs  /redoc  /openapi.json

# ASP.NET Web API
/Help  /Help/Api

# Spring Boot
/actuator  /actuator/health  /actuator/info  /actuator/env
/actuator/configprops  /actuator/mappings  /actuator/loggers

# GraphQL
/graphql  /graphiql  /playground  /altair
```

### 3.2 Info Leak Endpoints
```bash
/info  /version  /health  /healthcheck  /status
/api/health  /api/info  /api/version  /api/status
/api/healthcheck  /.well-known/openid-configuration
/api/auth/providers  /api/auth/csrf  # NextAuth.js
/__NEXT_DATA__  /_next/data/  # Next.js
```

### 3.3 Config & Debug Endpoints
```bash
/env  /config  /settings  /debug  /trace
/elmah.axd  /trace.axd  # ASP.NET diagnostics
/server-info  /server-status  # Apache
/nginx_status  # nginx
```

### 3.4 Git & Source Leak
```bash
/api/info  /api/version  # Custom git info endpoints
/.git/HEAD  /.git/config
/.env  /env.js  /env-config.js  /config.js
/app.settings.json  /appsettings.json
```

---

## Phase 4: JS Bundle Deep Dive (Highest ROI)

### 4.1 Khi nào download JS?
- Host trả về 200 với HTML > 5KB → có JS bundles
- SPA frameworks (React/Angular/Vue) → main JS bundle chứa TOÀN BỘ app logic

### 4.2 JS Extraction
```bash
# Tải JS chính
curl -s "https://host/" | grep -oE 'src="[^"]*\.js[^"]*"' | sed 's/src="//;s/"//'
# Download bundle lớn nhất
curl -s "https://host/main.abc123.js" -o app_main.js
```

### 4.3 Secrets Grep Pattern
```bash
grep -iE "(api[_-]?key|secret|token|password|credential|auth|bearer|jwt|client.?id|client.?secret|access.?key|private.?key|mongodb|postgres|mysql|redis|azure|aws|gcp|firebase)" bundle.js
```

### 4.4 API Endpoint Discovery
```bash
grep -oE '"/(api|v[0-9]|auth|admin|internal)[^"]*"' bundle.js | sort -u
grep -oE 'https?://[a-zA-Z0-9._-]+\.[a-z]{2,}[^"'\'']*' bundle.js | sort -u
```

**Kết quả Coca-Cola**: 
- Nexus AI JS → MongoDB URI + GitHub token + Azure credentials
- GCDS B2C JS → hardcoded CDB password
- AI DevOps Agent env-config.js → full credential dump
- MD Portal JS → S3 bucket + partial API keys

---

## Phase 5: Ecosystem Mapping

### 5.1 Follow the Ecosystem
Khi tìm 1 app trên 1 subdomain → LUÔN check:

```
# App variants
{app}.target.com          # PROD
{app}-dev.target.com      # DEV
{app}-test.target.com     # TEST
{app}-qa.target.com       # QA
{app}-stg.target.com      # STAGING

# API + Frontend split
{app}-api.target.com      # Backend API
{app}-fe.target.com       # Frontend

# Regional variants
{app}-na.target.com       # North America
{app}-emea.target.com     # Europe/Middle East
{app}-apac.target.com     # Asia Pacific
{app}-latam.target.com    # Latin America
```

### 5.2 Staging/Playground Ecosystems (Goldmine)
Staging environments thường có:
- Swagger/API docs enabled (vì dev cần)
- Health endpoints exposed
- Git info endpoints
- Debug mode / verbose errors
- Weaker auth (default creds, dummy secrets)
- Wildcard CORS
- Keycloak/auth admin consoles accessible

**Coca-Cola pattern**: `playground-stage.coke.com` → 23+ APIs exposed, Keycloak admin console, 80-path IAM API.

### 5.3 Technology Detection → Attack Playbook

| Tech Detected | Where to Find | Attack Surface |
|---------------|--------------|----------------|
| Next.js | `__NEXT_DATA__`, `/_next/` | SSRF, API routes, `getServerSideProps` |
| FastAPI | `/docs`, `/openapi.json` | OpenAPI spec, all endpoints mapped |
| ASP.NET Web API | `/Help`, `.aspx` | Help page, Elmah, trace.axd |
| Spring Boot | `/actuator` | Env vars, loggers (writable!), heapdump |
| Keycloak | `/auth/realms/` | Admin console, realm config |
| Azure Function | Landing page 149KB | Function endpoints, config leak |
| Azure Blob | 400 XML error | Container listing, SAS tokens |
| S3 | 403 AccessDenied XML | Bucket listing, public objects |
| Bot Framework | `/api/messages` 400 | Direct Line API, conversation injection |

---

## Phase 6: Finding Categorization & Volume Strategy

### 6.1 Finding Types by ROI

| Priority | Finding Type | Ví dụ | Expected Volume |
|----------|-------------|-------|-----------------|
| P1 | Credential/secret exposure | JS bundle creds, env-config.js | 5-10 per target |
| P2 | Unauthenticated data access | Open APIs returning PII/records | 3-5 per target |
| P3 | API documentation exposure | Swagger/OpenAPI/Help pages | 10-20 per target |
| P4 | Infrastructure info disclosure | Health endpoints, git info | 10-15 per target |
| P5 | Auth misconfiguration | Wildcard CORS, CSRF tokens | 5-8 per target |

### 6.2 Grouping Strategy
Nhiều info disclosure liên quan → group thành 1 finding:
- Tất cả API docs trên cùng 1 ecosystem (playground-stage) → 1 finding
- Cùng app trên 3 envs (PROD/DEV/TEST) → 1 finding
- Dev+PROD cùng app → 1 finding (note cả 2 hosts)

### 6.3 Escalation Check
Với mỗi info disclosure, luôn thử escalate:
1. API docs → test data endpoints (auth bypass?)
2. Health endpoint → test `/api/` paths
3. Git info → search commit hash trên GitHub
4. Keycloak config → try default admin creds
5. JS secrets → try the credentials/tokens
6. S3/Blob → try listing/public access

---

## Phase 7: Continuous Discovery

### 7.1 Revisit Pattern
- Hosts trả 502/503 → retry 24h sau (backend may restart)
- Hosts trả 504 → retry (timeout, not dead)
- New subdomains appear → crtsh monitor

### 7.2 Cross-Reference Findings
- Finding A exposes email → use in Finding B IDOR test
- Finding A exposes API key → test on Finding B's API gateway
- CSP header leaks → probe every leaked domain
- Record all discovered endpoints via insert_assets so they're visible across tasks on the same asset graph

### 7.3 Velocity Targets
- **Đầu engagement**: 20-30 hosts probed/hour (mass discovery)
- **Mid engagement**: 5-10 deep probes/hour (API docs, JS analysis)
- **Late engagement**: 2-3 exploitation attempts/hour (auth bypass, data access)

---

## Checklist — Apply cho mỗi Wildcard Program

- [ ] Enumerate ALL root domains from scope
- [ ] Run subfinder + crtsh on ALL domains
- [ ] Keyword-filter into priority tiers
- [ ] Mass probe Tier 1 (API/dev/test)
- [ ] Classify responses by HTTP code + size
- [ ] Deep probe all 200s: /docs, /swagger, /Help, /actuator, /info, /health
- [ ] JS bundle download + secrets grep on all SPAs
- [ ] Follow ecosystem (dev/test/qa variants)
- [ ] Check staging/playground environments specifically
- [ ] CSP header analysis on every host (leak internal domains)
- [ ] Group related findings, escalate where possible
- [ ] Record all discoveries via record_fact/insert_assets
- [ ] Re-probe 502/503/504 hosts after 24h

---

## Stats: Coca-Cola Engagement

| Metric | Value |
|--------|-------|
| Root domains | 10 |
| Total subdomains | ~7000 |
| Subdomains probed | ~3000 |
| Alive hosts | ~300 |
| Findings documented | 91+ |
| Finding types | Credential leaks, API docs, health endpoints, JS secrets, S3 buckets, admin consoles |
| Highest severity | Critical (hardcoded DB credentials in JS) |
| Key technique | Mass probe → keyword filter → deep dive |

## Operator Notes (Battle-Tested)

- **Keyword filter is the force multiplier**: 7000 subdomains is too many to probe one by one. Filter by keyword tiers (api/dev/test first, then admin/portal, then data/integration). Coca-Cola proved this approach.
- **Dev/test/staging environments are goldmines**: They consistently have Swagger docs enabled, verbose errors, debug endpoints, weaker auth, wildcard CORS, and Keycloak admin consoles accessible.
- **Follow the ecosystem**: When you find `fsdatahub.ko.com`, ALWAYS check `-dev`, `-test`, `-qa`, `-stg`, `-uat` variants. Dev/test almost always expose more than PROD.
- **JS bundle deep dive is highest ROI**: 60%+ of findings from Coca-Cola came from JS analysis. Download every main JS bundle from SPA hosts and grep for secrets, API endpoints, internal URLs.
- **CSP header analysis leaks internal domains**: Parse CSP headers on every alive host. They frequently reference internal APIs, Azure services, and staging environments not in the subdomain list.
- **Group related findings**: Multiple info disclosures on the same ecosystem = 1 finding. Same app on 3 envs = 1 finding. Reduces report count, increases quality.

## Related Skills & Chains

| Pattern | Chain Potential |
|---------|---------------|
| `subdomain-enum-protocol` | Coverage audit for root domains |
| `internal-portal-discovery` | Internal portal methodology |
| `js-bundle-secrets` | JS analysis for secrets |
| `origin-ip-discovery` | CDN bypass for direct access |
| `oauth-testing` → `references/oauth-client-id-hunting.md` | OAuth discovery across subdomains |
