---
name: internal-portal-discovery
description: "Discover internal and admin portals via adjacent subdomain enumeration, SPA config leaks (app.settings.json, assets/config.json), redirect chain analysis, and SignalR /negotiate probing for unauthenticated access. Use after subdomain enumeration when hunting backoffice or management interfaces, or whenever a SPA is likely shipping its internal API map to the browser."
---

# Internal/Admin Portal Discovery

## Crown Jewel Targets

- **K8s internal admin panels** — redirect chains exposing `admin.prod.*.com` internal Kubernetes management interfaces
- **SignalR endpoints without auth** — `/notify/negotiate` returning 200 without authentication, enabling real-time event subscription
- **SPA config files** — `app.settings.json`, `core.settings.json`, `assets/config.json` leaking internal API URLs and service endpoints
- **Employee portals on adjacent subdomains** — `staff.`, `backoffice.`, `cms.`, `manage.` subdomains with weaker access controls
- **Debug/staging endpoints** — internal services accidentally exposed to internet with full functionality
- **Management APIs with CORS** — admin API endpoints with permissive CORS allowing cross-origin data access

## Attack Surface Signals

- Subdomain enumeration results containing `admin`, `manage`, `internal`, `portal`, `dashboard`, `backoffice`, `staff`, `cms`
- HTTP redirects (301/302) to internal domains (`.internal`, `.corp`, `.local`, `.k8s`)
- SignalR paths (`/negotiate`, `/hub`, `/signalr`) in alive host responses
- SPA config endpoints returning JSON with internal URLs
- Non-standard ports (`:3030`, `:8080`, `:8443`, `:9090`) on discovered subdomains
- `.settings.json`, `config.json`, `environment.json` files accessible without auth

## Detection Methods

### Adjacent Subdomain Enumeration
```bash
# From alive hosts, look for admin/internal patterns
grep -iE "admin|manage|internal|portal|dashboard|backoffice|staff|cms" recon/alive.txt
```

### SPA Config File Discovery
```bash
curl -s TARGET/app.settings.json
curl -s TARGET/core.settings.json
curl -s TARGET/settings/app.settings.json
curl -s TARGET/assets/config.json
```

### Redirect Chain Analysis
```bash
# Redirects to internal domains reveal admin panels
curl -sI TARGET | grep -i location
# 301 → admin.prod.internal.com = finding
```

### SignalR Endpoint Check
```bash
curl -s TARGET/notify/negotiate
# 200 without auth = unauthenticated access
```

## What to Report
- URL of internal portal/admin panel
- Evidence it's not meant to be public (internal domain, debug info, etc.)
- Any accessible functionality without authentication

## Historical Results
- target-corp: manage.target-corp.com → redirect to admin.prod.pbk8s.com (internal K8s)
- target-corp: Adjacent subdomains exposed employee portals
- target-corp: Management API with CORS misconfiguration

---

## Operator Notes (Battle-Tested)

- **SPA config files are the #1 quick win** — `app.settings.json`, `core.settings.json`, `assets/config.json` often exposed without authentication, leaking internal API URLs
- **SignalR `/negotiate` returning 200 without auth is reportable** — unauthenticated real-time event subscription to internal notifications
- **Redirect chains reveal internal infrastructure** — follow ALL redirects to final destination. Internal domain names in Location headers = evidence of exposed internal services
- **Adjacent subdomain pattern matching** — grep alive hosts for `admin|manage|internal|portal|dashboard|backoffice|staff|cms`. High match rate on enterprise targets
- **MEMORY: 401 on root does not mean fully locked** — always `ffuf -fc 401` to find accessible paths on apparently locked-down portals
- **Non-standard ports are goldmines** — `:3030`, `:8080`, `:8443`, `:9090` on discovered subdomains often host admin interfaces with weaker controls
- **After discovery, test for CORS and access control** — internal portals often have permissive CORS and weak auth assumptions since they were "internal only"

## Related Skills & Chains

| Situation | Pattern / Skill |
|-----------|----------------|
| Need origin IP to reach internal directly | `origin-ip-discovery` |
| 403 on discovered portal | `403-bypass` |
| JS bundles on portal leaking secrets | `js-bundle-secrets` |
| Access control testing on portal | `access-control-testing` |
| Hidden parameters on portal endpoints | `hidden-param-discovery` |
| Auth bypass on portal login | `auth-bypass-testing` |
