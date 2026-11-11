---
name: mobile-api-testing
description: "Extract and test mobile backends — jadx APK decompilation, React Native index.android.bundle recovery, Frida SSL pinning and root bypass, hardcoded secret extraction, exported activity abuse, deep link hijacking, and mobile-only endpoints that skip the web app's auth checks. Use when the target ships an Android or iOS app, or when the pre-auth web surface is exhausted and a new angle is needed."
---

# Mobile API Extraction & Testing

## Crown Jewel Targets

- **React Native apps** -- `assets/index.android.bundle` = FULL JavaScript source code. Treat exactly like web JS analysis (). Highest ROI mobile target type
- **Apps with hardcoded Firebase keys** -- test Firestore/RTDB direct access without auth. If rules are misconfigured, you get full database read/write
- **Banking/fintech mobile apps** -- mobile-only API endpoints often lack auth checks present in web UI. Same backend, weaker client-side assumptions
- **Apps with exported activities** (`android:exported="true"`) -- bypass login screen, access admin features, trigger sensitive actions via `adb shell am start`
- **Apps using custom URI schemes for OAuth** -- `myapp://callback?token=XXX` can be hijacked by another app registering the same scheme. Token theft via deep link hijacking
- **Apps with `android:allowBackup="true"`** -- `adb backup` extracts SharedPreferences containing tokens, passwords, session data in plaintext XML
- **Capacitor/Cordova apps** -- `assets/www/` contains the COMPLETE web app source including `.env` and config files with secrets
- **Apps with Google Maps API keys** -- check if billing-enabled APIs (Directions, Geocoding, Places) are unrestricted. Financial impact via quota abuse

## Attack Surface Signals

- **APK signals**: `index.android.bundle` (React Native), `assets/www/` (Capacitor/Cordova), `libapp.so` (Flutter), `assemblies/` (Xamarin)
- **Manifest signals**: `android:exported="true"`, `android:allowBackup="true"`, `android:debuggable="true"`, `<data android:scheme=` (deep links)
- **Secret locations**: `BuildConfig.java`, `strings.xml`, `google-services.json`, `network_security_config.xml`, Gradle properties, `assets/*.json`
- **API patterns**: Retrofit annotations (`@GET`, `@POST`), OkHttp `Request.Builder().url()`, `BASE_URL`/`API_URL` in BuildConfig

## Why Mobile Apps Are High-ROI for Bug Bounty
- Developers hardcode secrets assuming APK is "compiled" = safe (FALSE — jadx reverses in seconds)
- Mobile-only API endpoints often lack auth checks present in web UI
- Same backend, different client = different access control assumptions
- API version fragmentation: old versions still active, may lack security
- React Native apps = FULL JavaScript source code in APK (same as web)

## APK Acquisition
- **apkeep (primary)**: WSL Kali — `wsl -d kali -- apkeep -a com.target.app ./`
  - Sources: APKPure (default, no auth), Google Play (needs gcloud), F-Droid, Huawei
  - XAPK handling: unzip the .xapk and use base.apk
- **Package ID from URL**: `python scripts/mobile/parse_package_id.py "PLAY_STORE_URL"`
- Fallback: apkpure.com, apkcombo.com, apkmirror.com (manual download)
- 103 Android package IDs tracked: `platform scope file

## APK Decompilation
- jadx (primary): `~/.local/bin/jadx -d output/ --deobf app.apk`
  - Flags: `--show-bad-code` (don't skip broken classes), `--threads-count 4` (multi-core)
  - OOM fix: `JAVA_OPTS="-Xmx4g"` or reduce with `--no-debug-info`
- apktool (resources): `apktool d app.apk -o output/`
- dex2jar + JD-GUI (alternative)
- For split APKs: `apktool d base.apk && apktool d split_config.arm64_v8a.apk`

## Dynamic Analysis (Frida)
- SSL pinning bypass: `scripts/mobile/frida/bypass_ssl_pinning.js` — hooks SSLContext, OkHttp3, Conscrypt, TrustKit
- Root detection bypass: `scripts/mobile/frida/bypass_root_detection.js` — File.exists, Runtime.exec, native access()
- Crypto key dump: `scripts/mobile/frida/dump_crypto_keys.js` — Cipher.init, SecretKeySpec, KeyStore
- Usage: `wsl -d kali -- frida -U -f <package> -l <script.js> --no-pause`
- Full guide: `scripts/mobile/frida/README.md`

## Secret Extraction Patterns (reuse from js-bundle-secrets.md + Java-specific)

### Universal patterns (same as JS)
```regex
api[_-]?key|apikey|api[_-]?secret
(secret|token|password|passwd|pwd)\s*[:=]
Bearer\s+[A-Za-z0-9\-._~+/]+=*
Authorization:\s*(Basic|Bearer)
AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY
```

### Java/Kotlin specific
```regex
SharedPreferences.*put(String|Int|Boolean).*("token"|"session"|"password"|"key")
BuildConfig\.(API_KEY|SECRET|TOKEN|BASE_URL)
getString\(R\.string\.(api_key|secret|token|password)\)
new OkHttpClient\.Builder\(\).*addInterceptor
```

### Firebase
```regex
google-services\.json
firebase.*apiKey
messagingSenderId
storageBucket.*\.appspot\.com
```

### Mobile-specific high-value
```regex
# FCM Server Key (push notification control)
AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}
# Google API Key
AIza[0-9A-Za-z_-]{35}
# Apple push certificate password
apns.*password|push.*certificate
```

## API Endpoint Extraction

### Retrofit (most common)
```java
@GET("/api/v1/users/{id}")
@POST("/api/v1/orders")
@Headers("Authorization: Bearer {token}")
```
Grep: `@GET|@POST|@PUT|@DELETE|@PATCH|@Headers|@Url`

### OkHttp
```java
Request.Builder().url(BASE_URL + "/endpoint")
```

### Base URL Locations
- `BuildConfig.java` → `BASE_URL`, `API_URL`, `SERVER_URL`
- `strings.xml` → `<string name="base_url">`
- `network_security_config.xml` → `<domain>` entries
- Gradle properties → `buildConfigField`
- Environment configs in assets/ folder

## Common Mobile-Specific Vulnerabilities

### 1. Hardcoded API Keys with Excessive Permissions
- Firebase keys → test Firestore/RTDB direct access without auth
- Google Maps keys → check billing-enabled APIs (Directions, Geocoding = $$)
- AWS keys → enumerate S3 buckets, Lambda functions

### 2. Missing Certificate Pinning
- Check `network_security_config.xml` for `<pin-set>`
- No pinning = standard Burp proxy intercept works
- With pinning = need Frida/Objection bypass (dynamic analysis)

### 3. Exported Activities/Services
- `android:exported="true"` without permission checks
- Test: `adb shell am start -n com.app/.ExportedActivity`
- Impact: bypass login, access admin features, trigger actions

### 4. Deep Link Hijacking
- Custom URI schemes: `myapp://callback?token=XXX`
- Another app can register same scheme → steal tokens
- Test: find `<data android:scheme="..." />` in manifest
- Impact: OAuth token theft, auth bypass

### 5. WebView JavaScript Interface
- `addJavascriptInterface()` → if WebView loads attacker-controlled URL = RCE
- Check: grep `addJavascriptInterface|setJavaScriptEnabled|loadUrl`

### 6. Backup Enabled
- `android:allowBackup="true"` → `adb backup` extracts app data
- SharedPreferences, databases, files accessible

### 7. Debug Mode in Production
- `android:debuggable="true"` → attach debugger, read logcat
- Check for verbose logging: `Log.d|Log.v|Log.i` with sensitive data

### 8. Plaintext SharedPreferences
- Tokens, passwords stored in XML files
- Path: `/data/data/com.app/shared_prefs/`
- No encryption = any root access reads all

## React Native / Flutter / Capacitor

### React Native (HIGHEST PRIORITY)
- `assets/index.android.bundle` = **FULL JavaScript source**
- Treat exactly like web JS analysis ()
- js-beautify → grep endpoints/secrets
- Hermes bytecode: `hbc-decompiler` to recover JS

### Flutter
- `libapp.so` in `lib/` → harder to reverse
- `strings libapp.so | grep -i "http\|api\|key\|token"` → extract URLs/strings
- Dart snapshot format: specialized tools (reFlutter, Doldrums)

### Capacitor / Cordova
- `assets/www/` = **complete web app source**
- Standard web analysis: JS files, HTML, CSS
- Often includes `.env` or config files with secrets

### Xamarin
- DLL files in `assemblies/`
- Use dnSpy or ILSpy to decompile C# code
- Same analysis as standard .NET application

## Testing Checklist

- [ ] APK downloaded and decompiled (jadx + apktool)
- [ ] Secrets extracted (grep)
- [ ] API endpoints mapped and cross-referenced with web surface
- [ ] AndroidManifest.xml reviewed (exported, backup, debug, deep links)
- [ ] Certificate pinning checked (network_security_config.xml)
- [ ] Backend APIs imported to Burp Repeater
- [ ] Mobile-only endpoints tested for missing auth
- [ ] IDOR tested on user-specific mobile endpoints
- [ ] Deep links tested for token theft / injection
- [ ] React Native bundle analyzed (if applicable)
- [ ] Results recorded via record_fact/insert_assets
- [ ] Findings saved to standard FINDING-{TARGET}-NNN/ structure

## Operator Notes (Battle-Tested)

1. **jadx with `--show-bad-code --deobf` flags is mandatory** -- `~/.local/bin/jadx -d output/ --show-bad-code --deobf app.apk`. Without `--show-bad-code`, jadx silently skips broken/obfuscated classes which often contain the most interesting code. OOM fix: `JAVA_OPTS="-Xmx4g"`.
2. **React Native bundle = web-level source access** -- `assets/index.android.bundle` is the FULL JavaScript source. Run `js-beautify` then grep for endpoints, secrets, API keys exactly like web JS analysis. For Hermes bytecode: use `hbc-decompiler`. This is the single highest-ROI mobile analysis technique.
3. **Frida SSL pinning bypass is a prerequisite for dynamic analysis** -- without it, Burp proxy cannot intercept HTTPS traffic. Use `scripts/mobile/frida/bypass_ssl_pinning.js` which hooks SSLContext, OkHttp3, Conscrypt, and TrustKit. Run via: `wsl -d kali -- frida -U -f <package> -l bypass_ssl_pinning.js --no-pause`.
4. **Mobile-only endpoints are often unprotected** -- decompile APK, extract all API endpoints from Retrofit annotations and OkHttp calls, import into Burp Repeater, test each without mobile-specific auth tokens. Developers frequently assume only the app calls these endpoints.
5. **Write results back immediately** -- insert_assets for discovered API endpoints and deep link schemes, record_fact for hardcoded secrets found (confidence=observed). This prevents redoing the same analysis later in the task or in a future task on the same asset graph.

## Related Skills & Chains

| When | Go to |
|------|-------|
| Mobile API endpoints need security testing | `api-security-testing` |
| IDOR/BAC on mobile-only endpoints | `access-control-testing` |
| Auth bypass via deep link token theft | `auth-bypass-testing` |
| Hidden params in mobile API requests | `hidden-param-discovery` |
| Hardcoded URLs lead to SSRF | `ssrf-testing` |
