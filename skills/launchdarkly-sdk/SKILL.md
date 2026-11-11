---
name: launchdarkly-sdk
description: "Enumerate LaunchDarkly feature flags from a leaked client-side SDK key and test whether flipping flags bypasses age verification, premium gating, or beta restrictions. Use when network requests hit app.launchdarkly.com / events.launchdarkly.com, or an SDK key turns up in a JS bundle."
---

# LaunchDarkly Feature Flag Enumeration

## Crown Jewel Targets

- Children's/COPPA platforms using feature flags for age verification
- SaaS platforms with premium feature flags
- Applications with beta/experimental features behind flags

## Attack Surface Signals

- Network requests to `app.launchdarkly.com` (use browser network tab, NOT JS source)
- SDK keys in fetch URLs, not in JavaScript source code
- Feature flag evaluation responses in network traffic

## Detection
```bash
# Check network requests (not JS source!)
# Use Playwright browser_network_requests
# Look for: app.launchdarkly.com in fetch URLs
```

**Key insight:** SDK keys appear in fetch URLs to `app.launchdarkly.com`, NOT in JS source code. Must use network interception.

## Exploitation
```bash
# With SDK key, enumerate all flags
curl "https://app.launchdarkly.com/sdk/eval/ENVIRONMENT_ID/contexts/BASE64_CONTEXT"
```

## Impact Assessment
- On children's/COPPA platforms: High (age verification, compliance features)
- On general platforms: Medium (feature flags = business logic insight)
- SDK keys are READ-ONLY — cannot modify flags

## Limitations
- Cannot modify flag values (read-only SDK key)
- Cannot exfiltrate user data through flags
- PUT/POST/PATCH to flag endpoints = unauthorized

## Historical Results
- Pokemon: 8 SDK keys, 31 feature flags enumerated. Age Gate Modal disabled globally on COPPA platform.

## Operator Notes (Battle-Tested)

- **SDK keys are in NETWORK requests, not JS source**: Must use Playwright network interception or browser DevTools. JS grep will miss these.
- **SDK keys are read-only**: Cannot modify flags. Impact assessment depends on what flags control.
- **COPPA platforms elevate severity**: Disabling age gates on children's platforms is HIGH impact due to regulatory implications.

## Related Skills & Chains

| Pattern | Chain Potential |
|---------|---------------|
| `js-bundle-secrets` | JS analysis methodology |
| `oauth-testing` → `references/oauth-client-id-hunting.md` | Client ID discovery across subdomains |
| `api-security-testing` | API endpoint testing |
