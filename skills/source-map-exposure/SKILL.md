---
name: source-map-exposure
description: "Recover original application source from exposed .js.map files on SPA deployments, then judge whether the reconstructed code actually exposes secrets, internal endpoints, or auth logic worth reporting. Use when a React/Angular/Vue/Next.js target serves .js.map in production — the map alone is spam, so report only what it reveals."
---

# JavaScript Source Map Exposure

## Crown Jewel Targets

- React/Angular/Vue SPA deployments with `.js.map` files not stripped
- Next.js apps with source maps in production
- Enterprise SPAs with auth flow logic in source maps
- Applications with hardcoded tokens/API keys in original source

## Attack Surface Signals

- `.js.map` extension returning 200 on main bundle URLs
- SPA frameworks: `__NEXT_DATA__`, `ng-version`, `data-reactroot`
- Large JS bundles (100KB+) suggesting compiled/bundled source

## Detection
```bash
# Find JS bundles
curl -s TARGET | grep -oP 'src="[^"]*\.js"' | head -20

# Check for source maps
curl -sI TARGET/path/to/bundle.js.map | head -5
# 200 = exposed, 404 = not available
```

**Quick check:**
```bash
curl -s TARGET/main.*.js.map -o /dev/null -w "%{http_code}"
```

## What to Look For in Source Maps
- API endpoints, internal URLs, staging environments
- Authentication flow logic (OAuth client_ids, scopes)
- Hardcoded tokens, API keys
- Internal service names, architecture details
- Environment variables referenced in code

## Report Notes
- Source map alone = Medium (info disclosure)
- Source map + secrets found inside = High
- Always mention what specific sensitive info was found
- Include the js-beautify output of relevant sections

## Historical Results
- target-corp OneID: Auth source code revealed via bootstrap.js.map — Medium
- Pokemon: 4 subdomains with .js.map (support-login revealed Zendesk SSO flow)

## Operator Notes (Battle-Tested)

- **Source map alone = Medium max**: MEMORY.md rule — source map exposure alone is often rejected. Must expose exploitable data (working credentials, API keys proven by live call).
- **Grep source maps for secrets**: After downloading, `grep -iE "api[_-]?key|secret|token|password|credential"` in the reconstructed source.
- **Quick check**: `curl -s TARGET/main.*.js.map -o /dev/null -w "%{http_code}"` — 200 = exposed.
- **Auth flow logic is valuable**: OAuth client_ids, scopes, internal service names exposed in auth source code can feed into OAuth exploitation.

## Related Skills & Chains

| Pattern | Chain Potential |
|---------|---------------|
| `js-bundle-secrets` | JS secret extraction methodology |
| `iis-shortname-exploitation` | Discover .map files via shortname |
| `nextjs-middleware-bypass` | Next.js specific exploitation |
| `oauth-testing` → `references/oauth-client-id-hunting.md` | OAuth client_id from source maps |
