---
name: craftercms-attack
description: "Probe CrafterCMS content store APIs for unauthenticated draft and unpublished content plus FreeMarker template path disclosure that can seed SSTI. Use when fingerprinting shows CrafterCMS (/api/1/site/content_store, /studio), commonly on event, media, and tournament sites."
---

# CrafterCMS Content Store Unauthenticated Access

## Crown Jewel Targets

- CrafterCMS deployments on event/tournament/media sites
- Content store API exposing draft/unpublished content metadata
- FreeMarker template paths (potential SSTI vector)

## Attack Surface Signals

- `X-Powered-By: Crafter` header
- `/api/1/site/content_store/` API paths accessible
- CrafterCMS admin interface indicators

## Detection
```bash
# Check server header
curl -sI TARGET | grep -i "x-powered-by.*crafter"

# Direct API test
curl -s "TARGET/api/1/site/content_store/children.json?url=/site/website" | head -50
```

## Endpoints to Test
- `/api/1/site/content_store/children.json?url=/site/website`
- `/api/1/site/content_store/descriptor.json?url=/site/website`
- `/api/1/site/content_store/tree.json?url=/site/website`

## What Leaks
- Full content tree with object IDs
- FreeMarker template paths (potential SSTI vector)
- Internal content structure and organization
- Draft/unpublished content metadata

## Historical Results
- Pokemon championships + worlds sites: Full content tree exposed, FreeMarker paths visible

## Operator Notes (Battle-Tested)

- **Check network requests, not just headers**: CrafterCMS is often behind CDN. Look for `/api/1/site/` calls in browser network tab.
- **FreeMarker paths = potential SSTI**: If template paths are exposed, test for Server-Side Template Injection via FreeMarker expressions.
- **Test all three API endpoints**: `children.json`, `descriptor.json`, `tree.json` — each reveals different metadata.

## Related Skills & Chains

| Pattern | Chain Potential |
|---------|---------------|
| `ssti-testing` | SSTI via exposed FreeMarker templates |
| `api-security-testing` | API endpoint testing |
| `graphql-testing` | Schema/content discovery |
