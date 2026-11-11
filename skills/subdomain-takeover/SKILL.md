---
name: subdomain-takeover
description: "Detect dangling CNAMEs pointing at deprovisioned services and actually claim the resource to prove takeover — GitHub Pages, Azure CDN, S3, Heroku, Shopify. Use when DNS enumeration surfaces CNAMEs resolving to service error pages; a dangling record on its own is not reportable, so prioritise GitHub Pages and other trivially claimable services."
---

# Dangling CNAME Subdomain Takeover

## Crown Jewel Targets

- **GitHub Pages CNAME** — `*.github.io` pointing to unclaimed repo, claimable by creating matching repo with CNAME file
- **Azure CDN endpoints** — `*.azureedge.net` CNAME to deprovisioned CDN profile, create matching endpoint in Azure
- **AWS S3 buckets** — CNAME to `*.s3.amazonaws.com` with deleted bucket, create bucket with same name
- **target-corp stores** — `shops.myshopify.com` CNAME to closed store, register same store name
- **Heroku apps** — `*.herokuapp.com` CNAME to deleted app, create app with same name
- **Cookie-setting across parent domain** — proven takeover enables setting cookies on `.victim.com` affecting all sibling services

## Attack Surface Signals

- `dnsx -cname -resp` output showing NXDOMAIN for CNAME targets
- `dig +short CNAME sub.target.com` pointing to third-party cloud service domains
- HTTP responses showing default cloud provider error pages (S3 NoSuchBucket, GitHub 404)
- Stale DNS records from decommissioned projects/services
- Multiple TLDs for same organization (check ALL for dangling records)
- Subdomain enumeration revealing `dev.`, `staging.`, `beta.` prefixes

## Detection
```bash
# Enumerate CNAMEs
dnsx -l subdomains.txt -cname -resp | grep NXDOMAIN

# Check specific
dig +short CNAME target.domain.com
# If CNAME → NXDOMAIN = potential takeover
```

## Claimable Providers
| Provider | Claimable | Notes |
|----------|-----------|-------|
| AWS S3 | Yes | Bucket name in CNAME |
| Heroku | Yes | heroku.com CNAME |
| GitHub Pages | Yes | github.io CNAME |
| Azure CDN | Yes | azureedge.net CNAME |
| target-corp | Yes | shops.myshopify.com |
| AWS ALB | **No** | Auto-generated hostnames |

## NOT Takeable
- AWS ALB endpoints (auto-generated)
- CNAMEs that resolve (even if target shows default page)
- Internal-only DNS records

## Report Requirements
- Must prove actual takeover (claim the resource)
- Just proving dangling CNAME is usually insufficient
- Show cookie-setting capability across sibling services
- **MUST deploy proof-of-ownership page** with hunter identifier (username) on the claimed subdomain
- **Screenshot of proof page** served from target domain = mandatory evidence
- If domain already taken over by third-party (gambling, phishing) → you are NOT the claimer → triage will ask "Who performed this takeover?" → severity downgrade or REJECT

## Takeover Claim Protocol (MANDATORY)
1. **Detect** dangling DNS: `dnsx -cname -resp | grep NXDOMAIN` or A record → third-party IP
2. **Identify provider**: Match CNAME/IP to claimable service (S3, Azure CDN, GitHub Pages, Heroku, target-corp)
3. **Claim resource**: Create bucket/repo/endpoint matching the CNAME target name
4. **Deploy proof page**: HTML with `"Subdomain Takeover PoC by [hunter_username] — [date]"`
5. **Verify**: `curl https://target-subdomain.victim.com` returns YOUR proof page
6. **Screenshot**: Browser screenshot showing proof page on victim domain
7. **Cookie test**: Check if `.victim.com` cookies are accessible from takeover domain (impact escalation)
8. **Report**: Include evidence that YOU claimed the resource, not someone else

## Case Studies
- **target-corp-5MXXWN34**: Subdomain takeover reported without proof of hunter claim → closed by triager. Lesson: triager requires YOU to be the one who performed the takeover.
- **LG FINDING-054**: `dev.pay.lg.com` → third-party gambling site. This is NOT hunter's takeover — it's pre-existing infrastructure issue. Reporting this without claiming = reporting someone else's work.

## Historical Results
- ING: sandbox.api.pos.ing.pl → paymento.pl (NXDOMAIN) — High/P2
- ING: dealwise-static.homebank.ro → azureedge.net (NXDOMAIN) — High/P2

---

## Operator Notes (Battle-Tested)

- **MUST deploy proof page** — MEMORY rule: just finding dangling CNAME is insufficient. You must CLAIM the resource and deploy a proof page with your hunter username
- **GitHub Pages only** — MEMORY rule: only GitHub Pages takeovers are reliably claimable. Skip EB/S3/Azure/Heroku unless you can actually claim and verify
- **Third-party gambling/phishing site =/= your takeover** — if someone else already took over the subdomain, reporting it as YOUR finding will be rejected. Triager asks "Who performed this?"
- **Cookie test = impact escalation** — after claiming subdomain, test if you can set `.victim.com` cookies affecting all sibling services. This upgrades severity
- **Scan ALL TLDs** — organization may have `target.com`, `target.nl`, `target.de` etc. Check all for dangling records. Country TLDs = highest value
- **AWS ALB endpoints are NOT takeable** — auto-generated hostnames cannot be claimed. Save time by filtering these out immediately
- **Screenshot from browser is mandatory evidence** — `curl` showing content is not enough. Browser screenshot of proof page served on victim domain required

## Related Skills & Chains

| Situation | Pattern / Skill |
|-----------|----------------|
| Found internal/admin portal on subdomain | `internal-portal-discovery` |
| Need origin IP behind CDN | `origin-ip-discovery` |
| Host header attacks on discovered domain | `host-header-attacks` |
| Finding discovered, check chain | `auto-chain-discovery` |
