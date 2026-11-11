---
name: csp-bypass
description: "Turn a Content-Security-Policy whitelist into an XSS delivery path by finding script-src entries pointing at expired or NXDOMAIN domains an attacker can simply register. Use when a target ships a CSP listing third-party analytics, legacy vendors, or defunct services — check every whitelisted host for availability."
---

# CSP Bypass via Unregistered Whitelisted Domain

## Crown Jewel Targets

- Sites with CSP `script-src` whitelisting expired/NXDOMAIN domains
- GDPR/privacy portals with third-party analytics in CSP
- Applications with legacy CSP entries referencing defunct services

## Attack Surface Signals

- `Content-Security-Policy` header with external domain references
- NXDOMAIN DNS response for whitelisted domains
- Expired domain WHOIS records for CSP-listed domains

## Detection
```bash
# Extract CSP header
curl -sI TARGET | grep -i content-security-policy

# Parse whitelisted domains
# Check each domain for NXDOMAIN or available registration
whois DOMAIN_FROM_CSP
dig DOMAIN_FROM_CSP
```

## Exploitation
1. Find CSP header with external domains in `script-src` or `default-src`
2. Check each whitelisted domain for availability (NXDOMAIN, expired, available for registration)
3. If registerable → register domain → host malicious JS
4. The CSP trusts your controlled domain → XSS bypass

## Report Notes
- Must demonstrate the domain is actually registerable (WHOIS + RDAP check)
- Show the specific CSP directive that whitelists the domain
- Explain the attack chain: register → host JS → bypass CSP → XSS

## Historical Results
- target-corp: moboxhelp.com NXDOMAIN but whitelisted in CSP on GDPR portal — Medium

## Operator Notes (Battle-Tested)

- **Must prove domain is registerable**: NXDOMAIN alone is not enough. Show WHOIS + RDAP confirm the domain can be purchased.
- **Only report if XSS vector exists**: CSP bypass without an injection point is theoretical. Need at least a reflected/DOM XSS that CSP was blocking.
- **Parse ALL CSP directives**: Not just `script-src` — check `default-src`, `connect-src`, `frame-src` for takeover opportunities.

## Related Skills & Chains

| Pattern | Chain Potential |
|---------|---------------|
| `abandoned-cloud-takeover` | Cloud storage + CSP takeover |
| `subdomain-takeover` | Subdomain takeover for CSP bypass |
| `xss-testing` | DOM XSS + CSP bypass chain |
