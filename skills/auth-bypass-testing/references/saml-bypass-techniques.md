---
name: saml-bypass-techniques
pattern: SAML SSO Bypass (Signature Wrapping, Comment Injection, Bypass)
description: "Test SAML SSO for signature wrapping (XSW1-8), XML comment injection in NameID, signature stripping, XSLT injection, and assertion replay"
tech: [saml, sso, xml, oauth]
triggers: ["/test-auth", "saml bypass", "sso bypass", "saml injection", "xml signature", "xsw attack", "saml raider"]
related_patterns: ["auth-bypass-techniques", "oauth-token-theft-chain", "xxe-techniques", "csrf-advanced"]
sources: ["portswigger-academy", "h1-disclosed"]
severity: Critical
---

# SAML SSO Bypass (Signature Wrapping, Comment Injection, Bypass)

## Crown Jewel Targets

- **Enterprise SSO (Okta, ADFS, PingFederate)** -- SAML is the primary auth mechanism; bypass = access to all connected apps ($10K+ bounties on GitHub, Slack, Microsoft)
- **SaaS platforms accepting external IdPs** -- Service Providers that trust third-party SAML assertions without strict validation
- **Custom SAML implementations** (non-library) -- hand-rolled XML parsing is almost always vulnerable to XSW or comment injection
- **Multi-cloud dashboards** (AWS, Azure, GCP consoles) -- SAML federation to cloud = infrastructure-level access on bypass
- **Healthcare/government portals** using SAML for citizen identity -- highest impact due to PII scope
- **Legacy Java-based SPs** -- older XML parsers (Xerces, Saxon) are more susceptible to XSLT injection and parser differentials

## Attack Surface Signals

- **URL patterns**: `/saml/acs`, `/auth/saml`, `/saml/metadata`, `/saml/login`, `/saml/sso`, `/saml/consume`, `/.well-known/saml`
- **Response signals**: `SAMLResponse` in POST body, `SAMLRequest` in redirects, `RelayState` parameter
- **Headers**: `X-SAML-*`, redirect to external IdP (Okta, ADFS, OneLogin, PingFederate)
- **Tech signals**: `/FederationMetadata/2007-06/FederationMetadata.xml` (ADFS), Shibboleth `/idp/profile/`, SimpleSAMLphp `/simplesaml/`

## Detection
```bash
# Check for SAML endpoints
curl -s TARGET | grep -iE "saml|sso|assertion|idp|sp_entity"
# Find SAML response in Burp history
# Check .well-known or metadata
curl -s TARGET/saml/metadata 2>/dev/null | head -20
curl -s TARGET/.well-known/saml 2>/dev/null
```

**Positive indicators:**
- `/saml/acs` or `/auth/saml` endpoint
- SAMLResponse parameter in POST bodies
- X-SAML-* headers
- SSO redirect to external IdP (Okta, ADFS, OneLogin, PingFederate)

## Exploitation
1. **XML Signature Wrapping (XSW)**: Move signed element, inject unsigned malicious element in same position
2. **XML Comment Injection**: `admin<!---->@target.com` → signature validates `adminXXX@target.com` but app parses as `admin@target.com`
3. **Signature Stripping**: Remove `<ds:Signature>` entirely → some SPs don't verify if missing
4. **NameID Manipulation**: Change NameID value after signature verification (parser inconsistency)
5. **XSLT Injection**: Some SAML processors apply XSLT → inject arbitrary XSLT for RCE

## PoC Template
```xml
<!-- XML comment injection in NameID -->
<saml:NameID>admin<!--comment-->@victim.com</saml:NameID>
<!-- Signature covers: admin[comment]@victim.com -->
<!-- App sees: admin@victim.com (comment stripped by XML parser) -->
```

```bash
# Signature Stripping
# 1. Capture SAMLResponse in Burp
# 2. Base64 decode → edit XML
# 3. Remove entire <ds:Signature>...</ds:Signature> block
# 4. Base64 encode → replay
# If SP doesn't enforce signature presence → authenticated as any user
```

## Important Notes
- SAML Raider Burp plugin automates XSW attacks (8 variants: XSW1-XSW8)
- Always test both signature stripping AND wrapping — different SPs fail differently
- Check `InResponseTo` attribute — if missing CSRF protection in SAML flow
- SAML assertion replay: capture valid assertion and replay after session expires

## Reference Writeups
- [SAML Bug in Github worth $15,000](http://www.economyofmechanism.com/github-saml.html)
- [Slack SAML authentication bypass](http://blog.intothesymmetry.com/2017/10/slack-saml-authentication-bypass.html) by Antonio Sanso
- [The road to hell is paved with SAML Assertions (Microsoft)](http://www.economyofmechanism.com/office365-authbypass.html)
- [XXE through SAML](https://seanmelia.files.wordpress.com/2016/01/out-of-band-xml-external-entity-injection-via-saml-redacted.pdf)
- [SAML Pen Test Good Paper](http://research.aurainfosec.io/bypassing-saml20-SSO/)

## Operator Notes (Battle-Tested)

1. **SAML Raider (Burp plugin) is non-negotiable** -- automates all 8 XSW variants (XSW1-XSW8). Install from BApp Store, intercept SAMLResponse, right-click to test all variants in seconds. Manual XML editing is error-prone.
2. **Always test BOTH signature stripping AND wrapping** -- some SPs reject missing signatures but accept wrapped ones (and vice versa). Test removal of entire `<ds:Signature>` block as a separate test from XSW attacks.
3. **Comment injection is the most underestimated vector** -- `admin<!---->@target.com` passes signature validation but XML parsers strip comments, yielding `admin@target.com`. Test on every NameID field.
4. **Check InResponseTo for CSRF protection** -- missing or unchecked `InResponseTo` attribute means you can replay captured SAML assertions across sessions. Combine with social engineering for practical exploitation.
5. **XXE through SAML is still alive** -- SAMLResponse is XML. Inject XXE in the assertion body or attribute values. See `xxe-techniques` for payloads. Many SAML processors do not disable external entities.

## Related Skills & Chains

| When | Go to |
|------|-------|
| Non-SAML SSO (OAuth/OIDC) detected | `oauth-token-theft-chain` |
| Generic auth bypass (2FA, session) | `auth-bypass-techniques` |
| XML parsing in SAML flow | `xxe-techniques` |
| CSRF on SAML login/logout endpoints | `csrf-advanced` |
| Need to chain with XSS for ATO | `dom-based-vulnerabilities` |
