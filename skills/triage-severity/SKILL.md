---
name: triage-severity
description: Decide severity and go/no-go for including a finding in the report, based on the CVSS and CWE mapping.
---
# Triage & Severity

Triage is a mandatory gate. Do not triage inline, and do not add a finding to the report on your own before it has gone through triage.

Severity scale follows CVSS version 3.0. 9.0 to 10.0 is Critical, e.g. unauthenticated RCE or insecure deserialization. 7.0 to 8.9 is High, e.g. SQL injection, sensitive IDOR, internal SSRF, auth bypass, path traversal, XXE. 4.0 to 6.9 is Medium, e.g. reflected XSS, open redirect, state-changing CSRF, mass assignment. 1.0 to 3.9 is Low, e.g. minor information disclosure. 0.1 to 0.9 is Informational, e.g. banner or version disclosure.

Some categories of finding need extra evidence before being accepted — not an automatic reject like some bug-bounty programs, but real evidence of impact is required before it goes into the client report. Version/banner disclosure, missing security headers, or default pages are only accepted if there's an unpatched CVE or they lead to a real directory listing. Self-XSS is not accepted unless chained with CSRF or clickjacking to turn it into a remotely exploitable attack. CORS misconfiguration is only accepted with an arbitrary origin plus credentials and a PoC that retrieves real data. A standalone open redirect is only accepted if it chains into OAuth token theft or SSO bypass. Unrate-limited OTP is only accepted if you can prove the time-to-exhaust is less than the OTP's expiry window, with a real account-takeover PoC.

Can the finding defend itself in front of the client. Has the impact chain from misconfiguration to exploitation to impact actually been demonstrated. Does the severity actually match a real CVSS vector or is it just a feeling. Has it passed a technical critique. Does it answer all four questions — WHY, HOW, WHAT, WHO. Is it on the contract's exclusion list.
