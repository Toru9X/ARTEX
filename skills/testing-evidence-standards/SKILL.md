---
name: testing-evidence-standards
description: Minimum evidence bar for a finding to be credible, to avoid false positives in the client report.
---
# Testing & Evidence Standards

A wrong client report damages the company's credibility. The rules below prioritize reliability over speed.

Distinguish network-layer errors from application-layer errors. A 403 from a load balancer or CDN such as CloudFront, Akamai, or AWS ELB is not a finding — that's a network-layer block, not an application logic flaw. A 401 is usually more worth attention since it's real application auth.

Detect SPAs before fuzzing broadly. If a random path returns the same content length as a real path, that's a SPA catch-all, and fuzzing with a large wordlist will produce nothing but false positives. Always probe about 30 paths across the whole host first before fuzzing a host deeply.

Use curl only to discover, use Playwright and Burp to prove. Any finding based only on curl must be re-verified with a real browser before it goes into the report, since a browser doesn't send some headers the way curl simulates them, and many bugs only trigger through a caching layer or the full request chain.

Four mandatory questions for every finding — missing any one of the four means it isn't ready to report: WHY explains why this specific system is vulnerable, HOW is the detailed exploit chain, WHAT is the concrete business impact, and WHO is the user or system affected.

Analyze chains. A standalone Low finding that doesn't chain with anything else is an incomplete finding. Spend time looking for related findings before finalizing severity.

Evidence verification gate. Require at least two successful reproductions with real evidence such as screenshots and real HTTP request/response pairs before considering a finding accepted.

Keep sessions alive when testing flows that require login. Save the session or storage state after a successful login and reuse it for subsequent tests, avoiding repeated logins, which are both slow and risk triggering real rate-limiting or lockouts on the client's system.

Full coverage per scope — use a coverage tracker against the scope list and by OWASP category, and confirm the coverage level promised to the client has been reached before closing the engagement.
