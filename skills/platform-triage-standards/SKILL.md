---
name: platform-triage-standards
description: "Platform triage standards distilled from Intigriti's public knowledge base: how duplicates are decided, which finding types get a default (usually Low) severity regardless of CVSS, what's out of scope by default, the no-hoarding/48h rule for chained vulnerabilities, and what a report needs to stand on its own (account setup steps, raw requests as text, not just a PoC link or screenshot). Use when triaging a finding before submission, when writing a report, or when deciding whether a borderline finding is worth the write-up. No secrets, no program-specific data -- this is the generic platform rulebook, not any one program's brief."
---

# Platform Triage Standards

Generic triage/report standards a bug-bounty platform applies on top of (and sometimes instead of) raw CVSS. Program-specific briefs always override these when they say something different -- this is the fallback ruleset for everything a brief doesn't address, and the lens to self-triage through before submitting.

## How severity actually gets decided

Three assessment methods exist, and a program can pick any of them; **the program's own written guideline always wins** over all three:

1. **Proof-of-Concept (the default)** -- severity is CVSS scored against the impact you actually *demonstrated*. If your XSS PoC could theoretically reach RCE but you didn't show that, it's scored on what you showed, not the theoretical ceiling.
2. **Vulnerability Type** -- scored on the "initial and immediate effect" of the vulnerability class only; further exploitation steps you describe but didn't demonstrate are not considered.
3. **Custom** -- the program substitutes its own severity table entirely.

CVSS-vector notes that catch people out:
- **Attack Complexity** reflects effort to *exploit*, never effort to *discover*. A hard-to-find bug that's trivial to exploit once found is still low AC.
- **Privileges Required**: an account obtained through public self-registration is **non-privileged (Low PR)** -- "no auth required" is wrong if signup is open to anyone.
- **User Interaction**: every distinct user action the victim must take counts, except an action that happens automatically in a common, everyday flow.
- **Scope Changed**: only applies if the new scope gained has *higher* authorization than the original -- lateral access at the same privilege level is not a scope change.
- **Multi-tenant Confidentiality/Integrity impact**: capped at Low unless you can show complete database-wide access or a genuinely significant business risk -- "I can read one other tenant's record" alone does not justify High C/I.

## Default severities (apply even with a technically-correct CVSS vector)

These finding types are capped at a default severity regardless of how you score them, **unless chained into something with real impact**:

| Finding | Default severity |
|---|---|
| Open redirect (standalone) | Low |
| Content/HTML/CSS injection | Low (unless critical data is actually stolen) |
| Broken link hijacking | Low |
| Debug info / path disclosure | Low (unless actively leveraged into something further) |
| WAF bypass alone, no demonstrated application impact | Low |
| Cookie-bombing DoS | Low |
| Invalidation vulnerabilities | Low (unless real business risk is shown) |

The pattern: a platform treats "I found the primitive" and "I proved the impact" as two different severities, and will not pay out on the former dressed up as the latter.

## Out of scope by default

- **Anything not explicitly listed in scope is out of scope.** The most-specific asset rule applies: `*.example.com` in scope does not pull in `sub.example.com` if `sub.example.com` is separately marked out of scope.
- **Third-party cloud services**: report to the vendor directly unless the program explicitly listed that service in scope. A misconfiguration *of* a third-party service that has in-scope impact is still forwarded; the service's own vulnerabilities are not yours to report here.
- **Personal/B2C leaked credentials**: never validate them against the target, regardless of where you found them.
- **Credentials from a criminal marketplace/breach database**: do not report, do not validate -- using purchased/stolen data funds the people who stole it and is a conduct violation, not a finding.
- **Speculative findings**: unused code paths forward at severity "none" unless you show evidence of production usage; low-entropy secrets ("this looks like a public token") are only in-scope if they're actually predictable or actually bypass authorization.
- **Self-XSS** and **missing-security-headers-alone** are out of scope on essentially every platform, not just Intigriti-specific policy.

## Duplicates and chaining -- the no-hoarding rule

- **No hoarding beyond 48 hours.** If you've found one piece of a chain, you have 48 hours to find and submit the rest before the clock on "you should have reported this already" starts working against you -- sitting on a partial chain hoping to inflate severity later is itself a policy risk.
- **Same root cause, multiple endpoints = one issue.** If the identical vulnerability class and root cause shows up on several endpoints, that is a single finding with multiple affected locations, not N separate reports.
- **Different impact on the same vulnerability** is assessed on the new impact only -- re-reporting the same primitive with a flashier PoC and no new impact does not re-open severity.
- **A regression or a bypass of a previously-fixed issue is a new vulnerability**, not a duplicate of the original report.
- **Combined chain impact is considered** when each step in the chain is itself a unique, independently-fixable vulnerability -- track each step separately even while reporting the combined impact.

## What a report needs to stand on its own

A report should be understandable and reproducible by someone who has never touched this engagement and cannot ask you follow-up questions. Concretely:

- **Every reproduction step is written text**, not implied by a screenshot. A screenshot of a POST request forces the reviewer to manually retype it from a picture -- paste the actual raw request (redacting only live cookies/auth tokens) instead.
- **No PoC-link-only reports.** A hosted PoC link that could go offline, or a video with no accompanying written steps, is not a substitute for a textual reproduction -- the platform (and the program) needs the written steps regardless of what else you attach.
- **Account setup is spelled out**: which role, which account, how it was obtained, and any state it needs to be in before the steps work.
- **The "print test"**: if the report were printed on paper with no links and no attachments, could someone still follow it end to end? If not, it is incomplete.
- **Impact statement covers all of**: technical impact (what access/data), user impact (who is harmed and how), compliance impact where relevant (e.g. GDPR), and optionally business impact -- vague impact ("sensitive data exposure") without specifics ("N user records including email + phone") reads as padding, not evidence.

## Before submitting -- self-triage checklist

- [ ] Asset is explicitly in scope (most-specific-asset rule applied)
- [ ] Finding type is not one of this program's `always_rejected` categories
- [ ] Finding is not one of the "default Low" types above, unless it's genuinely chained into more impact
- [ ] Rate limits and any required custom headers/User-Agent were respected during testing
- [ ] Report is in English, with copy-pasted raw requests, not screenshots-only
- [ ] Impact statement is specific (counts, data types, affected roles), not generic
- [ ] Any credentials involved were obtained and used ethically (no purchased/leaked personal credentials, no excessive validation beyond proving access)
- [ ] No hoarding: if this is part of a chain, the rest of the chain is submitted within 48 hours
- [ ] Severity claimed matches demonstrated impact, not the theoretical ceiling of the vulnerability class
