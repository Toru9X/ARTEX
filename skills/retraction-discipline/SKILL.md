---
name: retraction-discipline
description: "Finding retraction methodology — when and how to retract submitted findings before triager closes them. Self-retraction is a positive signal. Use when doubting a submitted finding or when post-submission evidence contradicts the initial claim."
---

# Retraction Discipline — Self-Correction Protocol

Self-retraction is a **positive signal**, not a failure. A retracted finding hits your platform metric less than a triager-closed N/A. Good hunters retract fast and move on.

## When to Retract

### Immediate Retraction (within minutes)
- You realize the "vulnerability" is actually a feature (e.g., CORS reflection is by design)
- The PoC only works because of your local environment (proxy artifact, DNS cache)
- Another researcher published the same finding while you were writing

### Post-Submission Review (within 24h)
- Browser verification fails what curl "confirmed"
- The response differential was caused by caching, not by your payload
- The 403→200 difference was load balancer rotation, not auth bypass
- Statistical jitter: n=1 timing difference disappeared on retry

### Never Retract
- Triager asks for clarification (respond, don't retract)
- You found a "better" way to exploit the same bug (update the report instead)
- Another researcher reports the same bug (that's a dupe, not a retraction)

## 7-Point Pre-Retraction Checklist

Before retracting, verify ALL of these:

1. **Reproduce again** — Try the PoC one more time. Sometimes intermittent = real
2. **Different network** — Try without VPN, different IP. Geo-based responses are real findings
3. **Different browser/tool** — Curl ≠ browser. Check with Playwright
4. **Check timing** — Was the target deploying when you tested? Rate limit lifted temporarily?
5. **Read the program rules again** — Some "informational" findings are actually in-scope for specific programs
6. **Check if partial credit** — Can you downgrade severity instead of retracting? (Critical → Medium)
7. **Save evidence locally** — Even retracted findings teach you something. Archive in `_archive/`

## Retraction Template

```
## Retraction Notice

**Finding**: [FINDING-NNN]
**Submitted**: [date]
**Retracted**: [date]

### Reason for Retraction
[One paragraph explaining what was wrong]

### What Was Observed vs What Actually Happened
- **Observed**: [what your initial PoC showed]
- **Reality**: [what actually caused the behavior]

### Root Cause of False Positive
[Why you made this mistake — helps prevent recurrence]

### Lesson Learned
[One sentence: what to check next time]
```

## Worked Examples (Real Engagement Lessons)

### Example 1: target-corp Korea — 4 Fake HIGH Findings (2026-06-11)
**What happened**: Agent-generated findings claimed 4 HIGH vulns on Korean target-corp domains. All were hallucinated — agents reported status codes and responses that didn't match reality.
**Root cause**: Agents ran curl commands but interpreted error responses as successful exploitation. No manual verification step.
**Lesson**: ALWAYS curl-verify EVERY agent finding manually before submitting. Agents hallucinate findings. [[feedback_verify_agent_poc]]

### Example 2: a past program — 8/8 REJECTED (2026-04)
**What happened**: 8 findings submitted without proper triage gate. All rejected — mix of informational, duplicate, and out-of-scope.
**Root cause**: Skipped `/triage` command, inline-triaged instead. Confirmation bias.
**Lesson**: MANDATORY triage gate exists for a reason. Never inline-triage. [[feedback_mandatory_triage]]

### Example 3: CORS on Intigriti Programs (2026-05)
**What happened**: Multiple CORS reflection findings reported across AS Watson, target-corp, and other programs. ALL rejected.
**Root cause**: Intigriti programs uniformly consider CORS as not-a-vulnerability or require evil.com reflection (not subdomain).
**Lesson**: ALL CORS findings are FP on Intigriti. Stop hunting/reporting CORS entirely. [[feedback_cors_arbitrary_origin_reject]]

### Example 4: SharePoint /_layouts/15/download.aspx SSRF (community research reference)
**What happened**: SharePoint returned 500 with attacker URL in error message. Initial scan flagged as SSRF.
**Reality**: 38 Collaborator-tagged payloads across 12+ URL-accepting parameters yielded ZERO DNS/HTTP interactions. The "echo" was client-side error-string formatting.
**Lesson**: OOB-Or-It-Didn't-Happen. Error message echo ≠ SSRF. Always require Collaborator/interactsh callback.

## Platform-Specific Retraction

### Intigriti
- Comment on the report with retraction notice
- Set finding to "Not applicable" if option available
- No penalty for self-retraction within 48h

### HackerOne
- Comment "I'd like to retract this report" — triager will close as N/A (self-requested)
- Affects "Signal" metric less than triager-initiated close

### Bugcrowd
- Comment with retraction request
- Triager closes as "Not Applicable" — minimal reputation impact

---

## Operator Notes (Battle-Tested)

- **Retract fast**: Every hour between submission and retraction increases the chance the triager already spent time on it. Fast retraction = professional courtesy
- **Never delete evidence**: Move to `_archive/`, don't delete. Retracted findings are learning opportunities
- **Track retraction rate**: If >20% of submissions are retracted, the problem is upstream (weak triage gate, not enough browser verification)
- **Agent findings need 100% manual verify**: Never trust agent-generated PoC without curl/Playwright reproduction (target-corp Korea lesson)
- **Statistical significance**: Timing-based findings (blind SQLi, blind SSRF) need n≥5 consistent measurements, not n=1

## Related Skills & Chains

| When | Go to |
|------|-------|
| Doubt a finding pre-submission | `/triage` — run full triage gate instead of retracting |
| Finding rejected by triager | `triage-reference` — analyze why, prevent recurrence |
| Duplicate suspected | `duplicate-detection` — check before submitting |
| Need to downgrade severity | `auto-chain-discovery` — can it chain to something higher? |
| Agent generated the finding | ALWAYS manual verify first — `feedback_verify_agent_poc` |
