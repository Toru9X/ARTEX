---
name: business-logic-testing
description: "Business logic flaw hunting — price and quantity manipulation, currency confusion, coupon and refund abuse, payment step skipping, state-machine and workflow violations, tier/seat limit bypass, multi-tenancy leaks. Use when testing checkout, subscription, wallet, or any multi-step workflow where the UI enforces constraints the API does not."
---

# Business Logic Vulnerability Testing

## Crown Jewel Targets

- **E-commerce checkout flows** -- price manipulation, negative quantities, currency confusion = direct financial loss = Critical bounty. Map ENTIRE flow: cart -> checkout -> payment -> confirmation
- **Subscription/SaaS tier systems** -- free trial -> premium manipulation, feature flag bypass via API, seat limit bypass. UI hides premium features but API allows access
- **Payment/fintech platforms** -- double-spend via race condition on balance operations, concurrent transfer/withdrawal exceeding balance, refund-to-different-method abuse
- **Coupon/discount engines** -- race condition on one-time coupon redemption, coupon stacking past 100% discount, expired coupon via direct API call
- **Multi-tenant SaaS** -- cross-tenant data access via shared resource IDs, API keys scoped to tenant A work for tenant B
- **KYC/verification workflows** -- change identity details after verification completes, OAuth login bypasses email verification
- **Referral/rewards systems** -- self-referral loops, automated bonus extraction, points multiplication via race condition

## Attack Surface Signals

- **URL patterns**: `/checkout`, `/payment`, `/api/cart`, `/api/order`, `/api/transfer`, `/api/redeem`, `/api/coupon`, `/api/subscription`, `/api/upgrade`
- **Parameters**: `amount`, `quantity`, `price`, `currency`, `coupon_code`, `discount`, `plan`, `tier`, `role`, `refund`
- **JS indicators**: `cartTotal`, `discountAmount`, `paymentIntent`, `subscriptionTier`, `featureFlag`, `trialExpiry`
- **State signals**: multi-step forms with hidden fields, session-based wizard flows, status fields in API responses (`pending`, `paid`, `shipped`)

> Elite hunters find their highest-bounty bugs through business logic flaws, not technical scanners. This pattern covers systematic business logic testing.

## Why Business Logic = High Bounty

- Scanners can't find these → low duplicate rate (<10%)
- Impact is always HIGH-CRITICAL (money, data, access)
- Programs value these most (shows understanding of their product)
- Cannot be fixed by WAF/security headers → real code fix needed

## Business Logic Vulnerability Taxonomy

### 1. Payment/Financial Logic

**Price Manipulation:**
- Change price in client-side request (cart total, individual item price)
- Currency conversion exploit: buy in cheap currency, refund in expensive currency
- Negative quantity → negative total → credit instead of charge
- Apply discount code after payment calculation but before charge
- Modify shipping cost to negative value

**Coupon/Discount Abuse:**
- Apply same coupon multiple times (race condition on redemption)
- Transfer coupon between accounts
- Apply expired coupon via direct API call (client validates, server doesn't)
- Stack multiple exclusive coupons via race condition
- Coupon for product A applied to product B

**Refund/Chargeback:**
- Refund item but keep digital access
- Partial refund > original payment
- Refund to different payment method than original
- Cancel subscription but retain access until next billing check
- Double refund via concurrent requests

**Test approach:**
1. Map the ENTIRE payment flow (add to cart → checkout → payment → confirmation)
2. Intercept EVERY request in the flow
3. At each step: modify amounts, quantities, IDs, currency
4. Test step-skipping: jump from step 1 to step 4
5. Test race conditions on payment + cancellation simultaneously

### 2. State Machine Violations

**Concept:** Applications have implicit state machines (order: pending→paid→shipped→delivered). Forcing invalid transitions = logic bugs.

**Common patterns:**
- Skip verification step: go from "email entered" to "account verified" without clicking link
- Reuse one-time tokens: password reset token used multiple times
- Reverse state: change "shipped" order back to "pending" → get refund + keep item
- Access features of higher state: access "premium" features before payment completes
- Race between state transitions: two concurrent requests both succeed when only one should

**Test approach:**
1. Map all states an object can be in (order, user, subscription, document)
2. For each state transition, test:
   - Can I skip states? (pending → delivered, skip payment)
   - Can I reverse states? (delivered → pending)
   - Can I access the wrong state? (unpaid → premium features)
   - Can two transitions happen simultaneously? (race condition)

### 3. Access Control Logic (Beyond IDOR)

**Role escalation via business flow:**
- Register as user → modify role parameter during onboarding
- Free trial → premium: manipulate subscription tier in API
- Guest → authenticated: access auth-only features via direct URL
- User → admin: admin endpoints with same auth token

**Multi-tenancy violations:**
- Access other tenant's data via shared resource IDs
- Invite user from tenant A to tenant B → cross-tenant data access
- Shared resources (reports, dashboards) leak across tenants
- API keys scoped to tenant A work for tenant B

**Feature flag bypass:**
- Disabled feature accessible via direct API call
- A/B test variant accessible by manipulating cookie/header
- Beta features in production behind simple boolean check

### 4. Workflow/Process Bypass

**Email verification bypass:**
- Change email after verification → new email inherits verified status
- Register with attacker email → change to victim email → skip verification
- OAuth login bypasses email verification entirely

**KYC/Identity verification bypass:**
- Submit verification → access features → change identity details
- Upload someone else's documents → access their verified status
- Verification status cached → modify details after cache set

**Approval workflow bypass:**
- Submit content for approval → edit after approval → unapproved content published
- Approve own request by modifying approver_id
- Delete approval requirement by removing field from API request

### 5. Rate/Limit Abuse

**Not just "no rate limit" — PROVE the abuse:**
- Referral bonus: create multiple accounts → refer each other → extract money
- Free trial abuse: register → use → delete → re-register (IP/email/device tracking?)
- API quota bypass: exceed quota by sending concurrent requests before counter updates
- Vote/like manipulation: automate votes to manipulate rankings
- Points/rewards gaming: find actions that give more points than intended

### 6. Data Integrity Violations

**Race conditions on shared resources:**
- Two users edit same document simultaneously → data corruption
- Concurrent balance updates: withdraw + transfer at same time → negative balance
- Inventory: buy last item twice via race condition → oversell

**Calculation errors:**
- Floating point: $0.001 × 1000000 = rounding error accumulation
- Tax calculation: change shipping address after tax calculated
- Bulk discount: add items to reach discount tier → remove items → keep discount

## Encryption oracles and parser discrepancies

Two logic flaws that look like crypto or parsing bugs but are really trust failures, and both are easy to walk past.

**Encryption oracle** — the app encrypts attacker-controlled data with a key it also uses for something security-relevant, and hands the ciphertext back. A "remember me" cookie built from `username:timestamp` encrypted with the same key that protects a privileged token is the classic shape. Look for any feature that returns ciphertext derived from your input (cookies, share links, unsubscribe tokens, tracking parameters), then check whether that ciphertext is accepted anywhere else. If an error message reflects the *decrypted* value, you also have a decryption oracle. Padding-oracle behaviour (different responses for invalid padding vs invalid content) turns the same primitive into arbitrary decryption.

**Email address parser discrepancies** — registration flows commonly grant privileges based on the domain part of an email (`@company.com` gets employee access). The flaw arises when the component that *validates* the address parses it differently from the component that *sends* to it. Encoded forms, quoted local parts, and unicode all create the split:

```
attacker@evil.com(@company.com)                comment syntax - parsers disagree on the real domain
"attacker@evil.com"@company.com                quoted local part
=?utf-8?q?attacker=40evil.com?=@company.com    encoded-word in the local part
attacker@company.com@evil.com                  multiple @ - which one is the separator?
```

Test where the confirmation email actually lands versus which domain the app decided you belong to. If the mail arrives in your inbox but the app granted you the internal domain's privileges, that is a full authorization bypass, not an email quirk.

## Testing Methodology

### Step 1: Understand the Business
Before testing, answer:
- How does this app make money?
- What are the high-value actions? (payment, data access, account creation)
- What are the trust boundaries? (user→admin, free→paid, unverified→verified)
- What objects have state? (orders, subscriptions, documents, users)

### Step 2: Map Critical Flows
For each high-value flow:
1. Walk through as normal user, capture all requests
2. Identify every decision point (if/else in the flow)
3. Identify every state transition
4. Identify every trust boundary crossed

### Step 3: Attack Each Flow
For each step in each flow:
- **Skip it** — can I jump to the next step?
- **Repeat it** — can I do this step twice?
- **Reverse it** — can I go back after this step?
- **Modify it** — can I change parameters mid-flow?
- **Race it** — can I do two things simultaneously?
- **Substitute it** — can I use a different object/user?

### Step 4: Test Cross-Flow Interactions
- Action in Flow A affects Flow B unexpectedly
- Cancelling Flow A mid-way leaves Flow B in inconsistent state
- Sharing objects between flows creates race conditions

## Quick Checklist by App Type

### E-commerce
- [ ] Modify cart total/item price in request
- [ ] Apply coupon multiple times (race condition)
- [ ] Negative quantity/amount
- [ ] Skip payment step → access order confirmation
- [ ] Refund more than paid
- [ ] Change currency mid-transaction
- [ ] Buy digital item → refund → keep access

### SaaS/Subscription
- [ ] Free trial → premium tier manipulation
- [ ] Cancel subscription → retain access
- [ ] Downgrade plan → keep features
- [ ] Multiple free trials (re-registration)
- [ ] Invite more users than plan allows
- [ ] Access admin features with user token
- [ ] Feature flag bypass via API

### Banking/Fintech
- [ ] Transfer to self between accounts → fee exploit
- [ ] Race condition on balance operations
- [ ] Negative transfer amount
- [ ] Currency conversion rounding exploitation
- [ ] Concurrent withdrawal exceeding balance
- [ ] Modify beneficiary after approval

### Social/Content Platform
- [ ] Vote/like manipulation
- [ ] Content approval bypass
- [ ] Report abuse → hide competitor content
- [ ] Profile verification bypass
- [ ] Private content accessible via direct URL
- [ ] Referral bonus gaming

## Severity Guide

| Finding | Typical Severity | Why |
|---------|-----------------|-----|
| Price manipulation (proven financial loss) | CRITICAL | Direct financial impact |
| Payment bypass | CRITICAL | Revenue loss |
| State machine → unauthorized access | HIGH-CRITICAL | Depends on what's accessed |
| Multi-tenancy data leak | HIGH-CRITICAL | Data breach |
| Free trial abuse (proven automation) | MEDIUM-HIGH | Financial impact |
| Feature flag bypass | MEDIUM | Unauthorized feature access |
| Vote manipulation | LOW-MEDIUM | Integrity impact |

## Operator Notes (Battle-Tested)

1. **"Follow the money" ()** -- billing, credits, wallet, payment, refund endpoints are the highest-ROI targets. Map the entire financial flow first before testing anything else. Price manipulation with proven financial loss = Critical.
2. **Race conditions need Turbo Intruder or single-packet attack** -- `Promise.all()` in Playwright for browser-based races, Turbo Intruder for server-side. Gate-based parallel requests: queue 20 identical requests, fire simultaneously. One success out of 20 = confirmed.
3. **Two accounts are mandatory for access control logic** -- free vs paid, user vs admin, tenant A vs tenant B. Create both accounts BEFORE testing (record both via insert_assets/record_fact so they aren't lost between workers). Single-account testing of BAC/IDOR = rejected.
4. **Client-side validation gaps are everywhere** -- frontend enforces min=1, max=99 for quantity; Burp intercept and send quantity=-1 or 999999. If backend accepts it without validation = business logic flaw. Compare what UI shows vs what raw API accepts.
5. **Scanners CANNOT find business logic bugs** -- this is why duplicate risk is < 10%. Understanding the business model (how the app makes money, what the trust boundaries are) is the prerequisite. Spend 30 minutes understanding the product before firing any payloads.

## Related Skills & Chains

| When | Go to |
|------|-------|
| Need payload reference for all logic attacks | `references/business-logic-taxonomy.md` |
| Race condition on financial operations | `race-condition-testing` |
| IDOR/BAC across user roles | `access-control-testing` |
| API endpoint testing for logic flaws | `api-security-testing` |
| Hidden params for mass assignment | `hidden-param-discovery` |

## Reference files

Read these when the situation calls for the depth they carry — they are not loaded automatically.

- `references/business-logic-taxonomy.md` — **business logic taxonomy** — related_patterns: ["business-logic-testing", "race-condition-money", "access-control-testing", "hidden-param-d
