---
name: race-condition-testing
description: "Race condition hunting on payment/reward/credit flows — single-packet HTTP/2 attack, last-byte sync, coupon/gift card double-spend, referral abuse, partial construction races, timestamp token collision. Use when testing e-commerce checkout, wallet/credit systems, referral programs, or any financial state-changing endpoint."
---

# Race Condition on Payment / Reward Flows

## Crown Jewel Targets

- **Gift card / promo code redemption** — fire 20 parallel redeem requests → balance credited N times (Critical, proven on Starbucks)
- **Referral bonus claiming** — race referral credit endpoint → unlimited referral rewards
- **Wallet-to-wallet transfers** — double-spend via simultaneous withdrawal requests exceeding balance
- **Subscription/free trial activation** — race trial start endpoint → multiple trial periods stacked
- **Voting/upvote systems** with rate limits — like/unlike race → extra engagement credits
- **Coupon application at checkout** — apply same single-use coupon to multiple carts simultaneously
- **Password reset token generation** — simultaneous resets generate identical tokens (timestamp collision) → ATO

## Attack Surface Signals

- **URL patterns**: `/api/redeem`, `/api/transfer`, `/api/apply-coupon`, `/api/claim-reward`, `/api/referral/claim`, `/checkout/apply-discount`
- **Request patterns**: POST with `code=`, `amount=`, `coupon_id=`, `reward_id=` — any financial state change
- **Response patterns**: `"balance":`, `"credits":`, `"points":`, no idempotency key (`X-Idempotency-Key`, `Idempotency-Key` header absent)
- **Tech stack signals**: No database-level locking (optimistic concurrency), Redis-based counters, eventual consistency architectures
- **Positive indicators**: Endpoint responds differently to rapid concurrent requests (some 200, some 400/409), balance changes are not atomic

## Methodology — predict, probe, prove

Limit-overrun races (redeem a code twice) are the obvious case, but most real race conditions are **hidden multi-step sequences**: a single request that the server internally splits into several sub-operations against shared state. Work them in three stages rather than firing parallel requests at random endpoints.

**1. Predict potential collisions.** Ask which endpoints touch state that other requests also read or write, and where that state is security-relevant — balances, quotas, tokens, role assignments, uniqueness constraints. Anything the server must read-then-write is a candidate; the window is between the read and the write.

**2. Probe for clues.** Send a burst and compare against a sequential baseline. You are not looking for the exploit yet — you are looking for *any* deviation: a different status code, a changed response ordering, a timing outlier, a message that only appears under concurrency, a record that ends up in a state the UI cannot produce. A deviation means there is a window, even if this particular burst did not profit from it.

**3. Prove the concept.** Work out which sub-operation you landed between, then shape the attack to exploit that specific window. Remove noise, confirm on a fresh account, and reproduce it more than once — a single lucky hit is not a finding.

Rate limits are worth noting here: hitting one is not necessarily a wall. PortSwigger's own framing is that rate and resource limits can be *abused* to widen a race window, because the server delays work while holding state.

## Multi-endpoint races and window alignment

The race does not have to be one endpoint against itself. A classic case is adding an item to a basket while the payment request is in flight — the two hit different endpoints but share the same order state.

The difficulty is **alignment**: the requests must arrive within the same window, and network jitter alone will usually spoil it. Two techniques matter:

- **Connection warming** — send one or more inconsequential requests (a static asset, a GET on an unrelated page) down the same connection first. This gets TLS and TCP setup out of the way so the real requests are not skewed by first-request overhead. Without warming, results are frequently false negatives.
- **Single-packet attack (HTTP/2)** — put the tail of every request into a single TCP packet so the server receives them simultaneously, eliminating network jitter entirely. This is the reliable primitive on HTTP/2; the last-byte sync technique is the HTTP/1.1 equivalent.

**Session-based locking** can defeat all of this: some frameworks (notably PHP's session handler) serialise requests carrying the same session cookie, so your parallel requests are processed one after another. If a race looks impossible, test whether separate sessions per request restores the window — that alone has turned many "not vulnerable" verdicts around.

## Detection
```bash
# Identify race-prone endpoints:
# - Gift card redemption
# - Coupon/promo code application
# - Referral bonus claiming
# - Free trial activation
# - Reward point spending
# - Like/vote/upvote actions with rate limits

# Use Burp Intruder to send parallel requests:
# Set attack type: Pitchfork, 20 threads, same request
```

**Positive indicators:**
- Endpoint changes financial balance (credits, coins, points, money)
- No idempotency key in request
- Server responds differently to concurrent requests (one 200, others 400)
- Multiple executions possible before state update completes

## Exploitation
1. Identify state-changing money endpoint (redeem, transfer, withdraw)
2. Capture request in Burp
3. Send 20-50 parallel requests simultaneously using:
   - Burp Intruder (Last-Byte sync technique)
   - `turbo-intruder` Burp plugin (most reliable)
   - Python asyncio / threading
4. Check if balance reflects multiple credits or if action executed multiple times
5. Confirm with fresh account

## PoC Template
```python
import asyncio, aiohttp

async def exploit(session, url, data):
    async with session.post(url, json=data) as r:
        return await r.json()

async def main():
    async with aiohttp.ClientSession(headers={"Cookie": "session=VICTIM_SESSION"}) as s:
        # Fire 20 simultaneous requests
        tasks = [exploit(s, "TARGET/redeem", {"code": "PROMO123"}) for _ in range(20)]
        results = await asyncio.gather(*tasks)
        print(results)

asyncio.run(main())
```

## Important Notes
- **Starbucks**: Multiple concurrent calls to redeem gift card → balance added N times
- **Last-Byte technique**: Prepare all requests, hold last byte, release simultaneously
- Database-level fix: `SELECT FOR UPDATE` or atomic transactions — check if implemented
- Business logic race: like → unlike → like rapidly = extra credit without spending

## Reference Writeups
- [Hacking Starbucks for unlimited money](https://sakurity.com/blog/2015/05/21/starbucks.html) by Egor Homakov
- [Race conditions on Facebook, DigitalOcean and others](http://josipfranjkovic.blogspot.hk/2015/04/race-conditions-on-facebook.html) by Josip Franjkovic
- [Race Conditions in Popular reports feature in HackerOne](https://hackerone.com/reports/146845) by Fabio Pires
- [Manipulation of ETH balance (blockchain race condition)](https://www.vicompany.nl/magazine/from-christmas-present-in-the-blockchain-to-massive-bug-bounty)

## PortSwigger Academy — Advanced Techniques

- **Single-packet attack (HTTP/2)**: Send 20-30 requests in ONE TCP packet — eliminates network jitter. Use `engine=Engine.BURP2`, `concurrentConnections=1`, gate mechanism
- **HTTP/1.1 last-byte synchronization**: Send all requests with final byte withheld, release simultaneously
- **Connection warming**: Prepend harmless GET to identify connection-based vs server-based latency
- **Single-endpoint email race (ATO)**: Two parallel `POST /change-email` — one attacker, one victim email — confirmation email misdirection
- **Partial construction race (null token)**: Window between record creation and token storage — `token[]=` (PHP empty array) matches NULL
- **Session-based locking bypass**: PHP serializes per-session — use DIFFERENT session tokens per parallel request
- **Timestamp token collision**: Simultaneous password resets generate identical tokens if based on timestamps

## Operator Notes (Battle-Tested)

1. **Single-packet HTTP/2 attack is the gold standard**: Send 20-30 requests in ONE TCP packet using Turbo Intruder with `engine=Engine.BURP2` and `concurrentConnections=1` with gate mechanism. This eliminates network jitter and is far more reliable than threading.
2. **Connection warming is mandatory**: Prepend a harmless GET request to each connection before the race payload. This distinguishes connection-setup latency from server processing time and ensures all requests arrive truly simultaneously.
3. **Use different session tokens per parallel request**: PHP serializes requests per session (session locking). If you send 20 requests with the same PHPSESSID, they execute sequentially. Use 20 different sessions to bypass this.
4. **Check balance BEFORE and AFTER**: Document the initial balance, fire the race, then check the final balance. Triagers need clear "before: 100 credits, after: 2000 credits" proof, not just "I sent 20 requests."
5. **Partial construction race is subtle but powerful**: The window between database record creation and token/secret storage — during this window, `token IS NULL`. Send `token[]=` (PHP empty array) which matches NULL via loose comparison. Requires precise timing.

## Related Skills & Chains

| When | Go to |
|------|-------|
| Race condition on non-financial business logic | `business-logic-testing` |
| Rate limiting blocks parallel requests | `rate-limit-bypass` |
| Need CSRF to trigger race from victim's browser | `csrf-testing` |
| Race on API endpoints, need to map all params | `api-security-testing` |
| Race on password reset tokens | `auth-bypass-testing` |
| Timestamp collision on session tokens | `jwt-testing` |
