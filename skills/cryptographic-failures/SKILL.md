---
name: cryptographic-failures
description: "Testing OWASP A02 cryptographic failures from the outside: ECB mode detected by ciphertext block repetition, bit-flipping against unauthenticated CBC, padding oracles, predictable IDs from timestamp or sequential seeds, weak password hashes exposed in a dump, and tokens that are encoded rather than signed. Use when the application hands the client an opaque blob it later trusts — a session cookie, a password-reset token, an unsubscribe link, a license key, an encrypted id in a URL — or when a response time or error message differs between a malformed and a well-formed ciphertext."
---

# Cryptographic Failures (OWASP A02)

The whole class starts from one question: **the server handed me bytes it will later trust — can I change them without knowing a key?**

## Crown Jewel Targets

- **Bit-flipping on unauthenticated CBC** — flip a byte in block N to control the plaintext of block N+1; turns `user=guest` into `user=admin` with no key
- **Padding oracle** — a distinguishable response for bad padding decrypts the whole ciphertext and lets you forge new ones (CBC, and PKCS#1 v1.5 on RSA)
- **ECB block shuffling** — identical plaintext blocks give identical ciphertext blocks; cut and paste blocks between two of your own tokens to build a token you were never issued
- **Predictable token generation** — reset tokens seeded from time or a counter, so you can generate another user's
- **Encoded, not signed** — base64/hex that decodes to readable JSON is not protection; edit and re-encode

## Attack Surface Signals

- A cookie or parameter that is base64 and whose length is an exact multiple of 8 or 16 — a block cipher, so block attacks are on the table
- Two accounts whose tokens share a long identical prefix or suffix — ECB, or a shared static IV
- The same plaintext always producing the same ciphertext — no IV, or a fixed one
- Error text or response time that differs between "cannot decrypt" and "decrypted but invalid"
- Reset links valid for a long window, or tokens that are short enough to collide
- `alg` confusion on a JWT — covered by jwt-testing, start there if the blob is a JWT

## Method

1. **Classify the blob first.** Decode base64/hex. Readable JSON → not encrypted, just encoded; edit it. High entropy and a length that is a multiple of 16 → block cipher.
2. **Find the block size.** Register accounts with usernames of growing length and watch where the ciphertext length jumps. The jump interval is the block size.
3. **Detect ECB.** Submit a long run of one repeated character. If repeated 16-byte ciphertext blocks appear, it is ECB. Detect with `jq`/`python` over the hex, not by eye.
4. **Probe for an oracle.** Corrupt the last byte of the second-to-last block and compare status, body length and timing against the untouched request. A reliable difference is an oracle.
5. **Check predictability.** Request several reset tokens in quick succession and diff them. Monotonic, time-correlated or short-shared-prefix values are predictable.

## Evidence That Survives Triage

A claim here is only accepted with **a token you forged that the server accepted**. Not "the cookie looks like ECB" — show the request/response where your constructed value authenticated as a different principal, plus the two original tokens you built it from. For a padding oracle, show the recovered plaintext of a ciphertext you did not create.

Timing differences need a distribution, not one sample: at least 30 requests each way with the medians, or triage will call it noise.

## Common False Positives

- A long random string that is simply an opaque database key — changing it gives 404, not a vulnerability
- "Weak" TLS ciphers reported by a scanner with no exploit path — report with `tlsx` output only as informational
- A JWT with `alg: HS256` is not broken by itself; see jwt-testing

See [[jwt-testing]], [[session-crlf-injection]], [[information-disclosure]].
