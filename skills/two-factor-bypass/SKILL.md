---
name: two-factor-bypass
description: "Test 2FA/MFA flows for step-skipping, unthrottled OTP brute force, response manipulation, code reuse, and disable-2FA IDOR."
---

# 2FA / MFA Bypass Testing

## Crown Jewel Targets

- **Admin/Staff login portals with required 2FA** — bypassing 2FA elevates standard credentials directly into administrative access.
- **Customer financial or profile settings** — bypassing step-up authentication on sensitive operations (funds transfer, password change, email change).
- **OAuth/SSO two-factor verification steps** — skipping 2FA callbacks during third-party authorization.

## Methodology

### 1. Map the 2FA flow
- Log in with valid credentials to reach the OTP/2FA verification step.
- Capture via proxy:
  - Where the OTP code is sent (SMS, email, TOTP authenticator).
  - The verification endpoint (URL, HTTP method, headers, request body structure).
  - The success vs. failure response shape (HTTP status, JSON body, `Set-Cookie`, redirect target).

### 2. Bypass Playbook

- **Step skipping**: After the password step (pre-2FA session cookie), directly request the post-login dashboard (`/dashboard`, `/account`) or the post-login redirect URL. Check if the pre-2FA session is already accepted as fully authenticated.
- **Unthrottled OTP brute force**: Send 50+ guesses of 4-6 digit numeric codes. Check for the absence of `429 Too Many Requests`, account lockout, or progressive delays.
- **Code reuse / No expiry**: Submit an already-used OTP code or a code after its validity window (e.g. >10 minutes).
- **OTP leakage in response**: Check previous API responses (e.g. `/api/auth/send-otp`, `/api/auth/login`) or HTML source to verify if the server accidentally returned the OTP in the JSON response or hidden input field.
- **Null / Default code acceptance**: Submit empty string `""`, `null`, `000000`, `123456`, or delete the code parameter entirely from the request.
- **Response manipulation**: Intercept the failed verification response (`401 Unauthorized` or `{"success":false}`) and modify it to `200 OK` / `{"success":true,"status":"verified"}` to see if the client-side app upgrades the session.
- **2FA Disable / Reset IDOR**: Test endpoints like `POST /api/user/{id}/2fa/disable` using another user's identifier without re-authenticating the second factor.
- **Remember-Device / Backup code abuse**: Test if the "Remember this device" cookie is predictable, forged, or valid across different accounts.

### 3. Verification & Evidence Requirements

Proof requires accessing a 2FA-gated resource or authenticated session **without providing the valid second factor**:
- Control: Failed or required 2FA request returning 401/403 or 2FA prompt.
- Bypass: Request reaching the protected account area or setting changes with HTTP 200 and authenticated session data.
- Status code changes alone (e.g. 200 without session upgrade) are NOT findings.

### 4. False Positives
- Bypasses that redirect back to the 2FA prompt or login page.
- Silent 200 responses where the action was actually rejected server-side.
- Testing with your own device cookie that previously passed valid 2FA.

