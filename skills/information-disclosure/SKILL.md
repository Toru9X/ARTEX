---
name: information-disclosure
description: "Hunt unintentionally leaked data and technical detail — robots.txt and sitemap entries, directory listings, developer comments, verbose error messages, debug endpoints and debug pages, user account pages, backup and temp files exposing source, insecure configuration headers, and exposed .git history. Covers how to engineer informative responses on purpose and, critically, how to judge whether a leak is reportable or just noise. Use when auditing any target for leaked data, when an error message looks unusually chatty, or before writing up a disclosure finding that might only be informational."
---

# Information Disclosure

Information disclosure is the most commonly found and the most commonly over-reported bug class. Both halves matter here: it is genuinely everywhere, and most instances of it are worth nothing on their own.

The discipline is therefore two-sided. **Hunt it broadly** — a leaked internal hostname or framework version is often the thread that leads to the real finding, and missing it costs you the chain. **Report it narrowly** — a version banner, a robots.txt, or a stack trace with no exploitable consequence is noise, and submitting it burns program goodwill.

Treat every leak first as *reconnaissance for another bug*, and only second as a finding in its own right.

## Crown Jewel Targets

- **Exposed `.git` directories** — full source history including deleted secrets; the single highest-value disclosure on this list
- **Backup and temp files of live code** (`.bak`, `.old`, `~`, `.swp`, `.zip` of the webroot) — server-side source that reveals auth logic and hardcoded credentials
- **Debug endpoints left on in production** — Spring Actuator `/env` and `/heapdump`, Django `DEBUG=True`, Laravel Ignition, `phpinfo()`. These leak credentials and session material, not just version strings
- **Verbose stack traces on database or template errors** — name the engine and version, and frequently the query, which is the fastest route into SQLi or SSTI
- **User account and profile endpoints** — leaking other users' fields via an over-broad API response is where disclosure and IDOR meet
- **CI/CD and build artifacts served from the webroot** — `.env`, `docker-compose.yml`, `appsettings.Development.json`, source maps
- **Behavioural differences that enable enumeration** — distinct responses for valid vs invalid usernames turn a non-finding into account enumeration

## Attack Surface Signals

- Response headers naming exact product versions (`Server`, `X-Powered-By`, `X-AspNet-Version`)
- Any 500 that returns more than a generic message; any 4xx whose body varies with input
- `Content-Type: text/html` on what should be an API error — often means an unhandled framework exception
- Directory paths ending in `/` returning a file index rather than 403/404
- HTML comments in production markup, especially near auth or admin functionality
- `.js.map` served alongside bundles; `/.git/HEAD` returning `ref: refs/heads/...`
- Response timing or length differences between valid and invalid identifiers

## How to test

Do not develop tunnel vision. Sensitive data leaks in places unrelated to whatever you are currently testing, so keep a running note of anything that looks like internal detail even when it is not the bug you are chasing.

### Fuzzing for informative responses
Submit unexpected types and malformed values into every interesting parameter and read the *differences*, not just the content — status code, response time, length, and any keyword appearing only in some responses.

```bash
# Burp Intruder is the natural tool here; grep-match rules make the differences pop
# Match on: error, exception, invalid, SELECT, SQL, stack, Traceback, Warning, at java.
# Grep-extract to pull the varying fragment out of each response for side-by-side comparison
```

Useful shapes to send: a string where an integer is expected, an array where a scalar is expected, a null, an oversized value, a value with a type-confusing prefix. The goal is to make the application attempt an invalid operation on real data — that is what produces the chatty error.

### Burp engagement tools
- **Search** — regex across a selected item or the whole site map for keywords of interest
- **Find comments** — extracts developer comments in bulk, with a jump back to the request that carried them
- **Discover content** — finds files and directories not linked from visible content, which is where backups and debug pages live
- **Logger++** (BApp) — filter and highlight across every request Burp has seen; good for catching a leak that appeared once, hours ago

### Engineering informative responses on purpose
Rather than waiting for an error, force one. Make the app perform an invalid action against a *specific item of data* — reference a record you know exists but in the wrong type or state — so the resulting trace or debug output describes real internal structure rather than generic input validation.

## Common sources

| Source | Where to look | What it is worth |
|---|---|---|
| **Crawler files** | `/robots.txt`, `/sitemap.xml` | Names directories the site wants hidden. Not a finding — a map |
| **Directory listings** | Any path without an index page | Not a vuln alone; becomes one when it exposes resources that lack access control |
| **Developer comments** | HTML/JS markup in production | Occasionally names hidden directories or explains application logic |
| **Error messages** | Any 500, malformed input, type confusion | Engine and version, sometimes the query. Prime lead for SQLi/SSTI/deserialization |
| **Debugging data** | Debug pages, verbose logs, custom error handlers | Session variable values, backend hostnames and credentials, server file paths, client-side encryption keys — this is the tier that is genuinely reportable |
| **User account pages** | Profile, settings, order history endpoints | Over-broad responses leaking other users' data; overlaps with IDOR |
| **Backup files** | `~`, `.bak`, `.old`, `.txt` appended to known scripts; archives in the webroot | Server-side source, and with it hardcoded credentials |
| **Insecure configuration** | Non-standard headers the app trusts, `TRACE`, permissive debug toggles | Config disclosure that reveals a trusted-header auth bypass is a real finding |
| **Version control** | `/.git`, `/.svn` | Full source and history, including secrets removed in later commits |

```bash
# Fast sweep for the high-value ones
curl -s https://target/robots.txt https://target/sitemap.xml
curl -sI https://target/.git/HEAD                     # 200 + "ref: refs/heads/" = jackpot
for e in .bak .old '~' .swp .zip .tar.gz; do curl -sI "https://target/app.php$e"; done
# Then reconstruct: git-dumper for exposed .git, and see `source-map-exposure` for .js.map
```

## Severity — the part that decides whether you submit

PortSwigger's own guidance is blunt about this, and it matches what triagers reward: **the focus is the impact and exploitability of the leaked information, not the fact that a leak exists.** Knowing a framework version is worthless if the version is patched, and significant if it is not.

Work it as a decision:

1. **What exactly leaked?** Credentials, keys, PII, and session material are inherently valuable. Paths, versions, and structure are not.
2. **Can I use it right now?** If yes, the finding is the *use*, not the leak — report the resulting access, with the disclosure as the first step of the chain.
3. **Does it unlock a known vulnerability?** A version string plus a matching unpatched CVE is a finding. A version string alone is not.
4. **If neither — is it still self-evidently sensitive?** Real customer PII or live credentials are reportable on disclosure alone. Internal hostnames are not.

**Reportable:**
- Exposed `.git` or backup source containing credentials, keys, or auth logic you can demonstrate using
- Debug output containing credentials, session material, or client-side encryption keys
- Any leak of real user PII or financial data
- Configuration disclosure that directly enables a bypass (trusted-header auth, for example)
- Version disclosure tied to a specific unpatched vulnerability you can show applies

**Not reportable on its own** (log it, chain it, but do not submit it):
- `robots.txt`, `sitemap.xml`, directory listings with nothing sensitive behind them
- Server banners and framework versions that are current
- Stack traces revealing only paths and class names
- Developer comments with no actionable content
- Source maps that reconstruct code containing no secrets — see `source-map-exposure`
- Public client-side configuration (Cognito pool IDs, Sentry DSNs, Firebase web API keys) — these are *designed* to be public, see `js-bundle-secrets`
- GraphQL introspection, OIDC discovery documents, Prometheus metrics — schema and telemetry are not data

That last group is where most rejected reports in this project came from. When in doubt, the question to answer is not "is this information leaking?" but "what can I do with it that I could not do before?"

## Triage Checklist

- [ ] Leaked content actually retrieved and saved, not just inferred from a status code
- [ ] Classified: secret / PII / technical detail — and technical detail is treated as a lead, not a finding
- [ ] Exploitation attempted with the leaked material (credentials used, key used, path fetched)
- [ ] For version disclosure: specific unpatched CVE identified and its applicability shown
- [ ] For `.git`/backups: source actually reconstructed and the sensitive content quoted
- [ ] For debug pages: the specific sensitive field named, not just "debug mode enabled"
- [ ] Chain checked — run `auto-chain-discovery` before deciding this is only informational
- [ ] Scope confirmed and the host is genuinely in scope
- [ ] If nothing exploitable came out of it, the honest verdict is informational, and it is not submitted

## Operator Notes (Battle-Tested)

1. **Hunt wide, report narrow.** Collect every leak you see, because leaks are how you find the next bug — but pass them through the severity decision above before anything reaches a submit queue.
2. **Force errors rather than waiting for them.** Type-confusing a parameter against a record you know exists produces far more informative traces than fuzzing garbage into an endpoint.
3. **Check `/.git/HEAD` on every host, always.** It is one request, and a hit is worth more than a week of parameter fuzzing.
4. **Debug data outranks error messages.** A stack trace names the framework; a debug page hands you session variables, backend credentials, and encryption keys. Prioritise finding the debug surface.
5. **Behavioural differences count as disclosure.** Distinct responses for valid and invalid usernames are an enumeration primitive — pair it with `rate-limit-bypass` and the result may be an actual account compromise rather than an informational note.
6. **"It's in the JS bundle" is not automatically a secret.** Client-side config is public by design. The finding starts when you make a privileged call with what you found.

## Related Skills & Chains

| When | Go to |
|------|-------|
| Secrets found in JS bundles, need to prove exploitability | `js-bundle-secrets` |
| `.js.map` exposed, judging whether it matters | `source-map-exposure` |
| ASP.NET / IIS verbose error pages specifically | `aspnet-verbose-errors` |
| Error message hints at a database engine | `sql-injection-testing` |
| Error message hints at a template engine | `ssti-testing` |
| Hidden files on IIS, wordlists returning nothing | `iis-shortname-exploitation` |
| Need to find undocumented parameters to fuzz | `hidden-param-discovery` |
| Leaked internal hosts or admin panels to chase | `internal-portal-discovery` |
| Config disclosure suggests trusted-header auth bypass | `403-bypass` |
| Deciding whether the leak chains into something HIGH+ | `auto-chain-discovery` |
| Enumeration primitive found, needs throttle bypass | `rate-limit-bypass` |

---

## Skill metadata

- **Pattern**: Information Disclosure / Sensitive Data Exposure
- **Severity**: Informational-High (impact-dependent; most instances are informational)
- **Tech**: generic, apache, nginx, iis, php, java, spring, django, laravel, aspnet, git
- **Triggers**: `/test-infoleak`, `information disclosure`, `information leakage`, `sensitive data exposure`, `verbose error`, `stack trace`, `debug page`, `directory listing`, `robots.txt`, `backup file`, `exposed git`, `.git`, `developer comments`
- **Related skills**: js-bundle-secrets, source-map-exposure, aspnet-verbose-errors, sql-injection-testing, ssti-testing, iis-shortname-exploitation, hidden-param-discovery, internal-portal-discovery, 403-bypass, auto-chain-discovery, rate-limit-bypass
- **Sources**: portswigger-academy (information-disclosure, information-disclosure/exploiting)
