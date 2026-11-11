---
name: chains-meta
description: "Meta-decision chains for the autonomous agent — the layer above technique playbooks. Use to decide: am I WALLED (defense blocking me) or WRONG-DIRECTION (no vuln here); is an observation REAL or FAKED (WAF-forged 200, honeypot shell, scanner false-positive, cached/reflected response); when to PIVOT to an orthogonal dimension; when an entry point is EXHAUSTED; how to PRIORITIZE targets; and how to CLOSE THE KILL once a getshell primitive is in hand. Primarily for the planner (dispatch/stuck/pivot/stop decisions); workers consult it to self-check a suspicious observation or a stuck state. Consult BEFORE concluding 'no vuln', reporting a finding, or abandoning a direction."
---

# chains-meta · Meta-Decision Chains

> The layer **above** technique playbooks. Technique skills tell you *how* to exploit X; this tells you *whether to believe what you see, whether to keep going, and where to turn*. Primarily for the **planner**; the worker consults it when an observation looks suspicious or progress has stalled.

## Iron rules (the five that matter most)

1. **A 200 is not a win.** WAFs forge `200` + a normal-looking page (even a copy of the real homepage) to fool automation. Before trusting any success, run a **benign/malicious A/B**: if an obviously-legal request and an obviously-illegal one return near-identical body length / Server header / timing, a middle layer is faking the response. Trust a **content anchor** (a value only real execution/real data produces), never the status code.
2. **No echo ≠ no vuln.** Negative reflection never means negative vulnerability until out-of-band (OOB) **and** blind differentials are also negative. Record "no echo" as "channel problem, to rule out", not "no bug".
3. **Change the axis, not the parameter.** After ~15–25 attempts whose responses are fully homogeneous (no new status/length/timing), the information gradient is zero — pivot to a different **dimension**, don't keep tuning values on the same one. Leave a suspend-marker (where stuck, what was tried, when to return).
4. **Too easy = suspect.** A high-value, low-friction, "sitting in the open" finding in an otherwise hardened environment is the classic honeypot/decoy signature. Verify environment authenticity (real, messy, interconnected data) before investing.
5. **Close the kill before you diverge.** Once you hold a primitive that converts directly to shell/flag (writable template, unchecked upload, stacked SQLi / `INTO OUTFILE`, arbitrary file read of the flag path, any command channel), **stop exploring** and convert it. Diverging with the kill in hand is self-sabotage; only diverge after that primitive is confirmed dead.

---

## 1. Stuck-detection — am I being WALLED?

Recognize a defense in the way, vs a dead end:

- **All responses same length/status** → assume a middle layer. A/B a pure-GET homepage vs a definitely-404 path; if even normal/abnormal collapse to one page, it's an interception layer. Confirm via response-header fingerprints (Server change, CDN/WAF headers, protection cookies, request-id/support-id), and abnormally short+stable RTT (WAF answered, never hit the backend).
- **Keyword vs IP block:** send a benign-but-complex request (long/many params, no attack signature). Passes → content/signature blocking, work the encoding. Also blocked → likely IP-level ban, payload tricks are pointless.
- **Sudden total timeout** → separate *my link* from *the target*: probe another port/IP of the target and an unrelated public site. Only target's service dead = target-side action. RST/ICMP = reject; silence to timeout = firewall drop (usually behavioral dynamic ban → **slow down**, don't burn IPs).
- **Still responding but slow, only for attack traffic** → tarpit. Stop using response-time as a signal (it's manipulated); switch the decision criterion to content difference (boolean/OOB instead of time-blind).
- **Was working, now the same request fails** → dynamic ban / rule hot-update / session expiry. Fresh session first; then clean source IP. IP-recovers = behavioral IP ban; still blocked = a rule was added to this exact point (you've been noticed — reassess exposure).
- **Scanner results all-red or all-green** → suspicious. All-green can be uniform interception the scanner misreads as "nothing"; all-red can be a honeypot answering "present" to everything. Real vuln distributions are ragged; "tidy" = verify manually (pick mutually-exclusive findings; both "true" = indiscriminate decoy).

## 2. Trust-observation — is this REAL or is the tool/environment lying?

Before acting on any observation, ask what else could produce it:

- **WAF-forged 200** (see iron rule 1): A/B + content anchor. If all payload variants converge to one forged page and IP/entry/encoding pivots all fail, tag "strong WAF" and go map assets for a softer bypass path.
- **"Clean" reverse shell may be a honeypot:** real production hosts are *dirty* (messy process tree, real business load, irregular home dirs). A "DB server" with an empty process list, no business connections, and one bait file in `home` is highly suspect. Cross-check `/proc` integrity, uname vs distro files, a deliberately-wrong command's error format. If suspect → low-noise read-only mode, drop no tooling, re-examine how you were *led* here.
- **Empty RCE echo:** judge by **side-effects, not echo**. Time probe (sleep) → OOB (DNS/HTTP callback) → file side-effect (write to web-reachable dir, read back). Only when time + OOB + file side-effect are all negative may you call the point non-executable.
- **`sqlmap` says not-injectable → distrust the negative.** Tool negatives mean "these payloads didn't trigger this run", never "safe". Check it actually reached the code path (auth, `--data`, cookie, CSRF). Then hand-probe the most basic boolean true/false fork. Consider 2nd-order and non-SQL injection. Tool **positives** are usually trustworthy; **negatives never close an attack surface you otherwise suspect.**
- **Banner version → "assumption", not fact.** Admins fake versions (honeypot bait), reverse proxies rewrite, patches fix code without bumping the banner. Cross-check with behavior fingerprints and a non-destructive existence check before firing a destructive exploit.
- **Scanner "high-severity" → inference-type is high-FP.** Distinguish PoC-type (payload sent, evidence obtained — credible) from inference-type (version/fingerprint guess — reproduce by hand). Demand unambiguous, unique evidence (your computed value, your random OOB string, a definite can't-read value). Weak "response contains a keyword" is probably FP.
- **Response may be a CDN cache of someone else's** (`Age`/`X-Cache`/`CF-Cache-Status`): a cache hit proves nothing about *your* request — bust it (random query param, no-cache, non-GET) before judging.
- **Reflected payload ≠ executed.** "Appears verbatim" is usually reflection (potential XSS), not server-side execution. Use an **evaluable probe** (an expression that changes only if executed): result changed = execution; verbatim = reflection. Avoids the classic XSS-mistaken-for-RCE error.
- **`whoami` still unprivileged after an exploit printed `[+] success`:** the exploit finishing ≠ you holding a privileged context. Verify a privilege **side-effect** (suid file, new user, root-owned listener), confirm exact kernel/version/mitigations. Success is "I can repeatedly run privileged commands and read a root-only file", nothing less.
- **Credentials that work everywhere / password-spray all-success:** mass success = deception. Feed a guaranteed-wrong credential; if it also "succeeds", the endpoint is a fake-auth decoy — its successes are void.
- **Overly-helpful error / too-perfect leak:** a message that conveniently tells you the next step is likely a honeytoken. Cross-verify the hinted resource in an independent source; if it exists only in the error, treat as bait.

## 3. Orthogonal pivot — HOW to change dimension

Pivoting means changing the **axis**, not a value on the same axis. Enumerate axes first, then choose:

- **Axis list:** ① attack-surface (network / application / protocol / dependency / people) ② means (exploit / credentials / misconfiguration / trust-abuse) ③ layer (network / transport / application / business-logic) ④ time (immediate vs patient) ⑤ channel (in-band / out-of-band) ⑥ data-state (in-transit / at-rest / in-memory-endpoint) ⑦ identity (current context / other users / service accounts).
- **Truly orthogonal?** Two paths are orthogonal only if A's failure cause would *not* also fail B. Re-encoding behind the same WAF is NOT orthogonal (same WAF decides); a different protocol/port that bypasses the WAF IS.
- **Exploit vs credentials** are the two most-conflated main trunks — evaluate in parallel. When patches are current but you have a foothold, credential reuse/spray usually beats hammering an exploit.
- **Network ↔ application:** app layer filtered → sink to transport/network (unencrypted protocols, direct backend, management ports); network locked → float up to business-logic bugs (which WAFs can't see).
- **Auth-bypass vs post-auth abuse:** "can't get in" and "what can I abuse once in" are orthogonal. Grab any low-priv legitimate identity (self-registration, trial, SSO callback, password-reset) and the battlefield changes to authorization (horizontal/vertical IDOR) — often soft where auth is hard.
- **Self vs third-party/supply-chain:** rigorous in-house code still ships an outdated component. Fingerprint components → known 1-days; then the build pipeline / dependency registry / integration glue (the three-no-man's-land between components).
- **Target vs its dependencies/upstream:** can't move the target → attack what it can't live without (its DB, the API it calls, shared infra, the thing that trusts its output).
- **Breadth vs depth:** recon early = breadth (map all entries); after a soft signal appears, switch to depth. Keep an **axis × depth matrix**: shallow-probe all axes for a signal ranking, then spend depth on the strongest. Every sink/float must take away one artifact (a port, a fingerprint, an error) — empty round-trips mean you didn't really project onto that axis.

## 4. Give-up — is this entry point EXHAUSTED?

- **Coverage matrix before quitting:** for the entry, mark tried/untried/N-A across injection, auth&session, authz/IDOR, file ops, business logic. Many blanks = not exhausted, you're under-covering — don't quit, cover.
- **Motive check:** if you're trying to *prove the point has a bug* rather than *use it to advance the goal*, ego is driving, not strategy — leave.
- **Time-box, pre-set:** assign each path a budget by value × confidence *before* you start. "Almost there" is the most dangerous signal because it can't be falsified — at the deadline, allow one extension only if you can state the concrete, verifiable next result; else leave. A give-up with a written **re-pickup trigger** ("come back after I get the version/a credential") is a suspend, not a retreat.
- **Sunk cost doesn't vote:** decide only on "expected value of the next X minutes here vs switching". If the remaining uncertainty hasn't dropped despite prior investment, it's negative-EV — switch.
- **Same vuln class failing across independent points** (different frameworks/languages) = the class doesn't fit this target, not "my technique"; switch class, then switch target (to softer edge/legacy/forgotten-test assets).

## 5. Priority — what to hit FIRST

- **Rank by exploit-maturity × privilege-gain × exposure**, not by port number. One-probe triage to red/yellow/green in ~10 min (e.g. SMB → MS17-010 check; DB → anon+weak-cred; web → fingerprint framework/version); invest only in red/yellow.
- **Low-hanging fruit before the crown jewel** (unless scoring says otherwise): a foothold is the prerequisite for everything, and an edge box yields credentials/internal-view/routing that make the crown jewel soft "from the inside". Prefer the soft target that is **credential-rich or close to core assets** (in-domain? high-priv service account? can reach a network you can't?).
- **Web apps by tech-debt density:** in-house legacy > upload/file/export functions > admin login > up-to-date standard CMS > static. Pull known-severe-CVE versions out first (deterministic wins). Same-origin/same-codebase apps = "study once, harvest many".
- **N-day before logic bugs:** N-day = deterministic, minutes to confirm/refute (but verify version-in-range, preconditions, local PoC repro before concluding a hot-patch). Logic bugs = high-uncertainty deep water, time-boxed per hypothesis.
- **Identity & trust path to the crown jewel:** core targets are usually entered through the front door with a valid credential, or via a trust channel (AD trust, ADCS templates, SCCM/WSUS, backup/monitoring agents), not punched open by an exploit.

## 6. Close-the-kill — convert the primitive, don't wander

- **Recognize the kill** (iron rule 5). The moment you can convert to code-exec/file-rw/flag, stop lateral exploration and drive that one primitive to shell.
- **Persist the entry ticket FIRST.** Before anything else, write the session cookie, admin path, default creds, captcha/validation bypass to durable task memory (`record_fact` / the exploration graph) — context gets compacted and what's only "in the window" vanishes. Store the **conclusion** ("upload point at X, filters Y, bypass with Z"), not the raw page. Re-reading the same artifact never yields new information; if you catch yourself re-reading, you've lost context — recall the stored conclusion instead.
- **Action order:** ① lock the one primitive and write the shortest path to shell; ② execute, read the real response; ③ on failure, diagnose what blocks *this* primitive (perm/filter/path) and change the technique **within** this primitive (suffix/MIME/dir/second-render), don't switch primitives; ④ once executing, immediately verify you can read the flag / land a webshell; ⑤ only then persist the foothold and move on.
- One failure is a clue, not the end. Only after every reasonable bypass of *this* primitive is dead do you fall back to finding the next primitive.

---

## How to use

Locate the topic + scenario above, follow its decision rule. When answering or deciding, the rules here **override** the optimism of "it feels close". The recurring meta-signal: when responses stop changing, when a result is "too good", or when you're re-deriving what you already knew — stop, and apply the matching rule before spending another round.
