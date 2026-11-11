---
name: abandoned-cloud-takeover
description: "Find and claim abandoned S3/GCS/Azure Blob buckets referenced from JS bundles, build configs, and IaC templates, turning a NoSuchBucket 404 into supply-chain code execution on the site that still loads them. Use when JS or config files point at cloud storage returning NoSuchBucket/404, or when auditing CloudFormation/Terraform for dangling bucket names."
---

# Abandoned Cloud Storage & S3 Bucket Takeover

## Crown Jewel Targets

- S3 buckets referenced in JS bundles, build configs, IaC templates
- GCS/Azure Blob storage referenced in documentation and configs
- CloudFormation templates referencing abandoned S3 buckets (IAM takeover)
- VPN config files fetched from abandoned buckets (traffic interception)
- Maven/Gradle dependencies hosted on abandoned S3 (build-time RCE)
- NPM packages served via CDN proxies like unpkg.com (XSS)
- CNAME subdomains pointing to non-existent S3 buckets

## Attack Surface Signals

- JS source containing `s3.amazonaws.com`, `storage.googleapis.com`, `blob.core.windows.net`
- Build configs (Makefile, Dockerfile, CI/CD YAML) with `s3://` references
- `NoSuchBucket` XML response from bucket URLs
- CNAME records pointing to `*.s3.amazonaws.com`
- `curl|bash` install scripts referencing S3 URLs

**Sources:** WatchTowr Labs (2025), general research
**Affected:** Any application referencing cloud storage that no longer exists

## Overview

When applications reference cloud storage buckets (S3, GCS, Azure Blob) that no longer exist, attackers register the bucket name and serve malicious content to all consumers.

## WatchTowr Case Study

Registered ~150 abandoned S3 buckets. Received 8 million requests over 2 months from governments, militaries, Fortune 500. Some buckets abandoned since 2015 still receiving live requests.

## Attack Vectors After Takeover

| Vector | Impact | Severity |
|--------|--------|----------|
| CloudFormation template poisoning | Arbitrary IAM/infra in victim AWS | CRITICAL |
| SSLVPN config hijacking | VPN traffic interception | CRITICAL |
| Unsigned binary distribution (`curl \| bash`) | RCE on build systems | CRITICAL |
| Maven/Gradle dependency poisoning | RCE on build servers | CRITICAL |
| Vagrant VM image poisoning | Developer workstation control | HIGH |
| JavaScript injection (`<script src>`) | XSS on referencing pages | HIGH |
| CSS injection | UI redressing, data exfil | MEDIUM |

## Detection Methodology

### Step 1: Find Cloud Storage References

```bash
# S3
grep -rn "s3\.amazonaws\.com\|s3-[a-z].*\.amazonaws\.com" *.js *.html

# GCS
grep -rn "storage\.googleapis\.com" *.js *.html

# Azure Blob
grep -rn "\.blob\.core\.windows\.net" *.js *.html

# Build configs
grep -rn "s3://" Makefile Dockerfile *.yml *.yaml
```

### Step 2: Test Bucket Existence

```bash
# S3 -- NoSuchBucket = takeover candidate
curl -s https://bucketname.s3.amazonaws.com/ | grep "NoSuchBucket"

# GCS
curl -s https://storage.googleapis.com/bucketname/ | grep "NoSuchBucket"

# Azure Blob
curl -s https://account.blob.core.windows.net/container/ | grep "BlobNotFound"
```

### Step 3: Check Build Pipelines

```bash
# CI/CD
grep -rn "curl.*s3\.\|wget.*s3\." .github/workflows/ .gitlab-ci.yml

# Homebrew (sha256: no_check = no integrity!)
grep -rn "sha256.*no_check" *.rb

# IaC
grep -rn "s3://" *.tf *.template
```

## Claiming

```bash
aws s3 mb s3://abandoned-bucket-name --region us-east-1
echo "Takeover proof by [researcher]" > index.html
aws s3 cp index.html s3://abandoned-bucket-name/ --acl public-read
```

## Variants

### S3 CNAME Subdomain Takeover

```
subdomain.target.com -> CNAME -> bucket.s3.amazonaws.com -> NoSuchBucket
```

Claim bucket = full subdomain control + cookie scope.

### NPM Package Squatting via CDN

CDN proxies (unpkg.com) serve NPM packages by name. Unpublished package name = register replacement. Unpkg serves HTML as `text/html` (XSS-able).

## Bug Bounty Relevance

- **HIGH-CRITICAL**: Supply chain impact, easy to prove
- Minimal technical complexity (recon + bucket registration)
- Look in: JS bundles, build configs, IaC templates, documentation
- Many programs specifically reward supply chain findings
- Proves real-world impact (code execution, data interception)

## Operator Notes (Battle-Tested)

- **`NoSuchBucket` = takeover candidate**: This is the only confirmation you need. Register the bucket name in the same region and serve your proof content.
- **Check JS bundles first**: S3/GCS references in compiled JavaScript are the most common source. `grep -rn "s3\.amazonaws\.com" *.js` across all captured JS files.
- **Build pipeline poisoning is CRITICAL**: If a CI/CD pipeline does `curl s3://bucket/script.sh | bash`, taking over the bucket = RCE on every build. Check `.github/workflows/`, `.gitlab-ci.yml`.
- **CloudFormation template poisoning = IAM takeover**: If a CF template references an abandoned bucket, you can inject IAM roles and resources into the victim's AWS account.
- **S3 CNAME subdomain takeover**: `subdomain.target.com -> CNAME -> bucket.s3.amazonaws.com -> NoSuchBucket`. Claim bucket = full subdomain control + cookie scope. This is the highest-impact variant.
- **Homebrew `sha256: no_check`**: Some Homebrew formulae skip integrity validation. If the download URL points to an abandoned bucket, supply chain attack on every Mac user who installs the package.

## Related Skills & Chains

| Pattern | Chain Potential |
|---------|---------------|
| `subdomain-takeover` | CNAME-based subdomain takeover |
| `js-bundle-secrets` | JS analysis for S3 references |
| `cicd-pipeline-attacks` | Build pipeline poisoning |
| `firebase-misconfig` | Cloud service misconfiguration |
| `csp-bypass` | CSP bypass via taken-over domain |
