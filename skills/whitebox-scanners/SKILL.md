---
name: whitebox-scanners
description: "Invoke this skill when you have source code on disk (data\\source\\...) and want automated scanner coverage before or alongside manual review: secrets (gitleaks, trufflehog), dependency CVEs (trivy, osv-scanner, govulncheck), static analysis (semgrep/opengrep with local rules, gosec, codeql). Gives commands verified on this host, what each is good for, and how to triage output so scanner noise never becomes a finding."
---

# Whitebox scanners (run on the source tree, then verify by hand)

Scanner output is a LEAD, never evidence. A result becomes a finding only when you trace it to attacker-controlled input and a reachable sink, or reproduce it live with a raw request and a control. State "source only, PoC not run" when the route is not reachable.

All commands run in Git Bash. Use a scratch dir inside your intent dir for outputs (`OUT=./scan; mkdir -p $OUT`). Pass native paths as `C:/...`.

## 1. Secrets
- `gitleaks detect --no-git --source <repo> --redact --report-format json --report-path $OUT/gitleaks.json` (works, fast: about 20 MB in 2 s).
- Triage by `File` first. Hits in `*_test.go`, fixtures, `.example`, `${ENV}` placeholders are almost always noise (all 10 hits on the Compliance Center tree were test fixtures). Real leaks live in `etc/`, `deploy/`, `Makefile`, `Dockerfile`, `.env*`, CI files and front-end bundles.
- `trufflehog filesystem <repo> --no-update --no-verification --json`: never let it verify a secret against a live third-party service.

## 2. Dependency vulnerabilities
- `trivy fs --skip-db-update --offline-scan --scanners vuln,secret,misconfig --format json -o $OUT/trivy.json <repo>` works offline here. Read `Results[].Vulnerabilities[]`: `PkgName`, `InstalledVersion`, `FixedVersion`, `Severity`, and `Target` (which go.mod or lockfile).
- `osv-scanner scan source -r <repo>` (online: sends only package names and versions). The local offline DB on this host holds PyPI only, so `--offline-vulnerabilities` is useless for Go or npm.
- `govulncheck ./...` inside a Go module reports only vulnerable functions the code actually calls; if it cannot load module dependencies, say so and fall back to trivy.
- Triage: a CVE is a finding only if the vulnerable function or feature is reachable from the service's input. Name the package, version, fixed version and the code path (file:line). A dependency CVE in an internal consumer that no request reaches is "source only, reachability not shown", Low unless a path exists.

## 3. Static analysis
- Semgrep with LOCAL rules only (no network): `semgrep --metrics=off --config C:/Users/trungnd66/SecTools/rules/trailofbits-semgrep-rules/go --json --quiet -o $OUT/semgrep.json <dirs>`. Rule dirs exist for go, javascript, python, jvm, generic. Zero results is a valid outcome: the ruleset is small.
- `opengrep scan --config <dir> --json` takes the same rule files.
- `gosec -no-fail -quiet -fmt=json -out=$OUT/gosec.json ./...` inside a Go module often writes no file here when dependencies are missing offline. Do not report "clean" from an empty gosec run; report "gosec could not analyse (deps)".
- `codeql` needs a database build (`codeql database create`) and a working Go build: only attempt it for the one or two services that matter most, after manual review found a sink worth confirming.

## 4. What to do with the results
1. Cluster by repo and class; drop test files and generated code (`*.pb.go`, `*_test.go`, `vendor/`).
2. For each remaining lead, read the code at file:line, find the caller, and decide whether it is reachable from an HTTP, gRPC or event entry point.
3. Reachable and live-testable with GET/HEAD/OPTIONS: reproduce with a raw request plus a control, then report. Needs a write or is internal only: record a fact "source only" with file:line.
4. Record the scanner commands you ran and their exit status in a fact, including tools that could not run, so coverage is auditable.
