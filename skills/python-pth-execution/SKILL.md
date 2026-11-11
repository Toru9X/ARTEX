---
name: python-pth-execution
description: "Turn an arbitrary file write into RCE on Python-based appliances by dropping a .pth file into site-packages, which the interpreter auto-executes on startup. Use when a Python appliance (FortiWeb, FortiAnalyzer, FortiManager) yields file write via SQLi INTO OUTFILE, upload, or traversal but no obvious code execution primitive."
---

# Python .pth File Code Execution

## Crown Jewel Targets

- Fortinet FortiWeb (SQLi + MySQL root + `.pth` write = pre-auth RCE)
- Any Python-based appliance with CGI scripts (FortiAnalyzer, FortiManager)
- Appliances with MySQL running as root (file write via `INTO OUTFILE`)
- Python web apps with path traversal file upload vulnerabilities
- Docker containers with writable `site-packages/` directory
- Systems where log injection can write to predictable paths

## Attack Surface Signals

- Python CGI scripts: `/cgi-bin/*.py`, `/api/*.py`
- MySQL running as root (common on appliances)
- File upload endpoints with path traversal potential
- Appliance management interfaces (FortiWeb, FortiAnalyzer)
- Error messages revealing Python version and `site-packages` paths

**Source:** WatchTowr Labs (FortiWeb CVE-2025-25257, 2025)

## Overview

Python's `site.py` module automatically processes `.pth` files in `site-packages/` during interpreter startup. Lines starting with `import` are executed as Python code. This is a documented feature, not a bug — but it creates a powerful RCE primitive when combined with arbitrary file write.

## Mechanism

Any `.pth` file in `lib/pythonX.Y/site-packages/` with an `import` line:
```
import os;os.system('id > /tmp/pwned')
```

Gets executed automatically when ANY Python script runs on the system.

## FortiWeb Exploitation Chain

1. Pre-auth SQLi in `Authorization: Bearer <sqli>` header
2. Space bypass: `/**/` MySQL block comments
3. 128-byte limit bypass: split across two requests (UPDATE + SELECT INTO OUTFILE)
4. Write `.pth` to `../../lib/python3.10/site-packages/x.pth` (relative path from MySQL workdir)
5. Trigger: hit `/cgi-bin/ml-draw.py` — Python startup loads `.pth`
6. MySQL runs as ROOT — file has root ownership

## General Application

Any vulnerability that allows file write to a Python site-packages directory:
- SQL injection with `INTO OUTFILE` (MySQL/MariaDB running as root)
- Path traversal file upload
- Symlink attacks
- Log injection to predictable paths

## Detection

```bash
# Find Python site-packages directories
python3 -c "import site; print(site.getsitepackages())"

# Check for existing .pth files (legitimate ones exist)
ls /usr/lib/python3.*/site-packages/*.pth

# FortiWeb specific — SQLi detection
curl -H "Authorization: Bearer AAAAAA'or'1'='1" https://target/api/fabric/device/status
# 200 = vulnerable, 401 = safe
```

## Bug Bounty Relevance

- Novel RCE primitive applicable to any system running Python
- Particularly relevant for appliances using Python CGI scripts
- MySQL running as root + SQLi = file write anywhere = .pth RCE
- The .pth mechanism is a FEATURE — it will never be patched

## Operator Notes (Battle-Tested)

- **`.pth` is a documented feature, not a bug**: Python's `site.py` automatically executes `import` lines in `.pth` files during ANY interpreter startup. This will NEVER be patched.
- **SQLi + root MySQL = .pth RCE**: `SELECT ... INTO OUTFILE '/path/to/site-packages/x.pth'`. MySQL running as root owns the file. Any Python CGI trigger loads it.
- **128-byte SQLi limit bypass**: Split the attack: first UPDATE to set a variable, then SELECT INTO OUTFILE using the variable. FortiWeb pattern.
- **Trigger is trivial**: Hit ANY `.py` CGI script — Python startup loads all `.pth` files. No need to find a specific vulnerable script.
- **Relative path from MySQL workdir**: `../../lib/python3.10/site-packages/x.pth` works when MySQL `LOAD_FILE` uses its working directory.
- **Combine with any file write primitive**: Path traversal upload, symlink attack, log injection — any write to site-packages = RCE.

## Related Skills & Chains

| Pattern | Chain Potential |
|---------|---------------|
| `appliance-management-attacks` | FortiWeb/FortiOS management interface access |
| `ssl-vpn-testing` | Fortinet appliance attack surface |
| `file-upload-testing` → `references/polyglot-file-upload-rce.md` | File upload to write `.pth` |
| `bash-rewritemap-injection` | Alternative RCE on appliances |
| `backup-mft-attacks` | File read to find site-packages path |
