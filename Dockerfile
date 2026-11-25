# syntax=docker/dockerfile:1
#
# Multi-stage build: `docker compose up -d --build` (or `docker build .`) produces
# the complete image from source. No prebuilt binary in the build context is needed,
# so a fresh `git clone` builds — dist/ is git-ignored and is no longer required.
#
#   frontend (web) -> Go binary with embedded UI (build) -> runtime image
#
# The Go binary is produced by build.sh with the same flags the release workflow's
# binaries job uses, so the image binary and the published release binary come from
# one source.

# ---------------------------------------------------------------- frontend ---
# Pinned to the Node 22 line the CI/release workflows use. On the build platform
# only; the frontend static export is architecture-independent.
FROM --platform=$BUILDPLATFORM node:25-bookworm-slim@sha256:81db02c4b671288a03915da9534dbd54f96d0e7c24d80ccc54f5b36b2e684370 AS web
ENV NEXT_TELEMETRY_DISABLED=1
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --ignore-scripts
COPY web/ ./
RUN npm run build:static

# ------------------------------------------------------------- Go binary ---
# Pinned to the exact Go release go.mod requires. The official image sets
# GOTOOLCHAIN=local, so a floating 1.26 tag that lags go.mod fails the build;
# bump this together with the go line in go.mod. The binary is CGO-free, so this
# stage runs on the build platform and cross-compiles to $TARGETARCH without QEMU.
FROM --platform=$BUILDPLATFORM golang:1.26.11-bookworm@sha256:dc40a13b61304647ed7e5d581d246b86413dfc29d63c6d018310feb93cd98fc0 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# Reuse the frontend built above; build.sh skips its own frontend step.
COPY --from=web /src/web/out ./server/webui/dist
ARG ARTEX_VERSION=dev
ARG TARGETOS
ARG TARGETARCH
# Same flags as the release binaries job (ARTEX_COMPRESS=0, -trimpath,
# -X main.version), driven through build.sh so there is one build path.
RUN ARTEX_SKIP_FRONTEND=1 \
    ARTEX_SKIP_NPM_CI=1 \
    ARTEX_COMPRESS=0 \
    ARTEX_OUTPUT=/out/artex \
    ARTEX_BUILD_VERSION="${ARTEX_VERSION}" \
    bash ./build.sh --target "${TARGETOS:-linux}/${TARGETARCH:-amd64}"

# ------------------------------------------------------- third-party tools ---
# Web-recon toolbox (drost-community take 1, #100): pinned release binaries, staged
# on the build platform and copied into /usr/local/bin of the runtime image so hunt
# workers can run them directly through their Bash tool. Versions pinned per tool;
# upgrade deliberately.
#
# Every archive is verified against a SHA-256 written down here, per asset and per
# architecture, not against the *_checksums.txt of its own GitHub release. Checking
# against that file catches a corrupted or swapped download and a moved tag, but the
# digest and the artifact it describes come from the same publisher and the same
# release: a replacement asset and a replacement checksums file agree with each
# other and the build passes. Pinning the digest here moves that decision out of the
# build, so a swapped asset fails unless the diff that swaps it also changes the
# digest a reviewer reads.
#
# Cost: a version bump is now three edits (the version ARG and the two digests), and
# a publisher re-uploading an asset under the same tag breaks the build until the
# digest is bumped on purpose. That is the trade: the build stops trusting the
# channel it downloads from.
#
# sqlmap has no release binaries: it is a shallow clone of a pinned tag, checked
# against the expected commit, which is the same idea.
FROM --platform=$BUILDPLATFORM debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc AS tools
ARG TARGETARCH
ARG NUCLEI_VERSION=v3.11.1
ARG NUCLEI_SHA256_AMD64=ea63d4ae232808cd7c6bc00d0142428e231fab59dae01042246097d195835ab6
ARG NUCLEI_SHA256_ARM64=8044e3d9768ba0a744b2872c1a87e813006f013da97ca9f50f7661a4203bec07
ARG HTTPX_VERSION=v1.12.0
ARG HTTPX_SHA256_AMD64=9d8439e8b6c9aa7d1e2314817a392e00d5178da3af5652f7475f88868f418f76
ARG HTTPX_SHA256_ARM64=fd7b123c1dfbc3d69f19f524e4eebcd6ec06b9a6cbd56813c76f11645197331e
ARG SUBFINDER_VERSION=v2.17.0
ARG SUBFINDER_SHA256_AMD64=a39c3e5c7a26ef3c430915c4d6cbf7716a00f26769a75e9405aba796142eba37
ARG SUBFINDER_SHA256_ARM64=24913d49dddc1d3a5e99a4a7580da5be980959b9415b96f52c4f7f4124392190
ARG KATANA_VERSION=v1.8.0
ARG KATANA_SHA256_AMD64=cb027ae99d0757061b70c07a15c7a80f62c5a535ab52c4a329f80c4b0a7309d2
ARG KATANA_SHA256_ARM64=80e269210727a855511ffac8dfb01297b2344742acec71a35e8ba4a67a90f0f2
ARG FFUF_VERSION=v2.3.0
ARG FFUF_SHA256_AMD64=b2a3c725fcb9da175159682f54d6e9149f2905b00d84d155e7efc5d599975ceb
ARG FFUF_SHA256_ARM64=e2d712615d53da797ee929006e41f2df5a7960a5353133db9c150ddaa22ae4e8
ARG DALFOX_VERSION=v3.2.4
ARG DALFOX_SHA256_AMD64=c11cfd2f8261973f0a2a2a1eba5a147ce77712a29acfa6343f9847fb8bb7eca2
ARG DALFOX_SHA256_ARM64=fd56b0b7da2d06868cd73b504f41d21314629feffcd5bdc97718db1c9dd2fa70
ARG SQLMAP_VERSION=1.9.9
ARG SQLMAP_COMMIT=cceda39208b5aad478de2c3f731df4239d9881f6
ARG TRIVY_VERSION=v0.76.2
ARG TRUFFLEHOG_VERSION=v3.99.9
ARG KITERUNNER_VERSION=v1.0.2
# feroxbuster publishes no checksums file and no arm64 Linux tarball: amd64 only,
# pinned by the sha256 of the release asset.
ARG FEROXBUSTER_VERSION=v2.14.0
ARG FEROXBUSTER_SHA256=3ab2cefdb03af090bcf11c4b82bd85a7e8a2b4439237ac06993568eade28ee96
# SecLists (sparse: discovery/fuzzing/credential lists, not the multi-GB leak dumps)
# and gf patterns, each pinned to a commit.
ARG SECLISTS_VERSION=2026.2
ARG SECLISTS_COMMIT=145f1f45ba7bc5fd6b3966d3a79bf95654deb20e
ARG GF_PATTERNS_COMMIT=f686f06ae647726578920084c894100d702496cc
# opengrep ships single binaries with no checksums file: pinned per arch by sha256.
ARG OPENGREP_VERSION=v1.33.1
ARG OPENGREP_SHA256_AMD64=46e8133cc490f9f50518061590ce2f6be5a08afaeda034471c0ceda4b3899808
ARG OPENGREP_SHA256_ARM64=d1433f63a90b8bc0b6ad4b498a13b372b856ce9a754a43484ba4920fe2d76dcf
# CodeQL bundle (CLI + query packs) is ~700 MB compressed / ~2 GB unpacked and amd64
# only, so it is opt-in: docker build --build-arg INSTALL_CODEQL=1 .
ARG INSTALL_CODEQL=0
ARG CODEQL_BUNDLE_VERSION=v2.27.4
ARG CODEQL_BUNDLE_SHA256=89ed56c8ec6bfccef6a0d2e7fe86da0469ca24b4db08b88016ec134b942c17a4
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl git unzip \
    && rm -rf /var/lib/apt/lists/*
RUN set -eux; \
    case "${TARGETARCH:-amd64}" in \
      amd64) PD_ARCH=amd64; FFUF_ARCH=amd64; DALFOX_ARCH=x86_64; TRIVY_ARCH=64bit; OG_ARCH=x86; OG_SHA="$OPENGREP_SHA256_AMD64"; \
             NUCLEI_SUM="$NUCLEI_SHA256_AMD64"; HTTPX_SUM="$HTTPX_SHA256_AMD64"; \
             SUBFINDER_SUM="$SUBFINDER_SHA256_AMD64"; KATANA_SUM="$KATANA_SHA256_AMD64"; \
             FFUF_SUM="$FFUF_SHA256_AMD64"; DALFOX_SUM="$DALFOX_SHA256_AMD64" ;; \
      arm64) PD_ARCH=arm64; FFUF_ARCH=arm64; DALFOX_ARCH=aarch64; TRIVY_ARCH=ARM64; OG_ARCH=aarch64; OG_SHA="$OPENGREP_SHA256_ARM64"; \
             NUCLEI_SUM="$NUCLEI_SHA256_ARM64"; HTTPX_SUM="$HTTPX_SHA256_ARM64"; \
             SUBFINDER_SUM="$SUBFINDER_SHA256_ARM64"; KATANA_SUM="$KATANA_SHA256_ARM64"; \
             FFUF_SUM="$FFUF_SHA256_ARM64"; DALFOX_SUM="$DALFOX_SHA256_ARM64" ;; \
      *) echo "unsupported architecture: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    mkdir -p /out; \
    fetch() { base="$1"; asset="$2"; want="$3"; name="$4"; \
      rm -rf /tmp/t; mkdir -p /tmp/t/x; \
      curl -fsSL "$base/$asset" -o "/tmp/t/$asset"; \
      if [ -z "$want" ]; then echo "no pinned digest for $asset" >&2; exit 1; fi; \
      got="$(sha256sum "/tmp/t/$asset" | cut -d' ' -f1)"; \
      if [ "$want" != "$got" ]; then echo "checksum mismatch for $asset: want $want got $got" >&2; exit 1; fi; \
      case "$asset" in *.zip) unzip -q "/tmp/t/$asset" -d /tmp/t/x ;; *) tar -xzf "/tmp/t/$asset" -C /tmp/t/x ;; esac; \
      find /tmp/t/x -type f -name "$name" -exec install -m 0755 {} /out/ \; ; \
      [ -x "/out/$name" ] || { echo "$name not found in $asset" >&2; exit 1; }; \
      rm -rf /tmp/t; }; \
    gh="https://github.com"; \
    fetch "$gh/projectdiscovery/nuclei/releases/download/$NUCLEI_VERSION" \
      "nuclei_${NUCLEI_VERSION#v}_linux_${PD_ARCH}.zip" "$NUCLEI_SUM" nuclei; \
    fetch "$gh/projectdiscovery/httpx/releases/download/$HTTPX_VERSION" \
      "httpx_${HTTPX_VERSION#v}_linux_${PD_ARCH}.zip" "$HTTPX_SUM" httpx; \
    fetch "$gh/projectdiscovery/subfinder/releases/download/$SUBFINDER_VERSION" \
      "subfinder_${SUBFINDER_VERSION#v}_linux_${PD_ARCH}.zip" "$SUBFINDER_SUM" subfinder; \
    fetch "$gh/projectdiscovery/katana/releases/download/$KATANA_VERSION" \
      "katana_${KATANA_VERSION#v}_linux_${PD_ARCH}.zip" "$KATANA_SUM" katana; \
    fetch "$gh/ffuf/ffuf/releases/download/$FFUF_VERSION" \
      "ffuf_${FFUF_VERSION#v}_linux_${FFUF_ARCH}.tar.gz" "$FFUF_SUM" ffuf; \
    fetch "$gh/hahwul/dalfox/releases/download/$DALFOX_VERSION" \
      "dalfox-${DALFOX_VERSION}-linux-${DALFOX_ARCH}-musl.tar.gz" "$DALFOX_SUM" dalfox; \
    fetch_checksums() { base="$1"; asset="$2"; sums="$3"; name="$4"; \
      rm -rf /tmp/t; mkdir -p /tmp/t/x; \
      curl -fsSL "$base/$asset" -o "/tmp/t/$asset"; \
      curl -fsSL "$base/$sums" -o /tmp/t/sums.txt; \
      (cd /tmp/t && grep "  $asset\$" sums.txt | sha256sum -c -); \
      case "$asset" in *.zip) unzip -q "/tmp/t/$asset" -d /tmp/t/x ;; *) tar -xzf "/tmp/t/$asset" -C /tmp/t/x ;; esac; \
      find /tmp/t/x -type f -name "$name" -exec install -m 0755 {} /out/ \; ; \
      [ -x "/out/$name" ] || { echo "$name not found in $asset" >&2; exit 1; }; \
      rm -rf /tmp/t; }; \
    fetch_checksums "$gh/aquasecurity/trivy/releases/download/$TRIVY_VERSION" \
      "trivy_${TRIVY_VERSION#v}_Linux-${TRIVY_ARCH}.tar.gz" "trivy_${TRIVY_VERSION#v}_checksums.txt" trivy; \
    fetch_checksums "$gh/trufflesecurity/trufflehog/releases/download/$TRUFFLEHOG_VERSION" \
      "trufflehog_${TRUFFLEHOG_VERSION#v}_linux_${PD_ARCH}.tar.gz" "trufflehog_${TRUFFLEHOG_VERSION#v}_checksums.txt" trufflehog; \
    fetch_checksums "$gh/assetnote/kiterunner/releases/download/$KITERUNNER_VERSION" \
      "kiterunner_${KITERUNNER_VERSION#v}_linux_${PD_ARCH}.tar.gz" "kiterunner_${KITERUNNER_VERSION#v}_checksums.txt" kr; \
    if [ "$PD_ARCH" = amd64 ]; then \
      curl -fsSL "$gh/epi052/feroxbuster/releases/download/$FEROXBUSTER_VERSION/x86_64-linux-feroxbuster.tar.gz" -o /tmp/fx.tgz; \
      echo "$FEROXBUSTER_SHA256  /tmp/fx.tgz" | sha256sum -c -; \
      tar -xzf /tmp/fx.tgz -C /out feroxbuster; chmod 0755 /out/feroxbuster; rm -f /tmp/fx.tgz; \
    fi; \
    curl -fsSL "$gh/opengrep/opengrep/releases/download/$OPENGREP_VERSION/opengrep_manylinux_${OG_ARCH}" -o /out/opengrep; \
    echo "$OG_SHA  /out/opengrep" | sha256sum -c -; chmod 0755 /out/opengrep; \
    mkdir -p /opt/codeql; \
    if [ "$INSTALL_CODEQL" = 1 ]; then \
      [ "$PD_ARCH" = amd64 ] || { echo "CodeQL bundle is amd64 only" >&2; exit 1; }; \
      curl -fsSL "$gh/github/codeql-action/releases/download/codeql-bundle-$CODEQL_BUNDLE_VERSION/codeql-bundle-linux64.tar.gz" -o /tmp/codeql.tgz; \
      echo "$CODEQL_BUNDLE_SHA256  /tmp/codeql.tgz" | sha256sum -c -; \
      tar -xzf /tmp/codeql.tgz -C /opt; rm -f /tmp/codeql.tgz; \
    fi; \
    git clone --quiet --depth 1 --filter=blob:none --sparse --branch "$SECLISTS_VERSION" https://github.com/danielmiessler/SecLists /opt/SecLists; \
    git -C /opt/SecLists sparse-checkout set Discovery Fuzzing Usernames Payloads \
      Passwords/Common-Credentials Passwords/Default-Credentials; \
    commit="$(git -C /opt/SecLists rev-parse HEAD)"; \
    if [ "$commit" != "$SECLISTS_COMMIT" ]; then echo "SecLists commit mismatch: want $SECLISTS_COMMIT got $commit" >&2; exit 1; fi; \
    rm -rf /opt/SecLists/.git; \
    git clone --quiet https://github.com/1ndianl33t/Gf-Patterns /tmp/gfp; \
    git -C /tmp/gfp checkout --quiet "$GF_PATTERNS_COMMIT"; \
    mkdir -p /opt/gf; cp /tmp/gfp/*.json /opt/gf/; rm -rf /tmp/gfp; \
    git clone --quiet --depth 1 --branch "$SQLMAP_VERSION" https://github.com/sqlmapproject/sqlmap /opt/sqlmap; \
    commit="$(git -C /opt/sqlmap rev-parse HEAD)"; \
    if [ "$commit" != "$SQLMAP_COMMIT" ]; then echo "sqlmap commit mismatch: want $SQLMAP_COMMIT got $commit" >&2; exit 1; fi; \
    rm -rf /opt/sqlmap/.git

# -------------------------------------------------------- nuclei templates ---
# nuclei ships no templates in the binary: on first run it clones
# projectdiscovery/nuclei-templates into $HOME/nuclei-templates. Where the process
# cannot reach github.com that install fails softly — it logs "nuclei-templates are
# not installed, installing...", then "no templates found in path", and exits 0, so a
# scan starts with an empty template set and looks like a broken tool. That is the
# normal case behind an egress allowlist, and the case for every agent-run scan: the
# executor's HOME is /app/data/exec-home, not the root-owned home the image is
# built with. Bake the set at a fixed path instead, and point nuclei at it with
# NUCLEI_TEMPLATES_DIR in the runtime stage, so the lookup does not depend on HOME or
# on which user the process runs as. Tag and commit are both pinned and asserted: a
# moved tag fails the build rather than silently changing the template set.
ARG NUCLEI_TEMPLATES_VERSION=v10.5.1
ARG NUCLEI_TEMPLATES_COMMIT=79fb682760ab3d5b0e22afbb44709353cbebf023
RUN set -eux; \
    git clone --quiet --depth 1 --branch "$NUCLEI_TEMPLATES_VERSION" \
      https://github.com/projectdiscovery/nuclei-templates /opt/nuclei-templates; \
    commit="$(git -C /opt/nuclei-templates rev-parse HEAD)"; \
    if [ "$commit" != "$NUCLEI_TEMPLATES_COMMIT" ]; then echo "nuclei-templates commit mismatch: want $NUCLEI_TEMPLATES_COMMIT got $commit" >&2; exit 1; fi; \
    rm -rf /opt/nuclei-templates/.git; \
    count="$(find /opt/nuclei-templates -name '*.yaml' | wc -l)"; \
    echo "baked nuclei templates: $count"; \
    test "$count" -gt 10000

# ------------------------------------------------------------- Go tools ---
# Go CLIs without checksummed release binaries for both arches: built from pinned
# module versions; go install checks every module against sum.golang.org.
# CGO-free cross-compile on the build platform. naabu needs cgo/libpcap and has
# its own stage below.
FROM --platform=$BUILDPLATFORM golang:1.26-bookworm AS gotools
ARG TARGETARCH
RUN set -eux; \
    # GOTOOLCHAIN=auto: a tool may need a newer Go (osv-scanner wants >= 1.27.3); the
    # toolchain download is checksum-verified like any module.
    export CGO_ENABLED=0 GOOS=linux GOARCH="${TARGETARCH:-amd64}" GOFLAGS=-trimpath GOTOOLCHAIN=auto; \
    for pkg in \
      github.com/projectdiscovery/dnsx/cmd/dnsx@v1.3.1 \
      github.com/projectdiscovery/interactsh/cmd/interactsh-client@v1.4.1 \
      github.com/lc/gau/v2/cmd/gau@v2.2.4 \
      github.com/tomnomnom/waybackurls@v0.1.0 \
      github.com/tomnomnom/gf@v0.0.0-20200618134122-dcd4c361f9f5 \
      github.com/Emoe/kxss@v0.0.0-20260531193025-acb2dc76e840 \
      github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@v1.4.1 \
      github.com/sensepost/gowitness@v0.0.0-20261011045312-601c84367aaf \
      github.com/fullstorydev/grpcurl/cmd/grpcurl@v1.9.4 \
      github.com/zricethezav/gitleaks/v8@v8.30.1 \
      github.com/google/osv-scanner/v2/cmd/osv-scanner@v2.7.1 \
      github.com/securego/gosec/v2/cmd/gosec@v2.30.0 \
      golang.org/x/vuln/cmd/govulncheck@v1.9.0 \
    ; do go install "$pkg"; done; \
    mkdir -p /out; find /go/bin -type f -exec install -m 0755 {} /out/ \;

# naabu links libpcap through cgo, so it builds on the target platform (QEMU for a
# cross-arch build); the runtime image installs libpcap0.8 for it.
FROM golang:1.26-bookworm AS naabu
RUN apt-get update && apt-get install -y --no-install-recommends libpcap-dev \
    && rm -rf /var/lib/apt/lists/*
RUN CGO_ENABLED=1 GOFLAGS=-trimpath GOTOOLCHAIN=auto \
    go install github.com/projectdiscovery/naabu/v2/cmd/naabu@v2.7.0

# ---------------------------------------------------------------- runtime ---
FROM python:3.12-slim-bookworm@sha256:935c3c5b12357a7e10caa9c1e6ca5692344d97cf229832ef584be2cec9fc03df
ARG TARGETARCH
# Common tools: ripgrep / curl / vim, plus a set of recon staples (add/remove as needed).
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates ripgrep curl wget vim git jq unzip xz-utils \
      dnsutils iputils-ping netcat-openbsd inetutils-telnet whois nmap libpcap0.8 \
      arp-scan arping fping iproute2 netdiscover net-tools nfs-common \
      python3-impacket python3-paramiko python3-scapy rpcbind sqlite3 xxd \
      hashcat hydra john ncrack openssh-client ssh-audit sshpass \
    && rm -rf /var/lib/apt/lists/*
# Node 22 from the official nodejs.org tarball: bookworm's apt nodejs is 18,
# Playwright requires >=20, and 20 is end-of-life. 22 matches the CI and release
# workflows. Verified against a digest pinned here rather than against the fetched
# SHASUMS256.txt, for the reason given at the tools stage.
ARG NODE_VERSION=22.23.4
ARG NODE_SHA256_AMD64=1805bcd35e6815559bd2eb97db438d3fdb0eb3a5e6a977b7c1badca76337e9ce
ARG NODE_SHA256_ARM64=6287aa46b6c375d816e63ae66d024fbbfd70404825aabdfdf898a970871d2f4b
RUN set -eux; \
    case "${TARGETARCH:-amd64}" in \
      amd64) NODE_ARCH=x64; want="$NODE_SHA256_AMD64" ;; \
      arm64) NODE_ARCH=arm64; want="$NODE_SHA256_ARM64" ;; \
      *) echo "unsupported architecture: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    base="https://nodejs.org/dist/v${NODE_VERSION}"; \
    asset="node-v${NODE_VERSION}-linux-${NODE_ARCH}.tar.xz"; \
    curl -fsSL "$base/$asset" -o "/tmp/$asset"; \
    [ -n "$want" ] || { echo "no pinned digest for $asset" >&2; exit 1; }; \
    got="$(sha256sum "/tmp/$asset" | cut -d' ' -f1)"; \
    if [ "$want" != "$got" ]; then echo "checksum mismatch for $asset: want $want got $got" >&2; exit 1; fi; \
    tar -xJf "/tmp/$asset" -C /usr/local --strip-components=1 --no-same-owner; \
    rm -f "/tmp/$asset"; \
    node --version; npm --version
# Pinned, checksum-verified recon binaries and the sqlmap checkout from the tools stage,
# plus the baked nuclei template set (see the tools stage for why it is baked).
COPY --from=tools /out/ /usr/local/bin/
COPY --from=tools /opt/sqlmap /opt/sqlmap
COPY --from=tools /opt/nuclei-templates /opt/nuclei-templates
COPY --from=gotools /out/ /usr/local/bin/
COPY --from=naabu /go/bin/naabu /usr/local/bin/naabu
COPY --from=tools /opt/codeql /opt/codeql
COPY --from=tools /opt/SecLists /opt/SecLists
COPY --from=tools /opt/gf /root/.gf
ENV ARTEX_WORDLISTS=/opt/SecLists \
    NUCLEI_TEMPLATES_DIR=/opt/nuclei-templates \
    DISABLE_NUCLEI_TEMPLATES_PUBLIC_DOWNLOAD=true
RUN set -eux; \
    ln -s /opt/sqlmap/sqlmap.py /usr/local/bin/sqlmap; \
    nuclei -version >/dev/null; httpx -version; subfinder -version; katana -version; \
    ffuf -V >/dev/null; dalfox --version >/dev/null; sqlmap --version >/dev/null; \
    templates="$(nuclei -tl -silent -duc | wc -l)"; \
    echo "nuclei templates visible at build time: $templates"; \
    test "$templates" -gt 10000; \
    if [ -x /opt/codeql/codeql ]; then ln -s /opt/codeql/codeql /usr/local/bin/codeql; codeql version >/dev/null; fi; \
    for t in dnsx naabu interactsh-client gau waybackurls gf kxss crlfuzz gowitness grpcurl \
             gitleaks osv-scanner gosec govulncheck trivy trufflehog kr opengrep; do \
      command -v "$t" >/dev/null || { echo "missing $t" >&2; exit 1; }; done; \
    trivy --version >/dev/null; gitleaks version >/dev/null; naabu -version >/dev/null 2>&1; \
    opengrep --version >/dev/null; \
    [ -d /opt/SecLists/Discovery/Web-Content ]

# Python CLIs (semgrep for whitebox, arjun for parameter discovery): pinned, own venv.
ARG SEMGREP_VERSION=1.185.0
ARG ARJUN_VERSION=2.2.7
RUN set -eux; \
    python -m venv /opt/pytools; \
    /opt/pytools/bin/pip install --no-cache-dir "semgrep==${SEMGREP_VERSION}" "arjun==${ARJUN_VERSION}"; \
    ln -s /opt/pytools/bin/semgrep /usr/local/bin/semgrep; \
    ln -s /opt/pytools/bin/arjun /usr/local/bin/arjun; \
    semgrep --version >/dev/null; arjun --help >/dev/null

# bbot recursive recon orchestrator (#117): blacklanternsecurity/bbot, AGPL-3.0
# (same license as ARTEX; standalone CLI dependency, not linked code). Pinned
# version, own venv to isolate from the image python. Module dependencies are
# preinstalled (--install-all-deps) so scans never need pip at runtime, which
# would fail under a program's egress allowlist.
ARG BBOT_VERSION=3.0.2
# arm64: bbot's Chrome and retirejs's Node are x86-64; use native builds.
RUN set -eux; \
    python -m venv /opt/bbot; \
    /opt/bbot/bin/pip install --no-cache-dir "bbot==${BBOT_VERSION}"; \
    ln -s /opt/bbot/bin/bbot /usr/local/bin/bbot; \
    if [ "${TARGETARCH:-amd64}" = "arm64" ]; then \
      apt-get update; \
      apt-get install -y --no-install-recommends chromium; \
      rm -rf /var/lib/apt/lists/*; \
      bbot_dir="$(/opt/bbot/bin/python -c 'import bbot, os; print(os.path.dirname(bbot.__file__))')"; \
      sed -i 's/linux-x64/linux-arm64/g' "$bbot_dir/modules/retirejs.py"; \
    fi; \
    bbot -y --install-all-deps; \
    if [ "${TARGETARCH:-amd64}" = "arm64" ]; then \
      printf '\nmodules:\n  gowitness:\n    chrome_path: /usr/bin/chromium\n' >> /root/.config/bbot/bbot.yml; \
    fi; \
    bbot --version >/dev/null; \
    bbot --dry-run -t example.com -m wafw00f,paramminer_getparams,lightfuzz,sslcert,gowitness,retirejs >/dev/null 2>&1 || true; \
    bbot --dry-run -t example.com -m wafw00f,paramminer_getparams,lightfuzz,sslcert,gowitness,retirejs --no-color >/tmp/bbot-dry.log 2>&1 || true; \
    ! grep -qE "Installing|ERRR|CRITICAL" /tmp/bbot-dry.log || { cat /tmp/bbot-dry.log; exit 1; }


# Preinstall Playwright MCP and CLI (globally) so no network download is needed at runtime.
# @playwright/mcp: the seeded browser MCP runs the playwright-mcp binary directly.
# `npx @playwright/mcp` is not used: it queries the npm registry on every start even
# with the package installed globally.
# @playwright/cli: provides playwright-cli, verified with --help right after install.
# Then install playwright (browser management) and preinstall chromium plus its system
# dependencies via --with-deps. @playwright/mcp and @playwright/cli bundle their own
# playwright-core, which expects a different Chromium build than
# playwright@PLAYWRIGHT_VERSION installs, so that build is installed as well (second
# install line); without it neither can launch a browser. All three packages are
# pinned; upgrade deliberately.
ARG PLAYWRIGHT_MCP_VERSION=0.0.83
ARG PLAYWRIGHT_CLI_VERSION=0.1.22
ARG PLAYWRIGHT_VERSION=1.64.1
# playwright-core's exports map hides cli.js from require.resolve, so run the
# binary npm links for @playwright/mcp instead: it is the copy MCP actually
# loads, and it installs the Chromium revision that copy expects.
ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
    NODE_PATH=/usr/local/lib/node_modules
RUN npm install -g "@playwright/mcp@${PLAYWRIGHT_MCP_VERSION}" "@playwright/cli@${PLAYWRIGHT_CLI_VERSION}" "playwright@${PLAYWRIGHT_VERSION}" \
    && playwright-cli --help \
    && playwright install --with-deps chromium \
    && "$(npm root -g)/@playwright/mcp/node_modules/.bin/playwright-core" install chromium \
    && npm cache clean --force \
    && rm -rf /root/.npm /var/lib/apt/lists/*

# Point /usr/bin/chromium to Playwright's Chromium binary so recon tools (api-recon, gowitness) can find it.
RUN set -eux; \
    CHROME_BIN="$(find /ms-playwright -path '*/chrome-linux*/chrome' -type f | head -n1)"; \
    test -n "$CHROME_BIN"; \
    ln -sf "$CHROME_BIN" /usr/bin/chromium; \
    ln -sf "$CHROME_BIN" /usr/bin/chromium-browser; \
    chmod -R a+rX /ms-playwright; \
    "$CHROME_BIN" --version
WORKDIR /app
# Binary compiled from source in the build stage above.
COPY --from=build /out/artex /app/artex
# Daemon startup script: relaunches the process after a crash and forwards SIGTERM
# to artex — docker stop only signals PID 1; without forwarding, artex never receives it,
# cannot shut down gracefully, and is hard-killed by SIGKILL after 10 seconds.
COPY start.sh /app/start.sh
RUN chmod +x /app/artex /app/start.sh && mkdir -p -m 0700 /app/keys \
    && mkdir -p /app/data /app/.playwright \
    && printf '%s\n' '{"browser":{"browserName":"chromium","launchOptions":{"args":["--no-sandbox"]}}}' > /app/.playwright/cli.config.json \
    && chmod 0711 /root
# No setuid or setgid programs (su, passwd, mount, bbot's chrome_sandbox, ...): an
# agent process runs as the executor and must not regain root through one, even
# when the container runs without docker-compose.yml's no-new-privileges.
RUN find / -xdev -perm /6000 -type f -exec chmod a-s {} +
COPY skills/ /app/skills/
# persistence points: data/ (traffic index, task files, transcripts) and keys/ (jwt.key, secret.key, via ARTEX_JWT_KEY_DIR)
VOLUME ["/app/data", "/app/keys"]
EXPOSE 8787 8788
ENTRYPOINT ["/app/start.sh"]
CMD ["-addr", ":8787", "-proxy", ":8788"]
