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
FROM --platform=$BUILDPLATFORM node:22-bookworm-slim AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --ignore-scripts
COPY web/ ./
RUN npm run build:static

# ------------------------------------------------------------- Go binary ---
# Pinned to the Go 1.26 line (matches go.mod and the release binaries job). The
# binary is CGO-free, so this stage runs on the build platform and cross-compiles
# to $TARGETARCH without QEMU.
FROM --platform=$BUILDPLATFORM golang:1.26-bookworm AS build
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
# upgrade deliberately. Each archive is verified against the checksums file of its
# own GitHub release (exact asset name, sha256). That file comes from the same
# release channel as the archive, so it catches corrupted or swapped downloads and
# moved tags, not a compromised publisher. sqlmap has no release binaries: it is a
# shallow clone of a pinned tag, checked against the expected commit.
FROM --platform=$BUILDPLATFORM debian:bookworm-slim AS tools
ARG TARGETARCH
ARG NUCLEI_VERSION=v3.11.1
ARG HTTPX_VERSION=v1.12.0
ARG SUBFINDER_VERSION=v2.17.0
ARG KATANA_VERSION=v1.8.0
ARG FFUF_VERSION=v2.3.0
ARG DALFOX_VERSION=v3.2.4
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
      amd64) PD_ARCH=amd64; FFUF_ARCH=amd64; DALFOX_ARCH=x86_64; TRIVY_ARCH=64bit; OG_ARCH=x86; OG_SHA="$OPENGREP_SHA256_AMD64" ;; \
      arm64) PD_ARCH=arm64; FFUF_ARCH=arm64; DALFOX_ARCH=aarch64; TRIVY_ARCH=ARM64; OG_ARCH=aarch64; OG_SHA="$OPENGREP_SHA256_ARM64" ;; \
      *) echo "unsupported architecture: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    mkdir -p /out; \
    fetch() { base="$1"; asset="$2"; sums="$3"; name="$4"; \
      rm -rf /tmp/t; mkdir -p /tmp/t/x; \
      curl -fsSL "$base/$asset" -o "/tmp/t/$asset"; \
      curl -fsSL "$base/$sums" -o /tmp/t/sums.txt; \
      want="$(awk -v a="$asset" '$2 == a || $2 == "*" a { print $1 }' /tmp/t/sums.txt)"; \
      if [ -z "$want" ]; then echo "no checksum entry for $asset" >&2; exit 1; fi; \
      got="$(sha256sum "/tmp/t/$asset" | cut -d' ' -f1)"; \
      if [ "$want" != "$got" ]; then echo "checksum mismatch for $asset: want $want got $got" >&2; exit 1; fi; \
      case "$asset" in *.zip) unzip -q "/tmp/t/$asset" -d /tmp/t/x ;; *) tar -xzf "/tmp/t/$asset" -C /tmp/t/x ;; esac; \
      find /tmp/t/x -type f -name "$name" -exec install -m 0755 {} /out/ \; ; \
      [ -x "/out/$name" ] || { echo "$name not found in $asset" >&2; exit 1; }; \
      rm -rf /tmp/t; }; \
    gh="https://github.com"; \
    fetch "$gh/projectdiscovery/nuclei/releases/download/$NUCLEI_VERSION" \
      "nuclei_${NUCLEI_VERSION#v}_linux_${PD_ARCH}.zip" "nuclei_${NUCLEI_VERSION#v}_checksums.txt" nuclei; \
    fetch "$gh/projectdiscovery/httpx/releases/download/$HTTPX_VERSION" \
      "httpx_${HTTPX_VERSION#v}_linux_${PD_ARCH}.zip" "httpx_${HTTPX_VERSION#v}_checksums.txt" httpx; \
    fetch "$gh/projectdiscovery/subfinder/releases/download/$SUBFINDER_VERSION" \
      "subfinder_${SUBFINDER_VERSION#v}_linux_${PD_ARCH}.zip" "subfinder_${SUBFINDER_VERSION#v}_checksums.txt" subfinder; \
    fetch "$gh/projectdiscovery/katana/releases/download/$KATANA_VERSION" \
      "katana_${KATANA_VERSION#v}_linux_${PD_ARCH}.zip" "katana-${KATANA_VERSION#v}-checksums.txt" katana; \
    fetch "$gh/ffuf/ffuf/releases/download/$FFUF_VERSION" \
      "ffuf_${FFUF_VERSION#v}_linux_${FFUF_ARCH}.tar.gz" "ffuf_${FFUF_VERSION#v}_checksums.txt" ffuf; \
    fetch "$gh/hahwul/dalfox/releases/download/$DALFOX_VERSION" \
      "dalfox-${DALFOX_VERSION}-linux-${DALFOX_ARCH}-musl.tar.gz" "dalfox-${DALFOX_VERSION}-linux-${DALFOX_ARCH}-musl.tar.gz.sha256" dalfox; \
    fetch "$gh/aquasecurity/trivy/releases/download/$TRIVY_VERSION" \
      "trivy_${TRIVY_VERSION#v}_Linux-${TRIVY_ARCH}.tar.gz" "trivy_${TRIVY_VERSION#v}_checksums.txt" trivy; \
    fetch "$gh/trufflesecurity/trufflehog/releases/download/$TRUFFLEHOG_VERSION" \
      "trufflehog_${TRUFFLEHOG_VERSION#v}_linux_${PD_ARCH}.tar.gz" "trufflehog_${TRUFFLEHOG_VERSION#v}_checksums.txt" trufflehog; \
    fetch "$gh/assetnote/kiterunner/releases/download/$KITERUNNER_VERSION" \
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
FROM python:3.12-slim-bookworm
ARG TARGETARCH
# Common tools: ripgrep / curl / vim, plus a set of recon staples (add/remove as needed).
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates ripgrep curl wget vim git jq unzip xz-utils \
      dnsutils iputils-ping netcat-openbsd inetutils-telnet whois nmap libpcap0.8 \
    && rm -rf /var/lib/apt/lists/*
# Node 22 from the official nodejs.org tarball, verified against its SHASUMS256.txt:
# bookworm's apt nodejs is 18, Playwright requires >=20, and 20 is end-of-life.
# 22 matches the CI and release workflows.
ARG NODE_VERSION=22.23.4
RUN set -eux; \
    case "${TARGETARCH:-amd64}" in \
      amd64) NODE_ARCH=x64 ;; \
      arm64) NODE_ARCH=arm64 ;; \
      *) echo "unsupported architecture: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    base="https://nodejs.org/dist/v${NODE_VERSION}"; \
    asset="node-v${NODE_VERSION}-linux-${NODE_ARCH}.tar.xz"; \
    curl -fsSL "$base/$asset" -o "/tmp/$asset"; \
    curl -fsSL "$base/SHASUMS256.txt" -o /tmp/SHASUMS256.txt; \
    want="$(awk -v a="$asset" '$2 == a { print $1 }' /tmp/SHASUMS256.txt)"; \
    if [ -z "$want" ]; then echo "no checksum entry for $asset" >&2; exit 1; fi; \
    got="$(sha256sum "/tmp/$asset" | cut -d' ' -f1)"; \
    if [ "$want" != "$got" ]; then echo "checksum mismatch for $asset: want $want got $got" >&2; exit 1; fi; \
    tar -xJf "/tmp/$asset" -C /usr/local --strip-components=1 --no-same-owner; \
    rm -f "/tmp/$asset" /tmp/SHASUMS256.txt; \
    node --version; npm --version
# Pinned, checksum-verified recon binaries and the sqlmap checkout from the tools stage.
COPY --from=tools /out/ /usr/local/bin/
COPY --from=tools /opt/sqlmap /opt/sqlmap
COPY --from=gotools /out/ /usr/local/bin/
COPY --from=naabu /go/bin/naabu /usr/local/bin/naabu
COPY --from=tools /opt/codeql /opt/codeql
COPY --from=tools /opt/SecLists /opt/SecLists
COPY --from=tools /opt/gf /root/.gf
# Read by agent/hostbash.go and advertised to workers as $ARTEX_WORDLISTS.
ENV ARTEX_WORDLISTS=/opt/SecLists
RUN set -eux; \
    ln -s /opt/sqlmap/sqlmap.py /usr/local/bin/sqlmap; \
    nuclei -version >/dev/null; httpx -version; subfinder -version; katana -version; \
    ffuf -V >/dev/null; dalfox --version >/dev/null; sqlmap --version >/dev/null; \
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
RUN set -eux; \
    python -m venv /opt/bbot; \
    /opt/bbot/bin/pip install --no-cache-dir "bbot==${BBOT_VERSION}"; \
    ln -s /opt/bbot/bin/bbot /usr/local/bin/bbot; \
    bbot -y --install-all-deps; \
    bbot --version >/dev/null; \
    bbot --dry-run -t example.com -m wafw00f,paramminer_getparams,lightfuzz,sslcert,gowitness >/dev/null 2>&1 || true; \
    bbot --dry-run -t example.com -m wafw00f,paramminer_getparams,lightfuzz,sslcert,gowitness --no-color >/tmp/bbot-dry.log 2>&1 || true; \
    ! grep -qE "Installing|ERRR|CRITICAL" /tmp/bbot-dry.log || { cat /tmp/bbot-dry.log; exit 1; }


# Preinstall Playwright MCP and CLI (globally) so no npx network download is needed at runtime.
# @playwright/mcp: browser MCP runs directly via `npx @playwright/mcp` (installed globally, no -y/@latest needed).
# @playwright/cli: provides playwright-cli, verified with --help right after install.
# Then install playwright (browser management) and preinstall chromium plus its system
# dependencies via --with-deps, so MCP/CLI work on first start inside the container
# without downloading browsers over the network. All three are pinned; upgrade deliberately.
ARG PLAYWRIGHT_MCP_VERSION=0.0.83
ARG PLAYWRIGHT_CLI_VERSION=0.1.22
ARG PLAYWRIGHT_VERSION=1.64.1
RUN npm install -g "@playwright/mcp@${PLAYWRIGHT_MCP_VERSION}" "@playwright/cli@${PLAYWRIGHT_CLI_VERSION}" "playwright@${PLAYWRIGHT_VERSION}" \
    && playwright-cli --help \
    && playwright install --with-deps chromium \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
# Binary compiled from source in the build stage above.
COPY --from=build /out/artex /app/artex
# Daemon startup script: relaunches the process after a crash and forwards SIGTERM
# to artex — docker stop only signals PID 1; without forwarding, artex never receives it,
# cannot shut down gracefully, and is hard-killed by SIGKILL after 10 seconds.
COPY start.sh /app/start.sh
RUN chmod +x /app/artex /app/start.sh && mkdir -p /app/keys
COPY skills/ /app/skills/
# persistence points: data/ (SQLite, task files) and keys/ (jwt.key, via ARTEX_JWT_KEY_DIR)
VOLUME ["/app/data", "/app/keys"]
EXPOSE 8787 8788
ENTRYPOINT ["/app/start.sh"]
CMD ["-addr", ":8787", "-proxy", ":8788"]
