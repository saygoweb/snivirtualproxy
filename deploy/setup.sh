#!/usr/bin/env bash
# deploy/setup.sh — Install snivirtualproxy on a Debian/Ubuntu system.
#
# Usage (from the repository root):
#   sudo bash deploy/setup.sh [--no-start] [--no-enable] [--sample-config]
#
# Options:
#   --no-start        Install and enable the service but do not start it.
#   --no-enable       Install but do not enable or start the service.
#   --sample-config   Install the sample config.yml even if a config already
#                     exists (backs up the existing file first).
#
# What this script does:
#   1.  Verify prerequisites (root, OS, required tools).
#   2.  Optionally install Go if not found.
#   3.  Build snivirtualproxy from source.
#   4.  Install binary → /usr/local/sbin/
#   5.  Create /etc/snivirtualproxy/
#   6.  Install a starter config.yml (skipped if one already exists, unless
#       --sample-config is given).
#   7.  Install the systemd unit and reload systemd.
#   8.  Enable and/or start the service (respecting --no-start/--no-enable).

set -euo pipefail

# ── Colour helpers ────────────────────────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; BOLD='\033[1m'; NC='\033[0m'
info()    { echo -e "${BOLD}[setup]${NC} $*"; }
success() { echo -e "${GREEN}[setup]${NC} $*"; }
warn()    { echo -e "${YELLOW}[setup]${NC} $*"; }
die()     { echo -e "${RED}[setup] ERROR:${NC} $*" >&2; exit 1; }

# ── Option parsing ────────────────────────────────────────────────────────────
OPT_NO_START=false
OPT_NO_ENABLE=false
OPT_SAMPLE_CONFIG=false

for arg in "$@"; do
    case "$arg" in
        --no-start)       OPT_NO_START=true ;;
        --no-enable)      OPT_NO_ENABLE=true ;;
        --sample-config)  OPT_SAMPLE_CONFIG=true ;;
        -h|--help)
            sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) die "Unknown option: $arg (use --help for usage)" ;;
    esac
done

# ── Locate the repository root ────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# ── Prerequisite checks ───────────────────────────────────────────────────────
[[ "$EUID" -eq 0 ]] || die "This script must be run as root (use sudo)."

if [[ ! -f /etc/debian_version ]]; then
    warn "This script targets Debian/Ubuntu; continuing anyway on $(uname -s)."
fi

# ── Go toolchain ──────────────────────────────────────────────────────────────
GO_MIN_MAJOR=1
GO_MIN_MINOR=21

ensure_go() {
    if command -v go &>/dev/null; then
        GO_VER=$(go version | awk '{print $3}' | sed 's/go//')
        GO_MAJOR=$(echo "$GO_VER" | cut -d. -f1)
        GO_MINOR=$(echo "$GO_VER" | cut -d. -f2)
        if [[ "$GO_MAJOR" -gt "$GO_MIN_MAJOR" ]] || \
           { [[ "$GO_MAJOR" -eq "$GO_MIN_MAJOR" ]] && [[ "$GO_MINOR" -ge "$GO_MIN_MINOR" ]]; }; then
            info "Go $GO_VER found at $(command -v go)"
            return
        else
            warn "Go $GO_VER is too old (need >= $GO_MIN_MAJOR.$GO_MIN_MINOR); will install a newer version."
        fi
    else
        info "Go not found; installing via apt..."
    fi

    apt-get update -qq
    if apt-get install -y -qq golang-go 2>/dev/null && command -v go &>/dev/null; then
        info "Installed Go $(go version | awk '{print $3}')"
        return
    fi

    # Fallback: download the official tarball for the current stable release
    local GOTAR_URL
    local GOARCH
    GOARCH=$(dpkg --print-architecture)
    [[ "$GOARCH" == "amd64" ]] || [[ "$GOARCH" == "arm64" ]] || \
        die "Unsupported architecture for automatic Go install: $GOARCH"
    GOTAR_URL="https://dl.google.com/go/go1.22.4.linux-${GOARCH}.tar.gz"
    info "Downloading Go from $GOTAR_URL ..."
    curl -fsSL "$GOTAR_URL" -o /tmp/go.tar.gz
    rm -rf /usr/local/go
    tar -C /usr/local -xzf /tmp/go.tar.gz
    rm /tmp/go.tar.gz
    export PATH="/usr/local/go/bin:$PATH"
    info "Installed Go $(/usr/local/go/bin/go version | awk '{print $3}')"
}

ensure_go

# ── Build ─────────────────────────────────────────────────────────────────────
info "Building snivirtualproxy from $REPO_ROOT ..."
cd "$REPO_ROOT"

BUILD_DIR="$REPO_ROOT/.build"
mkdir -p "$BUILD_DIR"

go build -o "$BUILD_DIR/snivirtualproxy" .

success "Build complete."

# ── Install binary ────────────────────────────────────────────────────────────
info "Installing binary to /usr/local/sbin/ ..."
install -m 755 "$BUILD_DIR/snivirtualproxy" /usr/local/sbin/snivirtualproxy
rm -rf "$BUILD_DIR"
success "Installed /usr/local/sbin/snivirtualproxy."

# ── Config directory ──────────────────────────────────────────────────────────
info "Creating config directory ..."
mkdir -p /etc/snivirtualproxy
chmod 750 /etc/snivirtualproxy
success "Config directory: /etc/snivirtualproxy/"

# ── Starter config.yml ────────────────────────────────────────────────────────
CONFIG_FILE=/etc/snivirtualproxy/config.yml

install_sample_config() {
    info "Installing starter config.yml → $CONFIG_FILE ..."
    cat > "$CONFIG_FILE" <<'EOF'
# /etc/snivirtualproxy/config.yml — snivirtualproxy configuration

logfile: '/var/log/snivirtualproxy.log'

server:
  bind: ":443"
  upstreamurl: "http://localhost:80"

ssl:
  # $(SNI_SERVER_NAME) is replaced with the TLS SNI hostname at runtime.
  # This allows a single proxy to serve multiple virtual hosts using
  # certificates managed by Let's Encrypt (certbot) or similar tools.
  certificate: "/etc/letsencrypt/live/$(SNI_SERVER_NAME)/fullchain.pem"
  key: "/etc/letsencrypt/live/$(SNI_SERVER_NAME)/privkey.pem"
EOF
    chmod 640 "$CONFIG_FILE"
    chown root:root "$CONFIG_FILE"
    success "Installed starter config at $CONFIG_FILE."
}

if [[ -f "$CONFIG_FILE" ]]; then
    if $OPT_SAMPLE_CONFIG; then
        BACKUP="${CONFIG_FILE}.bak.$(date +%Y%m%dT%H%M%S)"
        warn "Backing up existing $CONFIG_FILE → $BACKUP"
        cp "$CONFIG_FILE" "$BACKUP"
        install_sample_config
    else
        info "Config $CONFIG_FILE already exists — skipping (use --sample-config to overwrite)."
    fi
else
    install_sample_config
fi

# ── Systemd unit ──────────────────────────────────────────────────────────────
UNIT_FILE=/etc/systemd/system/snivirtualproxy.service
info "Installing systemd unit → $UNIT_FILE ..."
install -m 644 "$REPO_ROOT/deploy/snivirtualproxy.service" "$UNIT_FILE"
systemctl daemon-reload
success "Systemd unit installed."

# ── Enable / start ────────────────────────────────────────────────────────────
if $OPT_NO_ENABLE; then
    warn "Skipping enable and start (--no-enable)."
elif $OPT_NO_START; then
    systemctl enable snivirtualproxy
    success "Service enabled (not started — use: systemctl start snivirtualproxy)."
else
    systemctl enable snivirtualproxy
    systemctl restart snivirtualproxy
    sleep 1
    if systemctl is-active --quiet snivirtualproxy; then
        success "snivirtualproxy is running."
    else
        warn "snivirtualproxy failed to start. Check logs with: journalctl -u snivirtualproxy -n 50"
    fi
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo
echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo -e "${GREEN}  snivirtualproxy installation complete${NC}"
echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo
echo "  Binary:  /usr/local/sbin/snivirtualproxy"
echo "  Config:  /etc/snivirtualproxy/config.yml"
echo "  Log:     /var/log/snivirtualproxy.log"
echo
echo "  Quick start:"
echo "    1. Edit config:   \$EDITOR /etc/snivirtualproxy/config.yml"
echo "    2. Start service: systemctl start snivirtualproxy"
echo "    3. Check status:  systemctl status snivirtualproxy"
echo "    4. View logs:     journalctl -u snivirtualproxy -f"
echo
