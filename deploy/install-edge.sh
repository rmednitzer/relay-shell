#!/usr/bin/env bash
set -euo pipefail

# relay-shell edge installer - idempotent.
#
# Installs Caddy and lays down the relay-shell Caddyfile with automated TLS
# via ACME (Let's Encrypt by default, ZeroSSL fallback). Provisioning and
# renewal are handled by Caddy's built-in ACME client; there is no cron and
# no certbot. Certificates persist across restarts under Caddy's data dir.
#
# Required:
#   RELAY_SHELL_EDGE_DOMAIN        public hostname (DNS A/AAAA must point here)
#   RELAY_SHELL_EDGE_ACME_EMAIL    contact email for ACME registration
#
# Recommended:
#   RELAY_SHELL_EDGE_CLIENT_CIDRS  space-separated source allowlist for
#                                  tool traffic and /token (defaults to
#                                  loopback only, which blocks remote clients)
#
# Optional:
#   RELAY_SHELL_EDGE_UPSTREAM      loopback upstream (default 127.0.0.1:8080)
#   RELAY_SHELL_EDGE_ACME_CA       ACME directory override (e.g. LE staging)
#   RELAY_SHELL_EDGE_OPEN_FIREWALL set to 1 to open 80/443 via ufw if present
#   RELAY_SHELL_EDGE_DRY_RUN       set to 1 to render the Caddyfile and exit
#
# Location: deploy/install-edge.sh  Run as: root (sudo)

SCRIPT_NAME="$(basename "$0")"
SRC_DIR="$(cd "$(dirname "$0")" && pwd)"
CADDYFILE_SRC="$SRC_DIR/Caddyfile"
CADDYFILE_DST="/etc/caddy/Caddyfile"
ENV_DROPIN_DIR="/etc/systemd/system/caddy.service.d"
ENV_DROPIN="$ENV_DROPIN_DIR/relay-shell-edge.conf"

log()  { echo "[$(date -Iseconds)] [$SCRIPT_NAME] $*"; }
warn() { log "WARN: $*" >&2; }
die()  { log "FATAL: $*" >&2; exit 1; }

require_var() {
    local name="$1"
    local val="${!name:-}"
    [ -n "$val" ] || die "$name is required (export it before running, or set it in /etc/relay-shell/relay-shell.env)"
}

# Load env so this installer can be re-run after editing the config file.
# shellcheck source=/dev/null
if [ -r /etc/relay-shell/relay-shell.env ]; then
    set -a
    . /etc/relay-shell/relay-shell.env
    set +a
fi

[ "$(id -u)" -eq 0 ] || die "must run as root"
[ -r "$CADDYFILE_SRC" ] || die "Caddyfile template not found at $CADDYFILE_SRC"

require_var RELAY_SHELL_EDGE_DOMAIN
require_var RELAY_SHELL_EDGE_ACME_EMAIL

: "${RELAY_SHELL_EDGE_UPSTREAM:=127.0.0.1:8080}"
: "${RELAY_SHELL_EDGE_CLIENT_CIDRS:=127.0.0.1/8 ::1}"
: "${RELAY_SHELL_EDGE_ACME_CA:=https://acme-v02.api.letsencrypt.org/directory}"

log "Edge domain : $RELAY_SHELL_EDGE_DOMAIN"
log "ACME email  : $RELAY_SHELL_EDGE_ACME_EMAIL"
log "ACME CA     : $RELAY_SHELL_EDGE_ACME_CA"
log "Upstream    : $RELAY_SHELL_EDGE_UPSTREAM"
log "Client CIDRs: $RELAY_SHELL_EDGE_CLIENT_CIDRS"

if [ "${RELAY_SHELL_EDGE_CLIENT_CIDRS}" = "127.0.0.1/8 ::1" ]; then
    warn "client CIDR allowlist is loopback only - remote clients will be 403'd until you set RELAY_SHELL_EDGE_CLIENT_CIDRS"
fi

if [ "${RELAY_SHELL_EDGE_DRY_RUN:-0}" = "1" ]; then
    log "Dry run - rendering Caddyfile to stdout (Caddy will substitute env vars at start)"
    cat "$CADDYFILE_SRC"
    exit 0
fi

if ! command -v caddy >/dev/null 2>&1; then
    log "Installing Caddy from the official apt repository"
    if ! command -v apt-get >/dev/null 2>&1; then
        die "no caddy binary and apt-get unavailable - install Caddy manually (see https://caddyserver.com/docs/install) and re-run"
    fi
    apt-get update -qq
    apt-get install -y -qq debian-keyring debian-archive-keyring apt-transport-https curl gnupg
    install -d -m 0755 /etc/apt/keyrings
    if [ ! -f /etc/apt/keyrings/caddy-stable-archive-keyring.gpg ]; then
        curl -fsSL https://dl.cloudsmith.io/public/caddy/stable/gpg.key \
            | gpg --dearmor -o /etc/apt/keyrings/caddy-stable-archive-keyring.gpg
        chmod 0644 /etc/apt/keyrings/caddy-stable-archive-keyring.gpg
    fi
    if [ ! -f /etc/apt/sources.list.d/caddy-stable.list ]; then
        cat >/etc/apt/sources.list.d/caddy-stable.list <<'REPO'
deb [signed-by=/etc/apt/keyrings/caddy-stable-archive-keyring.gpg] https://dl.cloudsmith.io/public/caddy/stable/deb/debian any-version main
deb-src [signed-by=/etc/apt/keyrings/caddy-stable-archive-keyring.gpg] https://dl.cloudsmith.io/public/caddy/stable/deb/debian any-version main
REPO
    fi
    apt-get update -qq
    apt-get install -y -qq caddy
else
    log "Caddy already installed: $(caddy version 2>/dev/null | head -1)"
fi

install -d -m 0755 /etc/caddy
install -d -m 0750 -o caddy -g caddy /var/log/caddy 2>/dev/null || install -d -m 0755 /var/log/caddy

log "Installing $CADDYFILE_DST"
install -m 0644 "$CADDYFILE_SRC" "$CADDYFILE_DST"

log "Installing systemd environment drop-in at $ENV_DROPIN"
install -d -m 0755 "$ENV_DROPIN_DIR"
umask 077
cat >"$ENV_DROPIN" <<EOF
# Managed by relay-shell deploy/install-edge.sh.
# These are read by Caddy at service start and substituted into the Caddyfile.
[Service]
Environment=RELAY_SHELL_EDGE_DOMAIN=${RELAY_SHELL_EDGE_DOMAIN}
Environment=RELAY_SHELL_EDGE_ACME_EMAIL=${RELAY_SHELL_EDGE_ACME_EMAIL}
Environment=RELAY_SHELL_EDGE_ACME_CA=${RELAY_SHELL_EDGE_ACME_CA}
Environment=RELAY_SHELL_EDGE_UPSTREAM=${RELAY_SHELL_EDGE_UPSTREAM}
Environment="RELAY_SHELL_EDGE_CLIENT_CIDRS=${RELAY_SHELL_EDGE_CLIENT_CIDRS}"
EOF
chmod 0644 "$ENV_DROPIN"
umask 022

log "Validating Caddyfile syntax"
# `caddy validate` reads the same env we just dropped in, so export them here.
export RELAY_SHELL_EDGE_DOMAIN RELAY_SHELL_EDGE_ACME_EMAIL RELAY_SHELL_EDGE_ACME_CA \
       RELAY_SHELL_EDGE_UPSTREAM RELAY_SHELL_EDGE_CLIENT_CIDRS
caddy validate --config "$CADDYFILE_DST" --adapter caddyfile

if [ "${RELAY_SHELL_EDGE_OPEN_FIREWALL:-0}" = "1" ] && command -v ufw >/dev/null 2>&1; then
    log "Opening 80/tcp and 443/tcp via ufw"
    ufw allow 80/tcp  >/dev/null || warn "ufw allow 80/tcp failed"
    ufw allow 443/tcp >/dev/null || warn "ufw allow 443/tcp failed"
fi

systemctl daemon-reload
log "Enabling and (re)starting caddy"
systemctl enable caddy >/dev/null
systemctl restart caddy

# Give Caddy a brief moment to settle, then report.
sleep 1
if systemctl is-active --quiet caddy; then
    log "Caddy is active. Initial certificate issuance happens on the first HTTPS request to ${RELAY_SHELL_EDGE_DOMAIN}."
    log "Watch progress with:  journalctl -u caddy -f"
else
    die "caddy failed to start - check 'journalctl -u caddy -n 100'"
fi

log "Done. Verify the cert with:  curl -I https://${RELAY_SHELL_EDGE_DOMAIN}/.well-known/oauth-protected-resource"
