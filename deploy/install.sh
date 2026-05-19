#!/usr/bin/env bash
set -euo pipefail

# mcpx installer - idempotent. Creates a dedicated service account and venv,
# installs the package, and lays down the systemd/logrotate assets. It does
# NOT enable or start the service: review the unit and configuration first.
#
# Location: deploy/install.sh   Run as: root (sudo)

SCRIPT_NAME="$(basename "$0")"
PREFIX="/var/lib/mcpx"
SRC_DIR="$(cd "$(dirname "$0")/.." && pwd)"

log() { echo "[$(date -Iseconds)] [$SCRIPT_NAME] $*"; }
die() { log "FATAL: $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "must run as root"

log "Ensuring service account 'mcpx'"
if ! id mcpx >/dev/null 2>&1; then
    useradd --system --create-home --home-dir "$PREFIX" \
            --shell /usr/sbin/nologin mcpx
fi

log "Creating venv at $PREFIX/venv"
if [ ! -x "$PREFIX/venv/bin/python" ]; then
    sudo -u mcpx python3 -m venv "$PREFIX/venv"
fi
sudo -u mcpx "$PREFIX/venv/bin/pip" install --quiet --upgrade pip
sudo -u mcpx "$PREFIX/venv/bin/pip" install --quiet "$SRC_DIR"

log "Audit log directory"
mkdir -p /var/log/mcpx
chown mcpx:mcpx /var/log/mcpx
if [ ! -e /var/log/mcpx/audit.jsonl ]; then
    install -o mcpx -g mcpx -m 0600 /dev/null /var/log/mcpx/audit.jsonl
fi
chattr +a /var/log/mcpx/audit.jsonl 2>/dev/null || \
    log "WARN: could not set append-only (non-ext filesystem?)"

log "Installing systemd unit + hardening drop-in"
install -m 0644 "$SRC_DIR/deploy/systemd/mcpx.service" /etc/systemd/system/mcpx.service
mkdir -p /etc/systemd/system/mcpx.service.d
install -m 0644 "$SRC_DIR/deploy/systemd/mcpx.service.d/hardening.conf" \
        /etc/systemd/system/mcpx.service.d/hardening.conf
systemctl daemon-reload

log "Installing logrotate config"
install -m 0644 "$SRC_DIR/deploy/logrotate/mcpx" /etc/logrotate.d/mcpx

mkdir -p /etc/mcpx
[ -e /etc/mcpx/mcpx.env ] || {
    install -m 0640 -o root -g mcpx "$SRC_DIR/.env.example" /etc/mcpx/mcpx.env
    log "Wrote /etc/mcpx/mcpx.env from .env.example - EDIT IT before starting"
}

log "Done. Review /etc/mcpx/mcpx.env and the unit, then:"
log "  systemctl enable --now mcpx"
log "  (HTTP transport: put deploy/Caddyfile in front; restrict the CIDRs)"
