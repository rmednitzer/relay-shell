#!/usr/bin/env bash
set -euo pipefail

# relay-shell installer - idempotent. Creates a dedicated service account and venv,
# installs the package, and lays down the systemd/logrotate assets. It does
# NOT enable or start the service: review the unit and configuration first.
#
# Location: deploy/install.sh   Run as: root (sudo)

SCRIPT_NAME="$(basename "$0")"
PREFIX="/var/lib/relay-shell"
SRC_DIR="$(cd "$(dirname "$0")/.." && pwd)"

log() { echo "[$(date -Iseconds)] [$SCRIPT_NAME] $*"; }
die() { log "FATAL: $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "must run as root"

# Install a managed file. If the target exists and differs from the shipped template (a
# local edit, or an older release), keep one copy of it first so an upgrade never destroys
# an operator's change silently (A14-D15). The copy lives outside the directories that
# systemd and logrotate scan, so a stale copy is never read as configuration.
BACKUP_DIR="${RELAY_SHELL_INSTALL_BACKUP_DIR:-$PREFIX/preinstall-backups}"
install_managed() {
    local mode="$1" src="$2" dst="$3" saved
    if [ -e "$dst" ] && ! cmp -s "$src" "$dst"; then
        install -d -m 0700 "$BACKUP_DIR"
        saved="$BACKUP_DIR/$(printf '%s' "$dst" | tr '/' '_').$(date +%Y%m%dT%H%M%S)"
        cp -p "$dst" "$saved"
        log "WARN: $dst differs from the shipped template; previous copy saved as $saved"
    fi
    install -m "$mode" "$src" "$dst"
}

log "Ensuring service account 'relay-shell'"
if ! id relay-shell >/dev/null 2>&1; then
    useradd --system --create-home --home-dir "$PREFIX" \
            --shell /usr/sbin/nologin relay-shell
fi

log "Creating venv at $PREFIX/venv"
if [ ! -x "$PREFIX/venv/bin/python" ]; then
    sudo -u relay-shell python3 -m venv "$PREFIX/venv"
fi
sudo -u relay-shell "$PREFIX/venv/bin/pip" install --quiet --upgrade pip
# Install against the tested direct pins when the checkout carries them (A14-D14).
if [ -r "$SRC_DIR/requirements.txt" ]; then
    sudo -u relay-shell "$PREFIX/venv/bin/pip" install --quiet -c "$SRC_DIR/requirements.txt" "$SRC_DIR"
else
    sudo -u relay-shell "$PREFIX/venv/bin/pip" install --quiet "$SRC_DIR"
fi

log "Audit log directory"
mkdir -p /var/log/relay-shell
chown relay-shell:relay-shell /var/log/relay-shell
if [ ! -e /var/log/relay-shell/audit.jsonl ]; then
    install -o relay-shell -g relay-shell -m 0600 /dev/null /var/log/relay-shell/audit.jsonl
fi
chattr +a /var/log/relay-shell/audit.jsonl 2>/dev/null || \
    log "WARN: could not set append-only (non-ext filesystem?)"

log "Installing systemd unit + hardening drop-in"
install_managed 0644 "$SRC_DIR/deploy/systemd/relay-shell.service" /etc/systemd/system/relay-shell.service
mkdir -p /etc/systemd/system/relay-shell.service.d
install_managed 0644 "$SRC_DIR/deploy/systemd/relay-shell.service.d/hardening.conf" \
        /etc/systemd/system/relay-shell.service.d/hardening.conf
systemctl daemon-reload

log "Installing logrotate config"
install_managed 0644 "$SRC_DIR/deploy/logrotate/relay-shell" /etc/logrotate.d/relay-shell

# DEP-2: 0750 root:relay-shell, not world-listable 0755: the env files hold
# deployment config. systemd reads the EnvironmentFile as root, so the service
# is unaffected.
install -d -m 0750 -o root -g relay-shell /etc/relay-shell
[ -e /etc/relay-shell/relay-shell.env ] || {
    install -m 0640 -o root -g relay-shell "$SRC_DIR/.env.example" /etc/relay-shell/relay-shell.env
    log "Wrote /etc/relay-shell/relay-shell.env from .env.example - EDIT IT before starting"
}

log "Done. Review /etc/relay-shell/relay-shell.env and the unit, then:"
log "  systemctl enable --now relay-shell"
log "  (HTTP transport: put deploy/Caddyfile in front; restrict the CIDRs)"
