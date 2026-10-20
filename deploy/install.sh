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

# Refuse an unsupported/missing profile before changing accounts or installation state.
INSTALL_PYTHON=python3
PROBE_PYTHON=(python3)
if [ -x "$PREFIX/venv/bin/python" ]; then
    INSTALL_PYTHON="$PREFIX/venv/bin/python"
    # The existing interpreter is service-owned and must never execute as root.
    PROBE_PYTHON=(sudo -u relay-shell "$INSTALL_PYTHON")
fi
PYTHON_PROFILE=$("${PROBE_PYTHON[@]}" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
case "$PYTHON_PROFILE" in
    3.12|3.13|3.14) ;;
    *) die "no qualified dependency lock for Python $PYTHON_PROFILE" ;;
esac
RUNTIME_LOCK="$SRC_DIR/requirements/runtime-py$PYTHON_PROFILE.txt"
[ -r "$RUNTIME_LOCK" ] || die "runtime dependency lock missing"
[ -r "$SRC_DIR/requirements-build.txt" ] || die "build tooling lock missing"

log "Ensuring service account 'relay-shell'"
if ! id relay-shell >/dev/null 2>&1; then
    useradd --system --create-home --home-dir "$PREFIX" \
            --shell /usr/sbin/nologin relay-shell
fi

log "Creating venv at $PREFIX/venv"
if [ ! -x "$PREFIX/venv/bin/python" ]; then
    sudo -u relay-shell python3 -m venv "$PREFIX/venv"
fi
# Build with locked tooling in an owned disposable environment, not in the runtime.
BUILD_DIR=$(sudo -u relay-shell mktemp -d "$PREFIX/.build-XXXXXXXX")
trap 'sudo -u relay-shell rm -rf -- "$BUILD_DIR"' EXIT
sudo -u relay-shell "$INSTALL_PYTHON" -m venv "$BUILD_DIR/venv"
sudo -u relay-shell "$BUILD_DIR/venv/bin/python" -m pip install --quiet \
    --only-binary=:all: --require-hashes -r "$SRC_DIR/requirements-build.txt"
sudo -u relay-shell "$BUILD_DIR/venv/bin/python" -m build --wheel --no-isolation \
    --outdir "$BUILD_DIR/dist" "$SRC_DIR"
shopt -s nullglob
wheels=("$BUILD_DIR"/dist/*.whl)
[ "${#wheels[@]}" -eq 1 ] || die "expected one locally built wheel"
sudo -u relay-shell "$PREFIX/venv/bin/python" -m pip install --quiet \
    --only-binary=:all: --require-hashes -r "$RUNTIME_LOCK"
sudo -u relay-shell "$PREFIX/venv/bin/python" -m pip install --quiet \
    --no-index --no-deps --force-reinstall "${wheels[0]}"
sudo -u relay-shell "$PREFIX/venv/bin/python" -m pip check

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
