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
#   RELAY_SHELL_EDGE_DRY_RUN       set to 1 to print the parameterized
#                                  Caddyfile template and exit
#   RELAY_SHELL_EDGE_FORCE         set to 1 to overwrite an existing
#                                  /etc/caddy/Caddyfile that this installer
#                                  did not place (back it up first!)
#
# Location: deploy/install-edge.sh  Run as: root (sudo)

SCRIPT_NAME="$(basename "$0")"
SRC_DIR="$(cd "$(dirname "$0")" && pwd)"
CADDYFILE_SRC="$SRC_DIR/Caddyfile"
CADDYFILE_DST="/etc/caddy/Caddyfile"
ENV_DROPIN_DIR="/etc/systemd/system/caddy.service.d"
ENV_DROPIN="$ENV_DROPIN_DIR/relay-shell-edge.conf"
EDGE_ENV_FILE="/etc/relay-shell/relay-shell-edge.env"
OPERATOR_ENV_FILE="/etc/relay-shell/relay-shell.env"

log()  { echo "[$(date -Iseconds)] [$SCRIPT_NAME] $*"; }
warn() { log "WARN: $*" >&2; }
die()  { log "FATAL: $*" >&2; exit 1; }

require_var() {
    local name="$1"
    local val="${!name:-}"
    [ -n "$val" ] || die "$name is required (export it before running, or set it in $OPERATOR_ENV_FILE)"
}

# Parse a systemd-style EnvironmentFile safely. Unlike `source`, this does
# not execute the file, so values containing spaces, shell metacharacters,
# or unbalanced quotes cannot crash or hijack the installer. Only keys
# matching RELAY_SHELL_EDGE_* are exported.
load_edge_env() {
    local file="$1" line key val
    [ -r "$file" ] || return 0
    while IFS= read -r line || [ -n "$line" ]; do
        case "$line" in
            ''|\#*) continue ;;
        esac
        line="${line#export }"
        case "$line" in
            *=*) ;;
            *) continue ;;
        esac
        key="${line%%=*}"
        val="${line#*=}"
        case "$key" in
            RELAY_SHELL_EDGE_*) ;;
            *) continue ;;
        esac
        # Strip a single pair of surrounding double or single quotes if
        # present (systemd permits, but does not require, them).
        case "$val" in
            \"*\") val="${val#\"}"; val="${val%\"}" ;;
            \'*\') val="${val#\'}"; val="${val%\'}" ;;
        esac
        # Reject control characters and embedded newlines (the latter cannot
        # appear in a single read line, but be explicit).
        case "$val" in
            *[$'\n\r']*) die "value for $key in $file contains a newline" ;;
        esac
        export "$key=$val"
    done < "$file"
}

load_edge_env "$OPERATOR_ENV_FILE"

[ "$(id -u)" -eq 0 ] || die "must run as root"
[ -r "$CADDYFILE_SRC" ] || die "Caddyfile template not found at $CADDYFILE_SRC"

require_var RELAY_SHELL_EDGE_DOMAIN
require_var RELAY_SHELL_EDGE_ACME_EMAIL

: "${RELAY_SHELL_EDGE_UPSTREAM:=127.0.0.1:8080}"
: "${RELAY_SHELL_EDGE_CLIENT_CIDRS:=127.0.0.1/8 ::1}"
: "${RELAY_SHELL_EDGE_ACME_CA:=https://acme-v02.api.letsencrypt.org/directory}"

# Reject any value containing characters that would corrupt the systemd
# EnvironmentFile we write below (newlines were caught above; reject NULs
# and stray quotes that would unbalance the file).
for var in RELAY_SHELL_EDGE_DOMAIN RELAY_SHELL_EDGE_ACME_EMAIL \
           RELAY_SHELL_EDGE_ACME_CA RELAY_SHELL_EDGE_UPSTREAM \
           RELAY_SHELL_EDGE_CLIENT_CIDRS; do
    case "${!var}" in
        *[$'\n\r\0']*) die "$var contains a control character" ;;
    esac
done

log "Edge domain : $RELAY_SHELL_EDGE_DOMAIN"
log "ACME email  : $RELAY_SHELL_EDGE_ACME_EMAIL"
log "ACME CA     : $RELAY_SHELL_EDGE_ACME_CA"
log "Upstream    : $RELAY_SHELL_EDGE_UPSTREAM"
log "Client CIDRs: $RELAY_SHELL_EDGE_CLIENT_CIDRS"

if [ "${RELAY_SHELL_EDGE_CLIENT_CIDRS}" = "127.0.0.1/8 ::1" ]; then
    warn "client CIDR allowlist is loopback only - remote clients will be 403'd until you set RELAY_SHELL_EDGE_CLIENT_CIDRS"
fi

if [ "${RELAY_SHELL_EDGE_DRY_RUN:-0}" = "1" ]; then
    log "Dry run - printing the parameterized Caddyfile template below."
    log "Caddy substitutes {\$RELAY_SHELL_EDGE_*} at service start using the values logged above."
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

# The rest of the installer assumes a systemd-managed caddy.service (the
# official apt package ships one). A binary installed by hand may not. Bail
# out early with an actionable message instead of failing inside `systemctl`.
if ! systemctl list-unit-files caddy.service >/dev/null 2>&1 \
        || ! systemctl list-unit-files caddy.service 2>/dev/null | grep -q '^caddy\.service'; then
    die "caddy binary is present but no caddy.service systemd unit was found.
       Install the official apt package (this script does that automatically
       when caddy is missing) or provide your own caddy.service unit before
       re-running. See https://caddyserver.com/docs/install."
fi

install -d -m 0755 /etc/caddy
install -d -m 0750 -o caddy -g caddy /var/log/caddy 2>/dev/null || install -d -m 0755 /var/log/caddy

# A magic marker on the first non-comment line lets us recognize a Caddyfile
# this installer owns vs. one a human (or another tool) has placed there for
# unrelated sites. Refusing to clobber the latter prevents an outage when
# this is run on a host that already serves other vhosts via Caddy.
MANAGED_MARKER="# relay-shell:install-edge:managed"
RELAY_SHELL_EDGE_FORCE="${RELAY_SHELL_EDGE_FORCE:-0}"

if [ -e "$CADDYFILE_DST" ] && [ "$RELAY_SHELL_EDGE_FORCE" != "1" ]; then
    if ! head -n 5 "$CADDYFILE_DST" | grep -qF "$MANAGED_MARKER"; then
        die "$CADDYFILE_DST exists and was not written by this installer.
       Refusing to overwrite a Caddyfile that may serve other sites.
       Options:
         - merge the contents of $CADDYFILE_SRC into $CADDYFILE_DST by hand
           (it is a single site block scoped to \$RELAY_SHELL_EDGE_DOMAIN), or
         - back up the existing file and re-run with RELAY_SHELL_EDGE_FORCE=1
           to replace it."
    fi
fi

log "Installing $CADDYFILE_DST"
# Prepend the ownership marker so a future run recognizes its own file.
{
    echo "$MANAGED_MARKER"
    cat "$CADDYFILE_SRC"
} > "$CADDYFILE_DST.tmp"
chmod 0644 "$CADDYFILE_DST.tmp"
mv "$CADDYFILE_DST.tmp" "$CADDYFILE_DST"

# Write a dedicated systemd EnvironmentFile rather than inlining values into
# the drop-in. Keeps the drop-in static and avoids `%`-specifier expansion
# that systemd applies inside Environment= assignments.
#
# Note on quoting: systemd's EnvironmentFile parser treats whitespace inside
# an unquoted value as a separator for additional KEY=VALUE pairs on the
# same line, which would silently truncate RELAY_SHELL_EDGE_CLIENT_CIDRS to
# the first CIDR. Emit every value double-quoted, with embedded double
# quotes escaped, so multi-token values survive intact.
emit_env() {
    local key="$1" val="$2"
    # Escape backslashes first, then double quotes.
    val="${val//\\/\\\\}"
    val="${val//\"/\\\"}"
    printf '%s="%s"\n' "$key" "$val"
}

log "Installing edge env file at $EDGE_ENV_FILE"
install -d -m 0755 /etc/relay-shell
umask 077
{
    echo "# Managed by relay-shell deploy/install-edge.sh - do not hand-edit."
    echo "# Update $OPERATOR_ENV_FILE and re-run the installer instead."
    emit_env RELAY_SHELL_EDGE_DOMAIN       "$RELAY_SHELL_EDGE_DOMAIN"
    emit_env RELAY_SHELL_EDGE_ACME_EMAIL   "$RELAY_SHELL_EDGE_ACME_EMAIL"
    emit_env RELAY_SHELL_EDGE_ACME_CA      "$RELAY_SHELL_EDGE_ACME_CA"
    emit_env RELAY_SHELL_EDGE_UPSTREAM     "$RELAY_SHELL_EDGE_UPSTREAM"
    emit_env RELAY_SHELL_EDGE_CLIENT_CIDRS "$RELAY_SHELL_EDGE_CLIENT_CIDRS"
} > "$EDGE_ENV_FILE"
# Not secret, but still security-relevant edge configuration: keep it
# root-owned and group-readable by caddy (which needs to read it for the
# drop-in's EnvironmentFile=), not world-readable.
if getent group caddy >/dev/null 2>&1; then
    chown root:caddy "$EDGE_ENV_FILE"
    chmod 0640 "$EDGE_ENV_FILE"
else
    chmod 0600 "$EDGE_ENV_FILE"
    warn "no 'caddy' group found; $EDGE_ENV_FILE is root-only - caddy may fail to read it"
fi
umask 022

log "Installing systemd environment drop-in at $ENV_DROPIN"
install -d -m 0755 "$ENV_DROPIN_DIR"
cat >"$ENV_DROPIN" <<EOF
# Managed by relay-shell deploy/install-edge.sh.
# Values live in $EDGE_ENV_FILE so unit syntax is not affected by user input.
[Service]
EnvironmentFile=$EDGE_ENV_FILE
EOF
chmod 0644 "$ENV_DROPIN"

log "Validating Caddyfile syntax"
# `caddy validate` reads the same env Caddy will see at start, so export here.
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
