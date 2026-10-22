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
#                                  tool traffic (defaults to
#                                  loopback only, which blocks remote clients)
#
# Optional:
#   RELAY_SHELL_EDGE_UPSTREAM      loopback upstream (default 127.0.0.1:8080)
#   RELAY_SHELL_EDGE_ACME_CA       ACME directory override (e.g. LE staging)
#   RELAY_SHELL_EDGE_OPEN_FIREWALL set to 1 to open 80/443 via ufw if present
#   RELAY_SHELL_EDGE_DRY_RUN       set to 1 to print the parameterized
#                                  Caddyfile template and exit
#   RELAY_SHELL_EDGE_VALIDATE_ONLY set to 1 to check the values above and
#                                  exit (needs no root)
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

# Parse a systemd-style EnvironmentFile without executing it (unlike `source`),
# so spaces, shell metacharacters or unbalanced quotes in values cannot crash or
# hijack the installer. Only RELAY_SHELL_EDGE_* keys are exported.
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
        # Explicitly exported values take precedence over the operator file.
        # This also keeps validate-only invocations independent of host defaults.
        # Check for *set*, not non-empty, so an explicitly empty value is
        # rejected by validation rather than silently replaced.
        if [ "${!key+x}" = x ]; then
            continue
        fi
        # Reject control characters and embedded newlines (the latter cannot
        # appear in a single read line, but be explicit).
        case "$val" in
            *[$'\n\r']*) die "value for $key in $file contains a newline" ;;
        esac
        export "$key=$val"
    done < "$file"
}

load_edge_env "$OPERATOR_ENV_FILE"

[ -r "$CADDYFILE_SRC" ] || die "Caddyfile template not found at $CADDYFILE_SRC"

require_var RELAY_SHELL_EDGE_DOMAIN
require_var RELAY_SHELL_EDGE_ACME_EMAIL

: "${RELAY_SHELL_EDGE_UPSTREAM:=127.0.0.1:8080}"
: "${RELAY_SHELL_EDGE_CLIENT_CIDRS:=127.0.0.1/8 ::1}"
: "${RELAY_SHELL_EDGE_ACME_CA:=https://acme-v02.api.letsencrypt.org/directory}"

# Every value is substituted into the Caddyfile by Caddy at start ({$VAR}) and written
# to a systemd EnvironmentFile below, so a stray `}`, space, quote or newline would
# change the configuration rather than be data (A14-D6). Check each against a strict
# shape, and say which variable is wrong. Bash strings cannot hold a NUL, so the control
# character test is `[[:cntrl:]]`.
valid_port() {
    local p="$1"
    [[ "$p" =~ ^[0-9]{1,5}$ ]] && [ "$((10#$p))" -ge 1 ] && [ "$((10#$p))" -le 65535 ]
}

valid_ipv4() {
    local oct IFS=.
    [[ "$1" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || return 1
    for oct in $1; do [ "$((10#$oct))" -le 255 ] || return 1; done
}

# Count the 16-bit groups of one side of an IPv6 address (the text before or after "::").
# Prints the count; fails on an empty group, a hextet over 4 digits, or (unless allow_v4,
# which is only true for the final side) an embedded dotted IPv4 tail, which counts as two.
v6_side_groups() {
    local side="$1" allow_v4="$2" g n=0 i=0 parts IFS=:
    [ -n "$side" ] || { echo 0; return 0; }
    case "$side" in :*|*:) return 1 ;; esac
    read -ra parts <<< "$side"
    for g in "${parts[@]}"; do
        i=$((i + 1))
        if [[ "$g" =~ ^[0-9A-Fa-f]{1,4}$ ]]; then
            n=$((n + 1))
        elif [ "$allow_v4" = 1 ] && [ "$i" -eq "${#parts[@]}" ] && valid_ipv4 "$g"; then
            n=$((n + 2))
        else
            return 1
        fi
    done
    echo "$n"
}

valid_ipv6() {
    local a="$1" head tail h t
    [[ "$a" =~ ^[0-9A-Fa-f:.]+$ ]] && [[ "$a" == *:* ]] || return 1
    [[ "$a" == *:::* ]] && return 1
    if [[ "$a" == *::* ]]; then
        head="${a%%::*}"
        tail="${a#*::}"
        [[ "$tail" == *::* ]] && return 1
        h=$(v6_side_groups "$head" 0) || return 1
        t=$(v6_side_groups "$tail" 1) || return 1
        # "::" stands for at least one group of zeros.
        [ $((h + t)) -le 7 ]
    else
        h=$(v6_side_groups "$a" 1) || return 1
        [ "$h" -eq 8 ]
    fi
}

valid_cidr_token() {
    local tok="$1" addr prefix=""
    addr="${tok%%/*}"
    [ "$addr" != "$tok" ] && prefix="${tok#*/}"
    if valid_ipv4 "$addr"; then
        [ -z "$prefix" ] || { [[ "$prefix" =~ ^[0-9]{1,2}$ ]] && [ "$((10#$prefix))" -le 32 ]; }
    elif valid_ipv6 "$addr"; then
        [ -z "$prefix" ] || { [[ "$prefix" =~ ^[0-9]{1,3}$ ]] && [ "$((10#$prefix))" -le 128 ]; }
    else
        return 1
    fi
}

validate_edge_values() {
    local var tok port
    for var in RELAY_SHELL_EDGE_DOMAIN RELAY_SHELL_EDGE_ACME_EMAIL \
               RELAY_SHELL_EDGE_ACME_CA RELAY_SHELL_EDGE_UPSTREAM \
               RELAY_SHELL_EDGE_CLIENT_CIDRS; do
        case "${!var}" in
            *[[:cntrl:]]*) die "$var contains a control character" ;;
        esac
    done
    [[ "$RELAY_SHELL_EDGE_DOMAIN" =~ ^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$ ]] \
        || die "RELAY_SHELL_EDGE_DOMAIN must be a fully qualified host name (letters, digits, '-', '.')"
    [ "${#RELAY_SHELL_EDGE_DOMAIN}" -le 253 ] || die "RELAY_SHELL_EDGE_DOMAIN is longer than 253 characters"
    [[ "$RELAY_SHELL_EDGE_ACME_EMAIL" =~ ^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,63}$ ]] \
        || die "RELAY_SHELL_EDGE_ACME_EMAIL must look like user@example.org"
    [[ "$RELAY_SHELL_EDGE_ACME_CA" =~ ^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?(/[A-Za-z0-9._~/%+-]*)?$ ]] \
        || die "RELAY_SHELL_EDGE_ACME_CA must be an https:// URL without spaces, quotes or query"
    if [[ "$RELAY_SHELL_EDGE_UPSTREAM" =~ ^(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9.-]+):([0-9]+)$ ]]; then
        port="${BASH_REMATCH[2]}"
        valid_port "$port" || die "RELAY_SHELL_EDGE_UPSTREAM port must be 1-65535"
    else
        die "RELAY_SHELL_EDGE_UPSTREAM must be host:port (for example 127.0.0.1:8080)"
    fi
    [ -n "$RELAY_SHELL_EDGE_CLIENT_CIDRS" ] || die "RELAY_SHELL_EDGE_CLIENT_CIDRS must not be empty"
    for tok in $RELAY_SHELL_EDGE_CLIENT_CIDRS; do
        valid_cidr_token "$tok" \
            || die "RELAY_SHELL_EDGE_CLIENT_CIDRS entry '$tok' is not an IPv4/IPv6 address or CIDR"
        case "$tok" in
            */0) warn "client CIDR '$tok' allows every address: the CIDR gate no longer limits who can reach the MCP endpoint" ;;
        esac
    done
}

validate_edge_values

# Check the values and stop before anything needs root or touches the host. Used by the
# test-suite and by operators who want to lint their env file.
if [ "${RELAY_SHELL_EDGE_VALIDATE_ONLY:-0}" = "1" ]; then
    log "Edge values are valid"
    exit 0
fi

[ "$(id -u)" -eq 0 ] || die "must run as root"

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
        # DEP-1: the Caddy repo key is fetched over TLS but is otherwise
        # trust-on-first-use. Dearmor to a temp file and print the fingerprint;
        # if the operator pinned one via RELAY_SHELL_EDGE_CADDY_GPG_FPR, refuse
        # to install unless it matches, so a swapped key (compromised mirror,
        # MITM past TLS) is caught before apt trusts it. No default fingerprint
        # is shipped because Caddy/cloudsmith publish no canonical one; pin the
        # value you confirm at https://caddyserver.com/docs/install.
        tmp_key="$(mktemp)"
        curl -fsSL https://dl.cloudsmith.io/public/caddy/stable/gpg.key \
            | gpg --dearmor -o "$tmp_key"
        observed_fpr="$(gpg --show-keys --with-colons --with-fingerprint "$tmp_key" \
            | awk -F: '$1 == "fpr" { print $10; exit }')"
        log "Caddy repo key fingerprint: ${observed_fpr:-<unreadable>}"
        expected_fpr="$(printf '%s' "${RELAY_SHELL_EDGE_CADDY_GPG_FPR:-}" | tr -dc 'A-Fa-f0-9')"
        if [ -n "$expected_fpr" ]; then
            if [ "$(printf '%s' "$expected_fpr" | tr 'a-f' 'A-F')" != \
                 "$(printf '%s' "$observed_fpr" | tr 'a-f' 'A-F')" ]; then
                rm -f "$tmp_key"
                die "Caddy repo key fingerprint mismatch: expected $expected_fpr, got ${observed_fpr:-<unreadable>} - refusing to trust the key"
            fi
            log "Caddy repo key fingerprint matches the pinned value"
        else
            warn "Caddy repo key is unpinned (trust-on-first-use). After verifying it at https://caddyserver.com/docs/install, set RELAY_SHELL_EDGE_CADDY_GPG_FPR=${observed_fpr:-<fpr>} to pin it."
        fi
        install -m 0644 "$tmp_key" /etc/apt/keyrings/caddy-stable-archive-keyring.gpg
        rm -f "$tmp_key"
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

# The rest assumes a systemd-managed caddy.service (the official apt package
# ships one; a hand-installed binary may not). Fail early with a clear message.
if ! systemctl list-unit-files caddy.service >/dev/null 2>&1 \
        || ! systemctl list-unit-files caddy.service 2>/dev/null | grep -q '^caddy\.service'; then
    die "caddy binary is present but no caddy.service systemd unit was found.
       Install the official apt package (this script does that automatically
       when caddy is missing) or provide your own caddy.service unit before
       re-running. See https://caddyserver.com/docs/install."
fi

install -d -m 0755 /etc/caddy
install -d -m 0750 -o caddy -g caddy /var/log/caddy 2>/dev/null || install -d -m 0755 /var/log/caddy

# A marker on the first non-comment line identifies a Caddyfile this installer
# owns. Refusing to overwrite any other prevents an outage on a host that
# already serves other vhosts via Caddy.
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

# Validate the candidate BEFORE it replaces the live file: a bad value must not
# leave a broken Caddyfile behind for the next restart. `caddy validate` reads the
# same env Caddy will see at start, so export it here.
log "Validating Caddyfile syntax"
export RELAY_SHELL_EDGE_DOMAIN RELAY_SHELL_EDGE_ACME_EMAIL RELAY_SHELL_EDGE_ACME_CA \
       RELAY_SHELL_EDGE_UPSTREAM RELAY_SHELL_EDGE_CLIENT_CIDRS
if ! caddy validate --config "$CADDYFILE_DST.tmp" --adapter caddyfile; then
    rm -f "$CADDYFILE_DST.tmp"
    die "Caddyfile failed validation; $CADDYFILE_DST left untouched"
fi
if [ -e "$CADDYFILE_DST" ]; then
    cp -p "$CADDYFILE_DST" "$CADDYFILE_DST.bak"
    log "Previous Caddyfile saved as $CADDYFILE_DST.bak"
fi
mv "$CADDYFILE_DST.tmp" "$CADDYFILE_DST"

# A dedicated systemd EnvironmentFile keeps the drop-in static and avoids the
# `%`-specifier expansion systemd applies inside Environment= assignments.
#
# Quoting: systemd's EnvironmentFile parser treats whitespace in an unquoted
# value as a separator for further KEY=VALUE pairs, which would silently
# truncate RELAY_SHELL_EDGE_CLIENT_CIDRS to the first CIDR. Every value is
# emitted double-quoted with embedded double quotes escaped.
emit_env() {
    local key="$1" val="$2"
    # Escape backslashes first, then double quotes.
    val="${val//\\/\\\\}"
    val="${val//\"/\\\"}"
    printf '%s="%s"\n' "$key" "$val"
}

log "Installing edge env file at $EDGE_ENV_FILE"
# DEP-2: 0750, not world-listable. Group relay-shell (as in the main installer),
# or root:root on an edge-only host where that group was never created. systemd
# reads the EnvironmentFile as root either way.
install -d -m 0750 -o root -g relay-shell /etc/relay-shell 2>/dev/null \
    || install -d -m 0750 /etc/relay-shell
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
# Not secret but security-relevant: root-owned and group-readable by caddy (the
# drop-in's EnvironmentFile= needs it), not world-readable.
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
