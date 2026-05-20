# Deployment

`relay-shell` grants real administrative power. The single most important control is
**where and as whom it runs**. This guide describes a production-grade
deployment modeled on a mature MCP gateway.

## 1. Service account

Default recommendation: run as a dedicated unprivileged user, never a human's account.

```bash
sudo useradd --system --create-home --home-dir /var/lib/relay-shell \
     --shell /usr/sbin/nologin relay-shell
```

Grant only the privileges the workload genuinely needs. If `sudo` is required
for the intended tasks, prefer **command-scoped** sudoers entries over
`NOPASSWD: ALL`. A single-owner lab host may accept a broader grant; a
multi-tenant or sensitive host must not. State the choice in an ADR.

If your explicit goal is maximum model capability (full root/sudo behavior),
run the service in **privileged posture** on an isolated admin host and treat
that host as a high-trust control plane.

## 2. Install

```bash
sudo -u relay-shell python3 -m venv /var/lib/relay-shell/venv
sudo -u relay-shell /var/lib/relay-shell/venv/bin/pip install --upgrade pip
sudo -u relay-shell /var/lib/relay-shell/venv/bin/pip install /path/to/relay-shell   # or: pip install relay-shell
```

`deploy/install.sh` does this idempotently. It deliberately does **not**
auto-start the service; review the unit and configuration first.

## 3. systemd

`deploy/systemd/relay-shell.service` plus the `relay-shell.service.d/hardening.conf`
drop-in. The hardening is intentionally **partial**: filesystem, capability,
and syscall confinement (`ProtectSystem=strict`, `NoNewPrivileges`,
`SystemCallFilter`) would break the very shell/SSH capability this service
exists to provide (see `docs/adr/0002`). What is applied: resource caps
(`MemoryMax`, `CPUQuota`, `TasksMax`), `PrivateTmp`, restart limits, and the
non-execution-breaking `Protect*` directives. Encrypted credentials are
delivered via `LoadCredentialEncrypted=`.

```bash
sudo cp deploy/systemd/relay-shell.service /etc/systemd/system/
sudo mkdir -p /etc/systemd/system/relay-shell.service.d
sudo cp deploy/systemd/relay-shell.service.d/hardening.conf /etc/systemd/system/relay-shell.service.d/
sudo systemctl daemon-reload
sudo systemctl enable --now relay-shell
```

## 4. Network edge (HTTP transport)

The HTTP transport binds `127.0.0.1` by design. Terminate TLS and restrict by
source IP at a reverse proxy. `deploy/Caddyfile` is shipped parameterized
through environment variables and provides:

- automatic TLS via ACME (Let's Encrypt by default, ZeroSSL fallback),
- an `@blocked` matcher that 403s any source outside the allowlisted CIDRs,
- HSTS / `X-Content-Type-Options` / `X-Frame-Options` / `Referrer-Policy`,
- `reverse_proxy` to the loopback MCP port.

Set the allowlist to the CIDRs of your MCP client only. The OAuth browser
endpoints (`/authorize`, `/.well-known/*`) are reachable for the redirect
flow; tool traffic and `/token` are CIDR-restricted.

Defense in depth: a host firewall (only 80/443 inbound), the proxy CIDR
matcher, OAuth 2.1, then the policy/audit layer.

### 4a. Automated TLS (Caddy + Let's Encrypt)

`deploy/install-edge.sh` is the supported turnkey path. It installs Caddy
from the official apt repository (if missing), drops the parameterized
Caddyfile in place, writes a systemd environment drop-in, validates the
config, and starts the service. Renewal is driven by Caddy's built-in ACME
scheduler - **no cron, no certbot**.

Prerequisites: a public DNS A/AAAA record for the chosen hostname pointing
at this host, and TCP/80 + TCP/443 reachable from the internet (port 80 is
required for the HTTP-01 challenge).

```bash
# Edit /etc/relay-shell/relay-shell.env (or export inline) and set at minimum:
#   RELAY_SHELL_EDGE_DOMAIN=relay-shell.example.org
#   RELAY_SHELL_EDGE_ACME_EMAIL=admin@example.org
#   RELAY_SHELL_EDGE_CLIENT_CIDRS="203.0.113.0/24 198.51.100.0/24"
sudo deploy/install-edge.sh
```

| Variable | Purpose |
|---|---|
| `RELAY_SHELL_EDGE_DOMAIN` | Public hostname presented in the TLS certificate. |
| `RELAY_SHELL_EDGE_ACME_EMAIL` | Contact email for the ACME account. |
| `RELAY_SHELL_EDGE_CLIENT_CIDRS` | Space-separated source CIDR allowlist (defaults to loopback only - remote clients get 403 until you set this). |
| `RELAY_SHELL_EDGE_UPSTREAM` | Loopback target (default `127.0.0.1:8080`). |
| `RELAY_SHELL_EDGE_ACME_CA` | ACME directory override; set to `https://acme-staging-v02.api.letsencrypt.org/directory` for dry runs against LE staging. |
| `RELAY_SHELL_EDGE_OPEN_FIREWALL` | Set to `1` to `ufw allow 80,443/tcp` if `ufw` is present. |
| `RELAY_SHELL_EDGE_DRY_RUN` | Set to `1` to log the resolved values and print the parameterized Caddyfile template, then exit without installing. Caddy substitutes the `{$RELAY_SHELL_EDGE_*}` placeholders at service start. |
| `RELAY_SHELL_EDGE_FORCE` | Set to `1` to overwrite an existing `/etc/caddy/Caddyfile` that this installer did not write. Without it, the installer refuses to clobber a Caddyfile that may serve other sites on the host. |

The installer is idempotent: re-run it after editing the env file to push
changes. The drop-in at
`/etc/systemd/system/caddy.service.d/relay-shell-edge.conf` is static and
references a managed `EnvironmentFile=/etc/relay-shell/relay-shell-edge.env`,
so user-supplied values never land inside systemd unit syntax. Cert state
persists under Caddy's data directory across restarts. See
[`docs/adr/0004-edge-tls-automation.md`](adr/0004-edge-tls-automation.md)
for the design rationale and rejected alternatives.

Operators running a non-Caddy edge (nginx, HAProxy, an upstream LB with
its own ACME integration) can still use the relay-shell service; the
loopback-bind contract and CIDR/header expectations described above are
all that matter.

## 5. OAuth 2.1 (optional)

```bash
RELAY_SHELL_TRANSPORT=http
RELAY_SHELL_AUTH_ENABLED=true
RELAY_SHELL_AUTH_ISSUER=https://relay-shell.example.org
RELAY_SHELL_AUTH_STATE_DIR=/var/lib/relay-shell/oauth
RELAY_SHELL_AUTH_SINGLE_CLIENT=true       # lock DCR after the first client registers
```

Install the `[http]` extra. Tokens are file-backed under the state dir
(`clients.json`, `codes.json`, `tokens.json`), access tokens are short-lived,
refresh tokens rotate on use, and expiry is enforced lazily on read. With
single-client lockdown, dynamic registration is refused once one client
exists.

## 6. Audit

`RELAY_SHELL_AUDIT_PATH` (default `/var/log/relay-shell/audit.jsonl`). Make it append-only
and rotate it without losing that attribute:

```bash
sudo mkdir -p /var/log/relay-shell && sudo chown relay-shell:relay-shell /var/log/relay-shell
sudo touch /var/log/relay-shell/audit.jsonl && sudo chattr +a /var/log/relay-shell/audit.jsonl
sudo cp deploy/logrotate/relay-shell /etc/logrotate.d/relay-shell
```

The bundled logrotate config drops the append-only bit only for the rotate
and restores it immediately. **Ship the log off-host** and alert on gaps; an
on-host log is evidence only until the host is compromised.

## 7. SSH credential scoping

The realized credential surface is whatever keys the service account can use.
Prefer one key per role/scope, revocable independently, over one all-powerful
key. `RELAY_SHELL_SSH_KNOWN_HOSTS=strict` is recommended for production; pre-populate
`~/.ssh/known_hosts` for the service account. Provide a JSON inventory via
`RELAY_SHELL_INVENTORY` for hosts not in `ssh_config`.

## 8. Policy posture

- `open` - full access, every call still classified and audited. The
  documented single-owner default.
- `guarded` - Tier 2+ refused unless `RELAY_SHELL_POLICY_ALLOW` matches; set an
  allowlist of sanctioned change patterns.
- `readonly` - only Tier 0. Useful for an observation-only client.

`RELAY_SHELL_POLICY_DENY` is enforced first in **every** mode; use it for absolute
prohibitions regardless of posture.

## 9. Health

`scripts/healthcheck.sh` checks the local HTTP port. For stdio, liveness is
the supervising client's concern. `server_info` reports effective limits and
whether the audit sink is degraded (a degraded audit sink is an alert).

## Emergency

- Disable fast: `sudo systemctl stop relay-shell` (and revoke OAuth tokens by
  clearing `tokens.json`, or rotate the proxy CIDR allowlist to none).
- Revoke SSH reach: remove/disable the service account's keys on targets.
- The audit log (off-host copy) is the post-incident record.
