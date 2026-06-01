# Deployment

`relay-shell` grants real administrative power. The single most important control is
**where and as whom it runs**. This guide describes a production-grade
deployment modeled on a mature MCP gateway.

## 0. Pre-flight checklist

Run through this list before §1 (service account creation). Each row is a
hard precondition for the matching later section; skipping any of them
turns a smooth install into an outage.

- [ ] **Service account name decided.** The default is `relay-shell`
      with home directory `/var/lib/relay-shell` (§1). Pick a different
      name only if your host conventions require it; update the systemd
      unit + logrotate config + `chown` lines below accordingly.
- [ ] **Audit directory writable by the service account.**
      `/var/log/relay-shell/` exists, is owned by the service account,
      and the filesystem supports `chattr +a` (ext2/3/4, xfs).
      Append-only on a `tmpfs` or fuse mount silently degrades to a
      normal write — confirm `lsattr` after `chattr +a`.
- [ ] **DNS resolves for the edge domain** (HTTP transport only).
      `dig +short ${RELAY_SHELL_EDGE_DOMAIN}` returns the host's public
      IP. The HTTP-01 ACME challenge does not work without this.
- [ ] **Ports 80 and 443 reachable from the internet** (HTTP transport
      only). Port 80 is required for HTTP-01; closing it blocks
      issuance and renewal both. If a host firewall is in front, open
      it before running `install-edge.sh` (or set
      `RELAY_SHELL_EDGE_OPEN_FIREWALL=1` to have the installer try).
- [ ] **SSH service account keypair generated** (`ssh-keygen -t ed25519`
      as the service account) and `known_hosts` strategy chosen
      (`strict` for production — pre-populate with `ssh-keyscan`; see
      §7).
- [ ] **Off-host audit shipping target ready** (Vector / Fluent Bit /
      journal-remote — see `docs/audit-shipper.md`). An on-host audit
      file is evidence only until the host is compromised; the
      shipper must be in place *before* the unit is enabled in
      production.

If any row is unchecked, fix it before continuing — the install is
idempotent but recovery from a half-configured edge or a non-shipping
audit log is more work than the precondition.

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

Validate the resolved configuration against the service account's
environment before enabling the unit:

```bash
sudo -u relay-shell \
  --preserve-env=RELAY_SHELL_AUDIT_PATH,RELAY_SHELL_TRANSPORT,RELAY_SHELL_POLICY_MODE \
  /var/lib/relay-shell/venv/bin/relay-shell --check-config
```

`--check-config` loads the settings, builds the server (audit sink open,
ssh_config + inventory parse, OAuth state dir creation if `auth_enabled=true`)
without starting a transport, and exits 0 on success or 2 on any
initialization failure - including a degraded audit sink, which is the
single most common production misconfiguration. Wire this into the
image-bake step of your CI pipeline.

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

`RELAY_SHELL_AUDIT_FORMAT` controls serialization for downstream SIEM ingest:
`jsonl` (default), `cef`, or `leef`.

The bundled logrotate config drops the append-only bit only for the rotate
and restores it immediately. **Ship the log off-host** and alert on gaps; an
on-host log is evidence only until the host is compromised. See
[`docs/audit-shipper.md`](audit-shipper.md) for worked examples using
Vector, Fluent Bit, and `journalctl` → `systemd-journal-remote`.

### 6a. Tamper-evident chain (optional)

`chattr +a` and off-host shipping protect the log, but neither makes a
*single altered record* detectable, and the shipper has a flush window. Set
`RELAY_SHELL_AUDIT_CHAIN=true` (requires `AUDIT_FORMAT=jsonl`) to add a
per-record hash chain ([ADR 0007](adr/0007-audit-hash-chain.md)): each record
carries `seq`, the previous record's `prev` hash, and its own `chain` hash, so
any edit, insertion, deletion, or reorder is detectable by recomputation —
including from the shipped copy, without trusting the relay host. Default off
keeps the record byte-identical; `server_info.audit.chain` reports the live
state.

Enable it on a **freshly rotated** log so the chain runs from genesis with no
leading legacy prefix. Verify the on-host log or a shipped copy:

```bash
relay-shell --verify-audit                         # uses RELAY_SHELL_AUDIT_PATH
relay-shell --verify-audit --audit-path /path/to/shipped.jsonl --json
# exit 0 = chain intact; exit 2 = a record was inserted / deleted / edited.
```

The chain is rotation-safe: the in-memory anchor carries it into the new file,
so cross-rotation continuity is the prior file's last `chain` equalling the new
file's first `prev` (printed as the verifier's start anchor). A restart that
cannot read the tail starts a fresh chain at genesis — a visible `seq`-reset
seam the verifier surfaces, never a silent gap.

## 7. SSH credential scoping

The realized credential surface is whatever keys the service account can use.
Prefer one key per role/scope, revocable independently, over one all-powerful
key. `RELAY_SHELL_SSH_KNOWN_HOSTS=strict` is recommended for production; pre-populate
`~/.ssh/known_hosts` for the service account. Provide a JSON inventory via
`RELAY_SHELL_INVENTORY` for hosts not in `ssh_config`.

The SSH connection pool caches one connection per `user@host:port` and
reuses it for follow-up calls. `RELAY_SHELL_SSH_IDLE_TIMEOUT` (default
1800 seconds) drops a cached connection that has not been used for that
many seconds the next time the pool is consulted; set `0` to keep the
historical behavior (closed connections are still purged on the next
sweep). Long-running deployments that fan out across a large host
inventory should leave the reaper on so a long-lived server does not
accumulate idle handles.

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
The end-to-end HTTP smoke (start the transport, hit
`/.well-known/oauth-protected-resource`, stop it) is documented in
[`runbook.md`](runbook.md) §4.6.

### 9a. Prometheus metrics

The HTTP transport exposes a `GET /metrics` endpoint in Prometheus text
exposition format (no auth - the route bypasses OAuth by design, scope it
via the Caddy CIDR allowlist). The audit log remains the source of truth
for what happened; metrics are for dashboards only and reset on restart.

| metric                              | type    | meaning                                                             |
|-------------------------------------|---------|---------------------------------------------------------------------|
| `relay_shell_tool_calls_total`      | counter | One per tool call. Labels: `tool`, `tier`, `mode`, `outcome`.       |
| `relay_shell_active_sessions`       | gauge   | Live local + SSH PTY sessions.                                      |
| `relay_shell_active_forwards`       | gauge   | Live SSH port forwards.                                             |
| `relay_shell_audit_degraded`        | gauge   | 1 if the audit sink is degraded, 0 otherwise. Should always be 0.   |

`outcome` is one of `ok` (work returned), `denied` (policy refused), or
`error` (work raised). Combine `mode + tier + outcome` for the classic
"denied tier-3 calls per minute" panel.

The stdio transport does not expose `/metrics`; the route is gated on
`RELAY_SHELL_TRANSPORT=http`.

## 10. Drift detection

After install, and on a periodic schedule in production, run:

```bash
/var/lib/relay-shell/venv/bin/relay-shell --verify-deploy
```

It compares each shipped template against the file the installer placed:

| name              | install path                                             |
|-------------------|----------------------------------------------------------|
| systemd-unit      | `/etc/systemd/system/relay-shell.service`                |
| systemd-hardening | `/etc/systemd/system/relay-shell.service.d/hardening.conf` |
| logrotate         | `/etc/logrotate.d/relay-shell`                           |
| caddyfile         | `/etc/caddy/Caddyfile` (marker line is stripped)         |

Exit 0 means every entry matched byte-for-byte; exit 2 means at least one
`DRIFT`, `MISSING`, or `ABSENT_TEMPLATE` row was reported. Pair with
`--json` for machine-readable output (Nagios / Prometheus blackbox /
Ansible drift-detection callouts). A cron line like:

```cron
17 4 * * * relay-shell /var/lib/relay-shell/venv/bin/relay-shell --verify-deploy --json > /var/log/relay-shell/drift.json
```

…lets a log shipper trip an alert when `ok: false` lands in the JSON.

## 11. Backup and restore

The relay's persistent state is small and lives in three directories.
Back them up together; the relay itself is stateless beyond these:

| What                                                            | Where                                                                                         | Why it matters                                                                              |
|-----------------------------------------------------------------|-----------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------|
| OAuth state                                                     | `${RELAY_SHELL_AUTH_STATE_DIR}/{clients.json, codes.json, tokens.json}` (default `/var/lib/relay-shell/oauth/`) | Losing it logs every client out and re-runs single-client lockdown from scratch (a new client can register, the old one cannot). |
| systemd EnvironmentFile                                         | `/etc/relay-shell/relay-shell.env` (plus `/etc/relay-shell/relay-shell-edge.env` for the edge) | Source of truth for every `RELAY_SHELL_*` knob; recreating it from scratch is error-prone.  |
| Audit log                                                       | `${RELAY_SHELL_AUDIT_PATH}` (default `/var/log/relay-shell/audit.jsonl`) plus `audit.jsonl.{1..N}.gz` rotations | The on-host copy is the local fallback when the off-host shipper has fallen behind.        |

A simple recipe (adapt to your backup tool):

```bash
backup_dir=/root/relay-shell-backups
sudo install -d -m 700 "$backup_dir"
sudo install -m 600 /dev/null "$backup_dir/relay-shell-state-$(date +%F).tar.gz"
sudo tar -czf "$backup_dir/relay-shell-state-$(date +%F).tar.gz" \
  /etc/relay-shell \
  /var/lib/relay-shell/oauth \
  /var/log/relay-shell
```

The `install` steps intentionally create a root-only destination
(directory `0700`, archive `0600`) before `tar` writes sensitive OAuth
state and environment material.

Restore the OAuth state with `chmod 0700 oauth/ && chmod 0600 oauth/*.json`
preserved (the file modes are part of the trust boundary — the relay
re-applies them on next write, but an attacker reading between restore
and first write should not see 0644 files). The audit log is append-only
on disk; restore it *before* the relay starts so `chattr +a` does not
race with a write into the unmoved file. The drift-detection CLI
(`relay-shell --verify-deploy`, §10) confirms the systemd unit + Caddyfile
+ logrotate config match the templates after a restore.

What is **not** in scope for backup:

- The Python venv under `/var/lib/relay-shell/venv/` — recreate with
  `pip install relay-shell` (§2).
- The Caddy data directory (`/var/lib/caddy/`) — Caddy will re-issue
  the certificate from ACME on first start. Backing it up is only
  worth doing if you are rate-limited on the ACME directory.
- The SSH known_hosts file under the service account's `~/.ssh/` —
  reseed with `ssh_keyscan` (§7) rather than restoring stale entries.

## Emergency

- Disable fast: `sudo systemctl stop relay-shell` (and revoke OAuth tokens by
  clearing `tokens.json`, or rotate the proxy CIDR allowlist to none).
- Revoke SSH reach: remove/disable the service account's keys on targets.
- The audit log (off-host copy) is the post-incident record.
