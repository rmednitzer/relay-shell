# Deployment

`relay-shell` grants real administrative power. The most important control is
**where and as whom it runs**. This guide describes a production-grade
deployment modeled on a mature MCP gateway.

## 0. Pre-flight checklist

Complete this list before §1 (service account creation). Each item is a
precondition for the matching later section.

- [ ] **Service account name decided.** The default is `relay-shell`
      with home directory `/var/lib/relay-shell` (§1). Pick a different
      name only if your host conventions require it; update the systemd
      unit + logrotate config + `chown` lines below accordingly.
- [ ] **Audit directory writable by the service account.**
      `/var/log/relay-shell/` exists, is owned by the service account,
      and the filesystem supports `chattr +a` (ext2/3/4, xfs).
      Append-only on a `tmpfs` or fuse mount silently degrades to a
      normal write; confirm with `lsattr` after `chattr +a`.
- [ ] **DNS resolves for the edge domain** (HTTP transport only).
      `dig +short ${RELAY_SHELL_EDGE_DOMAIN}` returns the host's public
      IP. The HTTP-01 ACME challenge does not work without this.
- [ ] **Ports 80 and 443 reachable from the internet** (HTTP transport
      only). Port 80 is required for HTTP-01; closing it blocks both
      issuance and renewal. If a host firewall is in front, open
      it before running `install-edge.sh` (or set
      `RELAY_SHELL_EDGE_OPEN_FIREWALL=1` to have the installer try).
- [ ] **SSH service account keypair generated** (`ssh-keygen -t ed25519`
      as the service account) and `known_hosts` strategy chosen
      (`strict` for production, pre-populated with `ssh-keyscan`; see
      §7).
- [ ] **Off-host audit shipping target ready** (Vector / Fluent Bit /
      journal-remote; see `docs/audit-shipper.md`). An on-host audit
      file is evidence only until the host is compromised; the
      shipper must be in place *before* the unit is enabled in
      production.

Fix any unchecked item before continuing. The install is idempotent, but
recovering from a half-configured edge or a non-shipping audit log costs more
than the precondition.

## 1. Service account

Default recommendation: run as a dedicated unprivileged user, never a human's account.

```bash
sudo useradd --system --create-home --home-dir /var/lib/relay-shell \
     --shell /usr/sbin/nologin relay-shell
```

A full-root administrator deployment requires an explicitly provisioned,
noninteractive sudo grant for arbitrary commands, normally
`relay-shell ALL=(ALL:ALL) NOPASSWD: ALL`. Keep that declaration root-owned,
mode 0440, and validate it with `visudo` and an effective sudo probe. The generic
package installer does not silently grant new host privileges: deployment
configuration owns the authorization, including grants on remote hosts.

Run the daemon under its dedicated identity and elevate individual commands.
Treat an administrator relay and its authenticated clients as a host-control
plane, not as an application sandbox. Command-scoped deployments remain possible
but must not be described or validated as full-root administrators. Separate
job-specific SSH keys and application identities may retain their own boundaries.

## 2. Install

```bash
sudo -u relay-shell python3 -m venv /var/lib/relay-shell/venv
sudo -u relay-shell /var/lib/relay-shell/venv/bin/pip install --upgrade pip
sudo -u relay-shell /var/lib/relay-shell/venv/bin/pip install \
    -c /path/to/relay-shell/requirements.txt /path/to/relay-shell   # or: pip install relay-shell
```

`deploy/install.sh` does this idempotently (it installs against `requirements.txt` when the
checkout has one, and saves a copy of any unit, drop-in or logrotate file you edited under
`/var/lib/relay-shell/preinstall-backups/` before replacing it). It deliberately does **not**
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
initialization failure, including a degraded audit sink (the most common
production misconfiguration). Wire it into the image-bake step of your CI pipeline.

## 3. systemd

`deploy/systemd/relay-shell.service` plus the `relay-shell.service.d/hardening.conf`
drop-in. This is a resource envelope, not a containment boundary. Resource
caps (`MemoryMax`, `CPUQuota`, `TasksMax`), restart limits and umask 0077 remain.
The host capability set and filesystem view are preserved explicitly. In
particular, `ProtectClock`, `ProtectKernelLogs` and `ProtectKernelModules` remove
capabilities even from later sudo processes; `PrivateTmp` creates a separate
mount namespace. They are disabled for the administrator execution contract.
Authentication, auditing and tool admission policy remain unchanged. Optional
systemd credentials are independent of these settings.

```bash
sudo cp deploy/systemd/relay-shell.service /etc/systemd/system/
sudo mkdir -p /etc/systemd/system/relay-shell.service.d
sudo cp deploy/systemd/relay-shell.service.d/hardening.conf /etc/systemd/system/relay-shell.service.d/
sudo systemctl daemon-reload
sudo systemctl enable --now relay-shell
```

### 3a. Host integrity + config-drift monitoring (recommended)

The systemd confinement above is deliberately partial (ADR 0002): the executor
is unsandboxed by design, so the deploy host cannot *prevent* the service
account from touching the filesystem, and in privileged posture (root/sudo) it
can touch `/etc`, the unit files, even the relay binary. Where prevention is
intentionally absent, **detection** is the compensating control, as the audit
chain (§6a) is for the log. These are host-admin tools, not part of the relay;
configure them on the host, outside the service.

- **`etckeeper`**: put `/etc` under version control (git + a package-manager
  hook) so every config change is diffable and revertable. A privileged edit
  through the relay of `/etc/sudoers.d`, a systemd unit, or `sshd_config`
  then shows up as a committed diff instead of a silent mutation. Pair with a
  periodic `etckeeper vcs log` review or an off-host push of the `/etc` repo.
- **`AIDE`** (or Tripwire): a file-integrity baseline over the things that
  should *not* change between deploys: the relay binary / venv
  (`/var/lib/relay-shell/venv`), the systemd unit + `hardening.conf` drop-in, the
  `EnvironmentFile` under `/etc/relay-shell/`, and the OAuth state dir's
  permissions. A timer-driven `aide --check` alerts on an unexpected change (a
  swapped binary, a loosened unit, an altered drop-in). **Exclude the live audit
  log** from the baseline (it grows by design); its integrity is the §6a hash
  chain's job, not AIDE's. Re-baseline (`aide --update`) as part of the release
  procedure so a legitimate upgrade is not a false positive.
- **`fail2ban`**: watch `sshd` and the TLS edge (repeated Caddy 401/403 from
  outside the CIDR allowlist, §4) and ban brute-force sources. The relay's own
  SSH is *outbound*, but the host still runs `sshd` for admin and exposes the
  HTTP edge; fail2ban bounds credential-guessing against both.
- **`lynis`**: a periodic host hardening audit (run on a timer, track the score
  across runs). It surfaces drift in the host's own posture (kernel params, PAM,
  file perms) that sits underneath everything the relay depends on.

None of these is installed by `deploy/`; host hardening is the operator's
domain and the right tool set varies by distro and fleet-management stack. An
unsandboxed, possibly-privileged service raises the value of host-level
integrity and config-drift monitoring, so pair the in-app controls (audit chain,
redaction, tiered policy) with host-level detection.

## 4. Network edge (HTTP transport)

The HTTP transport binds `RELAY_SHELL_HTTP_HOST:RELAY_SHELL_HTTP_PORT`, which
defaults to `127.0.0.1:8080` (loopback by design), so a reverse proxy (below)
is the only thing that should face the network. You can retarget the bind (a
different loopback port, a container's internal interface), but do **not** bind
a non-loopback address without the edge protections here: the service stands up
no TLS or source-IP filtering of its own. Terminate TLS and restrict by source
IP at a reverse proxy. `deploy/Caddyfile` is shipped parameterized through
environment variables and provides:

- automatic TLS via ACME from the configured directory (`RELAY_SHELL_EDGE_ACME_CA`,
  Let's Encrypt production by default),
- an `@blocked` matcher that 403s any source outside the allowlisted CIDRs,
- HSTS / `X-Content-Type-Options` / `X-Frame-Options` / `Referrer-Policy` /
  `Content-Security-Policy` (`default-src 'self'; frame-ancestors 'none'; base-uri 'none'`),
  and the `Server` header removed,
- a 64 KB request-body cap on the public OAuth endpoints (the MCP path is capped by the
  relay itself, `RELAY_SHELL_MAX_INPUT`),
- an access log that drops the `Location` response header, which carries the authorization
  code on the `/authorize` redirect,
- `reverse_proxy` to the loopback MCP port.

Set the allowlist to the CIDRs of your MCP client only. The OAuth browser
endpoints (`/authorize`, `/.well-known/oauth-authorization-server`,
`/.well-known/oauth-protected-resource*`, `/register`, `/token`, `/revoke`)
are publicly reachable for the OAuth flow; every other path, other `/.well-known/` paths
included, is CIDR-restricted. MCP tool traffic is CIDR-restricted,
including when upstream OAuth is disabled. The default loopback-only allowlist
denies remote MCP clients with 403. Enabling OAuth does not bypass this gate;
allowlist the client's source CIDRs. Do not use an all-address allowlist while
upstream authentication is disabled.

Defense in depth: a host firewall (only 80/443 inbound), the proxy CIDR
matcher, OAuth 2.1, then the policy/audit layer.

### 4a. Automated TLS (Caddy + Let's Encrypt)

`deploy/install-edge.sh` is the supported turnkey path. It installs Caddy
from the official apt repository (if missing), validates the parameterized
Caddyfile as a candidate and only then replaces the live one (keeping the previous file as
`/etc/caddy/Caddyfile.bak`; a candidate that fails validation leaves the live file
untouched), writes a systemd environment drop-in, and starts the service. Renewal is driven by Caddy's built-in ACME
scheduler - **no cron, no certbot**.

Prerequisites: a public DNS A/AAAA record for the chosen hostname pointing
at this host, and TCP/80 + TCP/443 reachable from the internet (port 80 is
required for the HTTP-01 challenge).

```bash
# Edit /etc/relay-shell/relay-shell.env (or export inline; a value in the env file
# overrides an exported one) and set at minimum:
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
| `RELAY_SHELL_EDGE_VALIDATE_ONLY` | Set to `1` to check every value above against a strict shape (fully qualified domain, `user@host` email, `https://` ACME URL, `host:port` upstream with a valid port, IPv4/IPv6 addresses or CIDRs) and exit without needing root. The installer always runs this check first: a `}`, quote or space in a value would otherwise change the Caddyfile or the systemd environment file. A `0.0.0.0/0` or `::/0` CIDR is accepted but warned about, because it removes the source gate. |
| `RELAY_SHELL_EDGE_DRY_RUN` | Set to `1` to log the resolved values and print the parameterized Caddyfile template, then exit without installing. Caddy substitutes the `{$RELAY_SHELL_EDGE_*}` placeholders at service start. |
| `RELAY_SHELL_EDGE_FORCE` | Set to `1` to overwrite an existing `/etc/caddy/Caddyfile` that this installer did not write. Without it, the installer refuses to clobber a Caddyfile that may serve other sites on the host. |
| `RELAY_SHELL_EDGE_CADDY_GPG_FPR` | Pin the Caddy apt repo signing key: the installer fails closed if the fetched key's fingerprint does not match (DEP-1). The key is fetched over TLS but otherwise trust-on-first-use; the installer always logs the observed fingerprint, so set this to that value (after confirming it at <https://caddyserver.com/docs/install>) to enforce it. Unset = unpinned, with a warning. Only used when the installer provisions Caddy via apt. |

The installer is idempotent: re-run it after editing the env file to push
changes. Both installers create `/etc/relay-shell` as `0750`
(`root:relay-shell`, or `root:root` on an edge-only host without the `relay-shell` group),
not world-listable; systemd reads the EnvironmentFiles
as root, so the service is unaffected. The drop-in at
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

Authentication is **opt-in and off by default** (`RELAY_SHELL_AUTH_ENABLED`
defaults to `false`) and applies only to the HTTP transport. A fresh install
stands up no network listener unless you choose the HTTP transport; once you
do, enable OAuth for any exposure beyond a trusted loopback + edge.

```bash
RELAY_SHELL_TRANSPORT=http
RELAY_SHELL_AUTH_ENABLED=true             # default false; opt in explicitly
RELAY_SHELL_AUTH_ISSUER=https://relay-shell.example.org
RELAY_SHELL_AUTH_STATE_DIR=/var/lib/relay-shell/oauth
RELAY_SHELL_AUTH_SINGLE_CLIENT=true       # lock DCR after the first client registers
RELAY_SHELL_AUTH_REQUIRE_APPROVAL=true    # default: a new client stays pending until you approve it
RELAY_SHELL_AUTH_RESOURCE_URL=https://relay-shell.example.org/mcp  # exact public MCP endpoint tokens are bound to
```

`RELAY_SHELL_AUTH_RESOURCE_URL` (RFC 8707) defaults to the issuer URL when empty, so an upgrade does
not change the identifier already advertised; set it explicitly in a new deployment. Tokens issued
before resource binding existed are refused until re-authorized ([`auth.md`](auth.md#9-resource-binding-rfc-8707)).
The TTL settings (`RELAY_SHELL_AUTH_ACCESS_TTL` / `_REFRESH_TTL` / `_CODE_TTL`) are in the defaults
table in [`auth.md`](auth.md#defaults-at-a-glance).

**Approve your client.** A client that registers is *pending*; `/authorize`
refuses it until you approve it on the host
(`sudo -u relay-shell /var/lib/relay-shell/venv/bin/relay-shell --auth-list`, then the same
binary with `--auth-approve <client_id>`; the commands read `RELAY_SHELL_AUTH_STATE_DIR` from
their own environment, not from the unit's EnvironmentFile, so export it when it is not the
default `/var/lib/relay-shell/oauth`). This
closes the window in which the first party to reach `/register` could obtain a
token; see [`auth.md`](auth.md#operator-approval). Existing installs are carried
over as approved on upgrade.

The `[http]` extra is an empty alias (`mcp` 2 already depends on PyJWT and cryptography), so
a plain install is enough. Tokens are file-backed under the state dir
(`clients.json`, `approvals.json`, `codes.json`, `tokens.json`), access tokens are short-lived,
refresh tokens rotate on use, secrets are stored hashed rather than raw, and expiry
is enforced lazily on read. With single-client lockdown, dynamic registration is
refused once one client exists. [`auth.md`](auth.md) has the full lifecycle: how a
client registers, obtains tokens, and stays authenticated via refresh rotation.

## 6. Audit

`RELAY_SHELL_AUDIT_PATH` (default `/var/log/relay-shell/audit.jsonl`). Make it append-only
and rotate it without losing that attribute:

```bash
sudo mkdir -p /var/log/relay-shell && sudo chown relay-shell:relay-shell /var/log/relay-shell
sudo install -o relay-shell -g relay-shell -m 0600 /dev/null /var/log/relay-shell/audit.jsonl
sudo chattr +a /var/log/relay-shell/audit.jsonl
sudo cp deploy/logrotate/relay-shell /etc/logrotate.d/relay-shell
```

`RELAY_SHELL_AUDIT_FORMAT` controls serialization for downstream SIEM ingest:
`jsonl` (default), `cef`, or `leef`.

The bundled logrotate config rotates daily and keeps 90 dated archives
(`audit.jsonl-YYYYMMDD`; the newest stays uncompressed, older ones are `.gz`). It drops the append-only bit
from the active file and every archive for the rotation run only (`firstaction`), restores it
on the new active file (`postrotate`) and then on every archive, and on the active file again
in case the rotation aborted (`lastaction`), so archives stay append-only too. **Ship the log off-host** and alert on gaps; an
on-host log is evidence only until the host is compromised.
[`docs/audit-shipper.md`](audit-shipper.md) has worked examples for
Vector, Fluent Bit, and `journalctl` → `systemd-journal-remote`.

### 6a-i. Cancelled calls and the write-ahead record

A call whose caller goes away mid-flight (client disconnect, MCP cancellation,
transport timeout) is audited with `action=cancelled` (output hash of the fixed
marker `[CANCELLED]`, `exit_code` null) and counted on `/metrics` as
`outcome="cancelled"`. The local command's process group is killed and a remote
command is sent a terminate, so a cancelled call does not keep running.

The completion record is written when the work returns, so a crash or SIGKILL of
the relay itself mid-command leaves no record of a command that may have run. Set
`RELAY_SHELL_AUDIT_INTENT=true` to also append an `action=intent` record (same
`args`, `exit_code` null) *before* the work starts; the completion record
follows. Default off keeps one record per call and every record byte-identical.
`server_info.audit.intent` reports the live state. A log consumer that counts
records per call must treat an `intent` record as the call's start, not a call.

### 6a-ii. Input typed into sessions

`session_send` is the one tool whose argument is often a secret with no keyword
(a `sudo` password). Its audit record therefore omits `data` (keeping `data_len`)
when the session is at a secret prompt: the last output line reads like one
(`[sudo] password for bob:`, `Enter passphrase for key ...:`, `Verification
code:`), or the local terminal has echo off. Anything else is recorded as before,
after pattern redaction. Set `RELAY_SHELL_AUDIT_SESSION_INPUT=hash` to record
only `data_len` and `data_sha256` for every send (at a recognised secret prompt the
digest is withheld too, leaving only `data_len`); the default is `redacted`.
`server_info.audit.session_input` reports the live setting. A secret typed at a
prompt the heuristic does not recognise is still recorded, so use `hash` where
typed content must never reach the log.

### 6a. Tamper-evident chain (optional)

`chattr +a` and off-host shipping protect the log, but neither makes a
*single altered record* detectable, and the shipper has a flush window. Set
`RELAY_SHELL_AUDIT_CHAIN=true` (requires `RELAY_SHELL_AUDIT_FORMAT=jsonl`) to
add a per-record hash chain ([ADR 0007](adr/0007-audit-hash-chain.md)): each
record carries `seq`, the previous record's `prev` hash, and its own `chain`
hash. Default off keeps the record byte-identical; `server_info.audit.chain`
reports the live state. **One relay process owns one chained log**: a second writer
keeps its own `seq` / `prev` and forks the chain, which `--verify-audit` reports as
a break. If the log cannot be written, the chain still advances in memory and the
missing record shows up as a `seq` gap on verification.

**What the chain proves, and what it does not.** From a single file the chain
detects any **edit, insertion, reorder, or interior deletion** by recomputation,
including from the shipped copy, without trusting the relay host.
**Head-truncation** (excising leading records) is caught by the genesis anchor.
**Tail-truncation** (dropping the newest records) leaves a shorter but valid
prefix and is *not* detectable from the file alone; catch it by comparing
against the off-host copy, which has the later records. This split is by design
(ADR 0007 delegates durability/truncation defense to off-host shipping).

`--verify-audit` is **fail-closed**: it exits 0 only when the file exists,
carries a chained record, verifies clean, and is genesis-anchored; a missing /
empty / unchained log, a broken chain, or a non-genesis start (head-truncation)
exits 2. Enable chaining on a **freshly rotated** log so the chain runs from
genesis. Verify the on-host log or a shipped copy:

```bash
relay-shell --verify-audit                          # uses RELAY_SHELL_AUDIT_PATH
relay-shell --verify-audit --audit-path /var/log/relay-shell/audit.jsonl-20260601 \
            --segment --json                        # a mid-stream rotation segment
# exit 0 = clean, genesis-anchored chain; exit 2 = missing/empty log, a record
# edited / reordered / inserted / deleted from the interior, or a non-genesis
# start. Pass --segment when the file legitimately starts at seq > 0 (a rotation
# segment); a missing/empty log and a broken chain fail regardless.
```

**Rotation.** While the process keeps running, rotation preserves the chain:
the in-memory anchor follows the file (`WatchedFileHandler` reopens, or
`copytruncate` keeps the fd), so the new file continues the same `seq`/`chain`.
If a restart finds the active file empty, the logger resumes from the newest
dateext- or numeric-named rotated sibling, including a gzip-compressed one.
A missing, unchained, or unparseable tail creates a visible genesis seam
instead; a non-empty malformed active tail is never bypassed with older
history. Verify cross-file seams against the ordered off-host stream, which
remains authoritative for tail-truncation and durability.

### 6b. Syscall-level audit channel (optional)

The audit record covers *what the model asked for* and the SHA-256 of the
output, but not what a spawned child does after `exec` returns. Set
`RELAY_SHELL_SECCOMP_NOTIFY=true` to add an audit-only seccomp **user-notify**
channel ([ADR 0006](adr/0006-seccomp-notify-audit-channel.md)):
locally-spawned children (one-shot: `shell_exec` / `shell_script` /
`ssh_keyscan`; and local PTY sessions: `shell_spawn`) get a BPF filter that
traps a small, high-signal syscall set (`execve`, the `set[re|res]?[ug]id`
family, `mount`/`umount2`, `unshare`/`setns`, `chroot`/`pivot_root`,
`ptrace`, write-`open`/`openat`, and `prctl` for privilege-relevant options
such as `PR_SET_SECUREBITS` / `PR_CAP_AMBIENT` / `PR_SET_NO_NEW_PRIVS`), and
a supervisor appends one `syscall_notify` line per observed call to the same
JSONL stream (it extends the §6a hash chain when that is on). It **never
blocks** a syscall (the supervisor always answers CONTINUE), so ADR 0002's
no-sandbox posture is unchanged. For a PTY session the filter rides the
session child (and everything it forks) for the session's whole life, and
events carry the spawning call's `request_id`. SSH sessions have no local
child (`asyncssh` runs in-process), so nothing is observed (or missed)
on that path.

**Activation is gated, by design.** A seccomp filter installs with
`CAP_SYS_ADMIN` *or* by latching `no_new_privs`; the latter would silently
disable set-uid escalation in the child (`sudo` would break). To preserve the
privileged-admin posture verbatim, the channel installs **only** with
`CAP_SYS_ADMIN` (e.g. running as root) and never latches `no_new_privs`. It
also requires Linux / `x86_64` / kernel ≥ 5.5 and a notify ABI matching the
build. Where any prerequisite is missing it **cleanly no-ops**: local spawns
are byte-identical to the off path, and `server_info.seccomp.supported` is
`false` with a `reason` (also logged once at startup). There is no system
package to install: the channel is pure `ctypes`.

`RELAY_SHELL_SECCOMP_NOTIFY_CAP` (default 256, range 1..65536) bounds the
event volume per spawned child, counted per call for the one-shot executors and per
session for `shell_spawn` (a long-lived interactive session runs many
commands under one filter, so size the cap for the session, not the
command): beyond it, one `syscall_notify_overflow` line is written
and emission stops while the child still runs to completion. Watch
`relay_shell_seccomp_notify_overflow_total` (§9a) and raise the cap if a
legitimate workload trips it. A process that outlives its call (a backgrounded job or daemon) keeps running
normally: its listener is kept open and answered, but its syscalls are no longer audited once the
call has ended, and each such listener holds one file descriptor until that process exits (ADR 0006,
2026-10-14 correction). The events ride the same off-host shipper as the
rest of the log (`docs/audit-shipper.md`), which routes on the `tool` field.

### 6c. Audit evidence verifier and off-host sync (optional)

`deploy/evidence/` ships a timer-driven verifier and an rsync wrapper that make the off-host
copy of the audit log trustworthy. Each run recomputes every retained record's hash, checks
sequence and `prev` continuity inside every segment and across rotation seams (a genesis reset
only with an exact entry in a root-owned approval ledger), writes `chain-verification.jsonl`,
`latest-anchor.json` and `retained-checkpoints.json`, and only then does the wrapper publish the
segments and, last, the anchor as the commit marker. A failed verification publishes nothing and
exits non-zero. The rsync run on the destination is plain `rsync` (`RELAY_AUDIT_RSYNC_PATH`,
default since 0.4.0); an installation that relied on the former `sudo -n /usr/bin/rsync`
default (root on the backup host) must now set it explicitly. It needs `RELAY_AUDIT_RSYNC_DEST` and, if logrotate keeps other than 90 rotated
segments, `RELAY_AUDIT_RETAIN_SEGMENTS`; after logrotate prunes the oldest segment the verifier
accepts the shortened history when it continues a checkpointed record (and hosts that rotated
before checkpoints existed need one reviewed `approved_heads` entry). Before publishing, the wrapper
pulls the remote anchor (capped at 64 KiB) and refuses (exit 4) a local chain that is behind it
or that differs from it at the same sequence number, since the sync is a mirror. A chain that
is ahead is accepted without proving the remote anchor is its ancestor. A missing anchor on the
first sync is skipped; any other pull failure stops the run, and write-only destinations must
set `RELAY_AUDIT_REMOTE_CHECK=off` explicitly (any value other than `pull` or `off` is refused).
Install steps, the ledger
format and the limits of that check are in
[`deploy/evidence/README.md`](https://github.com/rmednitzer/relay-shell/blob/main/deploy/evidence/README.md);
host metrics and the anchor health check are in
[`deploy/monitoring/README.md`](https://github.com/rmednitzer/relay-shell/blob/main/deploy/monitoring/README.md).
It complements, and does not replace, the shipper recipes in `audit-shipper.md`.

## 7. SSH credential scoping

The realized credential surface is whatever keys the service account can use.
Prefer one key per role/scope, revocable independently, over one all-powerful
key. `RELAY_SHELL_SSH_KNOWN_HOSTS=strict` is recommended for production; pre-populate
`~/.ssh/known_hosts` for the service account. Provide a JSON inventory via
`RELAY_SHELL_INVENTORY` for hosts not in `ssh_config`.

The SSH tools that take connection parameters (`ssh_exec`, `ssh_spawn`, `ssh_upload`,
`ssh_download`, `ssh_forward`) also accept a per-call `known_hosts` argument, so by default a
caller can pass `ignore` against a `strict` server default. Set
`RELAY_SHELL_SSH_ALLOW_WEAKER_KNOWN_HOSTS=false` to refuse any per-call mode weaker than
`RELAY_SHELL_SSH_KNOWN_HOSTS` (strength order `strict` > `accept-new` > `ignore`) with a
bounded error; a stronger per-call mode is always allowed, and a `known_hosts` entry in the
operator-written inventory is honoured as written. The audit record's `known_hosts` field
is always the mode actually used (per call, then inventory, then the server default), and
`server_info.ssh.allow_weaker_known_hosts` reports the setting. The default is `true`
(historical behaviour); use `false` wherever the server default is `strict`.

The SSH connection pool caches one connection per `user@host:port` and
reuses it for follow-up calls. `RELAY_SHELL_SSH_IDLE_TIMEOUT` (default
1800 seconds) drops a cached connection that has not been used for that
many seconds the next time the pool is consulted; set `0` to keep the
historical behavior (closed connections are still purged on the next
sweep). Long-running deployments that fan out across a large host
inventory should leave the reaper on so a long-lived server does not
accumulate idle handles.

## 8. Policy posture

The default is `open` with no deny list and no confirmation step, so **no command is refused
because of what it does** ([ADR 0013](adr/0013-open-by-default-with-unsafe-notices.md)). The
server tells the caller instead: an admitted Tier 2 or Tier 3 call, or one using SSH with
host-key verification off, ends with a `[NOTICE ...]` line, and `server_info.warnings` plus the
startup log list the permissive settings (root, open policy, `accept-new`/`ignore` host keys,
per-call weaker host keys, HTTP without OAuth, audit chain off). `RELAY_SHELL_UNSAFE_NOTICES=false`
removes the trailing lines; the audit record is the same either way. A notice is information,
not a block, and a call without one is not thereby safe, because the classifier is a heuristic.
What still refuses a call is a resource bound (`RELAY_SHELL_MAX_INPUT`, the session and forward
caps), never the command's meaning.

- `open` - full access, every call still classified and audited. The
  default.
- `guarded` - Tier 2+ refused unless `RELAY_SHELL_POLICY_ALLOW` matches; set an
  allowlist of sanctioned change patterns. The pattern is an unanchored `re.search`
  over `<tool> <policy text>`, and a match admits the whole call, so anchor the start
  (`(?s)^shell_exec systemctl restart nginx\b`) rather than naming a word that could
  appear anywhere in a longer command. SSH and transfer tools append host, jump and IP
  lines after the command, so do not end-anchor with `$`; the per-tool shapes are in
  [`tools.md`](tools.md).
- `readonly` - only Tier 0. Useful for an observation-only client.

Interactive PTY sessions are classified per input: each `session_send` payload
is run through the same tier scan as a one-shot command (so a destructive
keystroke payload like `rm -rf /` is Tier 3 and refused under `guarded`, not
waved through at the Tier-1 keystroke default). The scan covers the **line being
typed**, not just the latest payload: text sent since the last Enter, Ctrl-C or
Ctrl-U is carried forward, so `r` followed by `m -rf /x` is classified as
`rm -rf /x` and refused. That closes plain fragmentation, but it is still text
matching: a line built with shell obfuscation, a script written to disk and run, or
an editor / REPL inside the session evades it the same way obfuscation evades the
deny list. If a `guarded` deployment must
prevent Tier-2+ actions inside an interactive shell, deny the spawn tools
(`^shell_spawn` / `^ssh_spawn`) outright, run `readonly`, or rely on OS/network
controls; do not treat the `guarded` ceiling as airtight against a live shell.

`RELAY_SHELL_POLICY_DENY` is a regex evaluated first in **every** mode, against
the probe text `"<tool> <command>"` (the tool name is prepended, so anchor with
`\b`/substrings rather than `^command`; you can also deny a whole tool, e.g.
`^ssh_keyscan`). Use it as an always-on first-line filter, but treat it as
**defence in depth, not an absolute prohibition**: it matches command *text*, so
a determined caller can evade it with shell obfuscation (extra whitespace,
quoting like `r''m`, `${IFS}`, `$(...)`, base64 `| sh`) or alternate encodings.
`ssh_keyscan` normalizes any *literal* IP in its target list into the probe, so
an IP deny (e.g. on the cloud metadata address) is not dodged by a
decimal/hex/octal/IPv4-mapped spelling of the same address (SSRF-1), but this
cannot help for hostnames (no DNS is resolved in the policy path; a DNS or
rebinding answer can differ from the one the connection dials). Enforce hard
prohibitions with OS/network controls, such as an egress firewall (DNS-rebinding-proof),
seccomp/AppArmor, a restricted service account or `readonly`/`guarded` mode, not
the deny list alone. See ADR 0003.

### 8a. Tier-3 confirmation broker (optional)

`open` runs Tier-3 (IRREVERSIBLE) commands on the first request (with a trailing notice);
`guarded` refuses them wholesale. For the middle ground (*permit irreversible admin work, but
require a deliberate second step per call*), set `RELAY_SHELL_CONFIRM_TIER3=true`
([ADR 0009](adr/0009-tier3-confirmation-broker.md)). When on, a Tier-3 call that
passed the deny list and mode check does not run on first request: it returns a
single-use, TTL-bounded token (audited `action=confirm_plan`, no side effect),
and the caller must arm it with the `operation_confirm` tool then re-issue the
exact same call (audited `action=confirm_execute`). Tokens are bound to the
exact operation and expire after `RELAY_SHELL_CONFIRM_TTL` seconds (default 120,
range 5..3600). This is an added safeguard, never a bypass (the deny list and
mode policy still run first), so it composes with any mode. Default off keeps
the audit record byte-identical. `server_info.confirm` reports the live posture
(`tier3`, `ttl`, `pending` token count).

### 8b. Windows targets over OpenSSH + PowerShell 7

Administering **Windows hosts over OpenSSH with PowerShell 7 (`pwsh`) as the
`DefaultShell`** is supported ([ADR 0011](adr/0011-windows-openssh-powershell.md)).

- **Execution and file transfer work as-is.** `ssh_exec` / `ssh_spawn` /
  `ssh_fanout` pass the command straight to the remote's own shell (no POSIX
  wrapping), so `pwsh` interprets it; SFTP paths (`ssh_upload` / `ssh_download`)
  pass through opaquely, so a caller uses `C:\...` remote paths as the server
  expects. There is no command- or path-translation layer; the caller supplies
  PowerShell-appropriate syntax.
- **The tier classifier covers common Windows/pwsh destructive operations**
  so `guarded` / `readonly` mode and the Tier-3 confirmation broker apply to
  Windows targets, not just POSIX ones. Tier 3 (irreversible): `Remove-Item
  -Recurse`/`-Force`, `Clear-Disk`, `Format-Volume`, `Stop-Computer` /
  `Restart-Computer`, `Remove-Service`, `Remove-LocalUser`, `Clear-EventLog`,
  plus native `del /s`, `rd /s`, `format <drive>`, `diskpart`, `vssadmin delete
  shadows`, `bcdedit`, `cipher /w`, `reg delete`, `sc delete`, `wevtutil cl`.
  Tier 2 (stateful): `Stop-`/`Set-Service`, `sc`/`net stop`, `Install-Module`/
  `-Package`, `choco`/`winget install`, `Remove-`/`Disable-NetFirewallRule`,
  `netsh advfirewall`, `reg add`, `New-LocalUser`, `Register-ScheduledTask`,
  `Set-ExecutionPolicy`. Privilege escalation: `runas` and `Start-Process -Verb
  RunAs` (the same tier bump as `sudo`).
- **Classification stays heuristic, with a sharper caveat for PowerShell.** pwsh
  parameters are case-insensitive, abbreviatable (`-Recurse` → `-rec` → `-r`),
  and `:`-bindable, and cmdlets have aliases (`ri`, `del`, `rd`); a pipeline
  form (`Get-ChildItem -Recurse | Remove-Item`) hides the recursion from the
  `Remove-Item` token. Fully-abbreviated or aliased destructive forms can still
  under-classify, exactly as shell obfuscation evades the deny list (ADR 0003).
  As on POSIX, the deny list (`RELAY_SHELL_POLICY_DENY`, e.g. `Remove-Item`,
  `Format-Volume`) and `readonly`/`guarded` mode remain the hard controls; the
  classifier is defence in depth.
- **Secret redaction.** Audited command *arguments* redact the PowerShell
  credential shapes (`-Credential` / `credential=`, and the
  `ConvertTo-SecureString 'plaintext' -AsPlainText` inline-secret idiom) as
  well as the shared `-Password`/`-Token`/`-ApiKey` forms. As on POSIX this is
  best-effort: a positional secret with no keyword (`net user bob NewP@ss`)
  cannot be recognized and is not redacted, so prefer credential objects
  (`Get-Credential`, a `PSCredential`) over inline plaintext.
- **Output encoding.** `pwsh` 7 defaults to **UTF-8**, so audited output is
  decoded correctly. The one edge: a legacy native `.exe` invoked *from* pwsh
  (e.g. `diskpart.exe`) may emit OEM-codepage bytes, which decode with `�`
  replacement; a display artifact, not a correctness or security issue.
- **Interactive sessions (`ssh_spawn`).** Modern Windows OpenSSH + pwsh 7 handle
  the ConPTY-backed PTY and window resize. On older Windows OpenSSH builds the
  SSH `signal` request may be unimplemented, so `session_kill` degrades to a
  best-effort channel close rather than a delivered signal.

### 8c. Settings reference

The authoritative list of `RELAY_SHELL_*` settings, with types, defaults and ranges, is the
`Settings` class in
[`src/relay_shell/config.py`](https://github.com/rmednitzer/relay-shell/blob/main/src/relay_shell/config.py);
[`.env.example`](https://github.com/rmednitzer/relay-shell/blob/main/.env.example) is the
annotated template. Operator-relevant ones not covered above:

- **HTTP listener:** `RELAY_SHELL_HTTP_HOST` / `RELAY_SHELL_HTTP_PORT` (default
  `127.0.0.1:8080`; see §4).
- **Resource bounds:** `RELAY_SHELL_MAX_OUTPUT` / `_MAX_OUTPUT_HARD` (output
  caps, defaults 65536 and 1048576 bytes), `RELAY_SHELL_DEFAULT_TIMEOUT` / `_MAX_TIMEOUT`
  (timeout used when a `shell_exec` / `ssh_exec` caller omits it, default 60 s, + the clamp
  for every call, default 900 s; other tools keep their own documented defaults),
  `RELAY_SHELL_MAX_SESSIONS` / `_MAX_FORWARDS` / `_MAX_CONNS` (concurrency caps for sessions,
  port forwards, and the SSH connection cache, defaults 64 / 64 / 256; `_MAX_CONNS` evicts the
  least-recently-used connection not in use when full), `RELAY_SHELL_SESSION_IDLE_TIMEOUT` /
  `_SESSION_BUFFER_BYTES` (PTY session reaping, default 1800 s, and the per-session buffer,
  default 262144 bytes),
  `RELAY_SHELL_MAX_INPUT` (default 2097152 characters: the command, stdin, script
  body and env overlay of one call, together). The tier classifier and the deny
  regex scan that text synchronously at about 0.5 s per MiB, so a call over the cap
  is refused, audited as denied, rather than stalling every other session or being
  scanned only in part (padding could then hide a command). Raise it only where
  multi-MiB payloads are really piped through stdin or a script.
- **Unauthenticated HTTP:** the server refuses to start with
  `RELAY_SHELL_TRANSPORT=http` on a non-loopback `RELAY_SHELL_HTTP_HOST` (anything
  other than `localhost` or a loopback address) unless `RELAY_SHELL_AUTH_ENABLED=true`
  or `RELAY_SHELL_ALLOW_UNAUTH_NETWORK=true`. The override is for deployments where an
  authenticating proxy is the only route to the port; `/metrics` is outside OAuth by
  design, so it is exposed to whoever can reach the port.
- **SSH:** `RELAY_SHELL_SSH_CONFIG` (default `~/.ssh/config`) and `RELAY_SHELL_INVENTORY`
  (JSON inventory) say where hosts come from; `RELAY_SHELL_SSH_KNOWN_HOSTS` and
  `RELAY_SHELL_SSH_ALLOW_WEAKER_KNOWN_HOSTS` set host-key verification (§7). The server
  honours `ProxyCommand` and `Match exec` in that file, which start local processes under the
  service account without a per-call audit record; use `ProxyJump` instead and keep the file
  operator-owned and not writable by the service account. Caller-supplied hosts, users and
  jump hops are restricted to plain tokens so they cannot add arguments to a `ProxyCommand`.
- **SSH connect tuning:** `RELAY_SHELL_SSH_CONNECT_TIMEOUT` (dial timeout, default 10 s) /
  `_SSH_KEEPALIVE` (keepalive interval, default 30 s, `0` disables); `_SSH_IDLE_TIMEOUT` for
  the pool reaper is in §7.
- **Audit sink:** `RELAY_SHELL_AUDIT_STDERR` (also mirror audit lines to stderr).

A `RELAY_SHELL_*` name that no setting reads (a typo such as `RELAY_SHELL_POLICY_MOD`,
in the environment or in `.env`) is ignored and the default stays in force, so the server
logs `ignoring unknown setting ... (did you mean ...?)` at startup. Read the start-up log
after changing a setting; `RELAY_SHELL_EDGE_*` names belong to the edge installer and are
not reported.

To check the effective bounds against the deployment posture, see [`runbook.md`](runbook.md) §2.6.

## 9. Health

`scripts/healthcheck.sh` checks the local HTTP port. For stdio, liveness is
the supervising client's concern. `server_info` reports effective limits and
whether the audit sink is degraded (a degraded audit sink is an alert).
The end-to-end HTTP smoke (start the transport, hit
`/.well-known/oauth-protected-resource`, stop it) is in
[`runbook.md`](runbook.md) §4.6.

### 9a. Prometheus metrics

The HTTP transport exposes a `GET /metrics` endpoint in Prometheus text
exposition format (no auth: the route bypasses OAuth by design, so scope it
via the Caddy CIDR allowlist). The audit log is the source of truth;
metrics are for dashboards only and reset on restart.

| metric                                       | type    | meaning                                                             |
|----------------------------------------------|---------|---------------------------------------------------------------------|
| `relay_shell_tool_calls_total`               | counter | One per tool call. Labels: `tool`, `tier`, `mode`, `outcome`.       |
| `relay_shell_seccomp_notify_events_total`    | counter | One per observed syscall when the §6b channel is on. Label: `syscall` (bounded set). |
| `relay_shell_seccomp_notify_overflow_total`  | counter | One per tool call that hit `RELAY_SHELL_SECCOMP_NOTIFY_CAP`.         |
| `relay_shell_active_sessions`                | gauge   | Live local + SSH PTY sessions.                                      |
| `relay_shell_active_forwards`                | gauge   | Live SSH port forwards.                                             |
| `relay_shell_audit_degraded`                 | gauge   | 1 if the audit sink is degraded, 0 otherwise. Should always be 0.   |

`outcome` is one of `ok` (work returned), `denied` (policy refused),
`error` (work raised), `cancelled` (the call was cancelled or the client disconnected), or `confirm_required` (a Tier-3 call returned a
confirmation token instead of running; only emitted when the Tier-3
confirmation broker is on, §8a). Combine `mode + tier + outcome` for the
classic "denied tier-3 calls per minute" panel, or alert on a rising
`confirm_required` rate to see irreversible operations being challenged.

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

The relay's persistent state is small and lives in three places; the relay is
stateless beyond them. Back them up together:

| What                                                            | Where                                                                                         | Why it matters                                                                              |
|-----------------------------------------------------------------|-----------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------|
| OAuth state                                                     | `${RELAY_SHELL_AUTH_STATE_DIR}/{clients.json, approvals.json, codes.json, tokens.json}` (default `/var/lib/relay-shell/oauth/`) | Losing it logs every client out and re-runs single-client lockdown from scratch (a new client can register, the old one cannot). |
| systemd EnvironmentFile                                         | `/etc/relay-shell/relay-shell.env` (plus `/etc/relay-shell/relay-shell-edge.env` for the edge) | Source of truth for every `RELAY_SHELL_*` knob; recreating it from scratch is error-prone.  |
| Audit log                                                       | `${RELAY_SHELL_AUDIT_PATH}` (default `/var/log/relay-shell/audit.jsonl`) plus the `audit.jsonl-YYYYMMDD[.gz]` archives | The on-host copy is the local fallback when the off-host shipper has fallen behind.        |

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

The `install` steps create a root-only destination (directory `0700`,
archive `0600`) before `tar` writes sensitive OAuth state and environment material.

Restore the OAuth state with `chmod 0700 oauth/ && chmod 0600 oauth/*.json`
preserved (the file modes are part of the trust boundary; the relay
re-applies them on next write, but nothing should read 0644 files between restore
and first write). The audit log is append-only
on disk; restore it *before* the relay starts so `chattr +a` does not
race with a write into the unmoved file. The drift-detection CLI
(`relay-shell --verify-deploy`, §10) confirms the systemd unit + Caddyfile
+ logrotate config match the templates after a restore.

What is **not** in scope for backup:

- The Python venv under `/var/lib/relay-shell/venv/`: recreate with
  `pip install relay-shell` (§2).
- The Caddy data directory (`/var/lib/caddy/`): Caddy will re-issue
  the certificate from ACME on first start. Backing it up is only
  worth doing if you are rate-limited on the ACME directory.
- The SSH known_hosts file under the service account's `~/.ssh/`:
  reseed with `ssh_keyscan` (§7) rather than restoring stale entries.

## Emergency

- Disable fast: `sudo systemctl stop relay-shell` (and revoke OAuth tokens by
  clearing `tokens.json`, or rotate the proxy CIDR allowlist to none).
- Revoke SSH reach: remove/disable the service account's keys on targets.
- The audit log (off-host copy) is the post-incident record.
