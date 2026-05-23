# Security Policy

## Model

`relay-shell` is operator infrastructure. It deliberately runs **without an internal
sandbox** and executes commands with the full privileges of its service
account. That is the point of the tool; see
`docs/adr/0002-no-sandbox-full-access.md`. Security is achieved by
**compensating controls** and by **deployment discipline**, not by
constraining the executor.

### Trust boundary

The trust boundary is the MCP transport. Treat everything arriving over it as
potentially attacker-influenced (prompt injection through tool results, file
contents, or remote command output). The protections below are designed so
that a persuaded model still cannot exceed the operator-defined envelope:

- **Tiered authority** (`docs/adr/0003-tiered-authority.md`). Every call is
  classified Tier 0 (read-only) to Tier 3 (irreversible). `RELAY_SHELL_POLICY_MODE`:
  - `open` (default): full access, every call still classified and audited.
  - `guarded`: Tier 2+ refused unless `RELAY_SHELL_POLICY_ALLOW` matches.
  - `readonly`: only Tier 0 permitted.
  `RELAY_SHELL_POLICY_DENY` is always enforced first, in every mode.
- **Append-only audit** (`audit.jsonl`). One JSON object per line:
  timestamp, tool, redacted/truncated args, SHA-256 of the output, output
  byte length, exit code, request id, client id, tier. The output **body is
  never written** - only its hash and length. Make the file append-only on
  disk (`chattr +a`) and ship it off-host; the bundled logrotate config
  preserves the attribute across rotation. See
  [`docs/audit-shipper.md`](docs/audit-shipper.md) for worked Vector,
  Fluent Bit, and `systemd-journal-remote` recipes.
- **Secret redaction.** Audited arguments are scrubbed for bearer tokens,
  API keys, private-key blocks, `Authorization` headers, long-name CLI
  flags (both `--password` and single-dash `-token=` forms), and
  URL-embedded credentials before logging. The compact short-form
  `-p<value>` is intentionally redacted only for MySQL-family commands
  (`mysql`, `mariadb-dump`, `mycli`, ...) because `-p` is overloaded
  elsewhere (`ssh -p22`, `nmap -p1-1000`); operators putting passwords
  inline should use `--password=...` or `~/.my.cnf` instead. See
  `src/relay_shell/redaction.py` for the full pattern set.
- **Resource bounds.** Per-call timeout and output caps, a bounded number of
  concurrent sessions, bounded per-session buffers, and idle/lifetime
  reaping. Failure paths return a structured error string; a tool never
  raises into the transport.
- **Optional OAuth 2.1 edge** (HTTP transport, `[http]` extra): dynamic
  client registration with single-client lockdown, PKCE, file-backed
  access/refresh tokens with rotation and lazy expiry.

### Deployment requirements (operator's responsibility)

These are **required**, not optional, for any non-local deployment:

1. Choose one explicit runtime posture:
   - **Scoped** (recommended): dedicated unprivileged service account
   - **Privileged** (maximum capability): root/system-level service on an isolated host
   In either posture, document and review the decision.
2. Bind the HTTP transport to loopback and place a TLS reverse proxy in
   front with an IP allowlist (reference `deploy/Caddyfile`).
3. Apply the systemd unit and hardening drop-in (`deploy/systemd/`).
4. Scope SSH credentials per role; prefer one key per scope, revocable
   independently. Do not reuse a single all-powerful key.
5. Ship the audit log off-host and alert on gaps.
6. Keep the host patched; treat compromise of the MCP client or transport
   as equivalent to compromise of the service account.

### Residual risk

If the MCP client or the transport is compromised, an attacker obtains the
capabilities of the service account on this host and any host its SSH
credentials reach. In privileged posture, this is effectively root-level host
control. Scope accounts/keys accordingly and isolate the host. This is stated
plainly so it can be designed around rather than discovered.

## Reporting a vulnerability

Open a private security advisory on the GitHub repository, or open an issue
without exploit detail and request a private channel. Please do not file
public issues containing working exploit payloads. Indicative response
target: 7 days to triage.

## Scope

In scope: authentication/authorization bypass, audit-trail evasion, policy
(tier) bypass, secret leakage into logs, sandbox-escape-equivalent privilege
gain *beyond the documented service-account posture*, transport handling.

Out of scope: the documented unsandboxed full-access posture itself, and the
ability of a correctly authenticated, policy-permitted caller to run
commands - that is the intended function.
