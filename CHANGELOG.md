# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- GitHub PR template and bug / feature / security issue templates under
  `.github/`. The PR template encodes the runbook §3.1 cross-reference
  checklist and the §3.3 security-sensitive-diff confirmations so they
  travel with every PR.
- Maintenance runbook at `docs/runbook.md` covering audit, review,
  validate, enhance, and extend procedures, a prioritized backlog
  (capability, quality, ops, docs, security hardening), and a per-file
  `.md` update plan.
- Automated TLS at the edge: `deploy/Caddyfile` is now parameterized via
  env variables and `deploy/install-edge.sh` provisions Caddy with ACME
  (Let's Encrypt by default) for hands-off issuance and renewal.
- ADR 0004 documenting the edge-TLS automation choice and rejected
  alternatives (certbot + cron, native TLS in the Python service).

### Changed

- `.env.example` and `docs/deployment.md` document the new
  `RELAY_SHELL_EDGE_*` variables and the one-shot install flow.
- Bumped MCP SDK: `mcp` 1.26.0 → 1.27.1 (tracked by Dependabot, validated
  by the existing test suite). ADR 0001 and `docs/architecture.md` updated
  to match the actual pin.

### Fixed

- `shell_exec` no longer permits policy/audit bypass through `stdin` or
  `env_json`: the policy-text probe now includes both, so a deny pattern
  that matches a command also matches the same payload smuggled in via
  stdin or an environment variable.
- Audit log creation uses `O_APPEND | O_CREAT` so the sink opens
  successfully on files hardened with `chattr +a`; the pre-create no
  longer races a stat/chmod path that an append-only attribute would
  reject.
- Argument redaction now covers single-dash long-name CLI flags
  (`-token=val`, `-password val`) and dash-prefixed secret values
  (`--token -abc123`), with escape-aware quoted-value handling. Compact
  `-p<value>` is redacted only inside MySQL-family invocations to avoid
  over-redacting `-p22` (ssh), `-p1-1000` (nmap), and similar overloads.
- File OAuth provider writes its JSON store with explicit `0o700`
  directory and `0o600` file modes regardless of the caller's umask.

### Security

- Treat the audit log as evidence only until shipped off-host; the
  bundled logrotate config drops and restores the append-only attribute
  across rotation. See `docs/deployment.md` §6.

## [0.1.0] - 2026-05-19

### Added

- Initial release: a Model Context Protocol server for shell and SSH
  operations, built on the official `mcp` SDK (FastMCP), `asyncssh`, and
  `pydantic-settings`.
- Local shell: `shell_exec`, `shell_script`, `shell_spawn`.
- SSH: `ssh_exec`, `ssh_spawn`, `ssh_upload`, `ssh_download`,
  `ssh_forward` (L/R/D), `ssh_forward_list`, `ssh_forward_close`,
  `ssh_check`, `ssh_hosts`.
- Unified session control for local and SSH PTYs: `session_send`,
  `session_recv`, `session_resize`, `session_kill`, `session_list`.
- `server_info` diagnostics tool.
- Append-only JSONL audit log with SHA-256 output hashing, argument
  redaction, and a rotation-safe handler.
- Tiered-authority policy layer (`open` / `guarded` / `readonly`) with
  always-on deny list and Tier 0..3 classification.
- Optional OAuth 2.1 provider for the HTTP transport: DCR with
  single-client lockdown, PKCE, file-backed rotating tokens, lazy expiry.
- stdio and streamable-HTTP transports.
- Deployment assets: systemd unit + hardening drop-in, reference Caddyfile,
  logrotate config, idempotent installer.
- Test suite: unit coverage plus an in-process `asyncssh` integration
  fixture (no network, no live credentials).
- Documentation: architecture, full tool reference, deployment guide, and
  three ADRs (runtime/SDK choice, no-sandbox posture, tiered authority).
