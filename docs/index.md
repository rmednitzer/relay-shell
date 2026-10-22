---
title: Overview
---

# relay-shell documentation

A [Model Context Protocol](https://modelcontextprotocol.io) server for **complete shell and
SSH operation**: local commands and scripts, interactive PTY sessions, fleet operation over
SSH, SFTP transfers and port forwards. Current release: **[v0.5.0](https://github.com/rmednitzer/relay-shell/releases/tag/v0.5.0)** (2026-10-22).

It is operator infrastructure for hosts you own and administer. It runs with the privileges
of its service account, with no sandbox, and it is **open by default**: with the default
settings no command is refused for what it does. What it adds is a record and a warning:

- **Every call is audited:** one JSON line with the redacted arguments, the output's SHA-256
  and length (never its body), the exit code, the client and the assessed tier; an optional
  hash chain makes the log tamper-evident.
- **Every risky call says so:** an admitted Tier 2 (changes state) or Tier 3 (irreversible)
  call, or an SSH call with host-key checking off, ends with a `[NOTICE ...]` line, and
  `server_info.warnings` lists the permissive settings in effect. The tier comes from a regex
  heuristic: a call without a notice is not thereby safe.
- **Refusal is opt-in:** `guarded` and `readonly` modes, a deny list and a Tier-3
  confirmation step are available and all off by default.
- **Everything is bounded:** timeouts, output, input size, sessions, forwards and cached SSH
  connections all have configured caps.

This site is generated from the
[`docs/`](https://github.com/rmednitzer/relay-shell/tree/main/docs) folder. For
the project overview and install steps see the
[README](https://github.com/rmednitzer/relay-shell#readme); for the threat model
and supported versions see
[`SECURITY.md`](https://github.com/rmednitzer/relay-shell/blob/main/SECURITY.md); for
what changed in each release see the
[`CHANGELOG`](https://github.com/rmednitzer/relay-shell/blob/main/CHANGELOG.md).

## Guides

- [Architecture](architecture.md): the request lifecycle, the module map, and the trust boundary.
- [Tool reference](tools.md): every MCP tool, resource, and prompt, with tiers and tests.
- [Deployment](deployment.md): service account, network edge (Caddy + ACME), OAuth, and audit shipping.
- [Authentication](auth.md): the OAuth 2.1 lifecycle. OAuth is opt-in (off by default); once on, new clients need operator approval by default, and unauthenticated HTTP is refused off loopback.
- [Audit shipping](audit-shipper.md): Vector, Fluent Bit, and `systemd-journal-remote` recipes.
- [Release trust](release-trust.md): how release tags are verified, the signing evidence per release, and what a signature does and does not establish.
- [Maintenance runbook](runbook.md): the audit / review / validate / enhance / extend procedures and the backlog.

## Architecture Decision Records

The [ADR index](adr/README.md) records every decision with its status and date, among them
the no-sandbox full-access posture (0002), tiered authority (0003), edge-TLS
automation (0004), the seccomp-notify audit channel (0006), the audit hash
chain (0007), the Tier-3 confirmation broker (0009), Windows targets over
OpenSSH + PowerShell (0011), cancel-safe session teardown (0012) and the open-by-default
posture with unsafe-operation notices (0013), and
[fresh-process syscall auditing and installer recovery qualification](adr/0014-seccomp-launch-and-install-recovery.md) (0014).

---

*Source: [github.com/rmednitzer/relay-shell](https://github.com/rmednitzer/relay-shell) · Apache-2.0 licensed.*
