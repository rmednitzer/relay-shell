# Relay Shell

[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/rmednitzer/relay-shell)

A highly reliable, maximally capable [Model Context Protocol](https://modelcontextprotocol.io)
server for **complete shell and SSH mastery**.

`relay-shell` gives an MCP client (Claude, or any MCP-compatible agent) a robust,
auditable interface to operate a Linux host and a fleet of remote hosts over
SSH: one-shot command execution, long-lived interactive PTY sessions, scripted
runs, SFTP transfer, port forwarding, and host-inventory aware connectivity.

It is designed as **operator infrastructure tooling for hosts you own and
administer**. The default operating posture is native, full access (no
sandbox), matching the way real administration is performed, paired with the
defensive controls a production operator actually needs: an append-only,
output-hashed audit trail; a tiered-authority policy layer; secret redaction;
strict resource and timeout bounds; and an optional OAuth 2.1 edge.

The architecture, security model, and deployment patterns are modeled on a
mature production MCP gateway and on established operational best practices.

## Why

Engineers SSH into hosts and run commands from memory, with no structured
reasoning trail and no pre-execution review. A well-built MCP relay improves
on that baseline: every action is captured with arguments, an output hash, an
exit code, and a tier classification; limits and timeouts are enforced
centrally; failure paths never crash the transport. The reasoning layer sits
*inside* the loop and can assess blast radius before acting.

## Capabilities

### Local shell

| Tool | Purpose |
|------|---------|
| `shell_exec` | Run a command. Timeout/output clamps, cwd, env overlay, stdin, exit code. |
| `shell_script` | Run a multi-line script (bash/sh/python), optional `set -euo pipefail`. |
| `shell_spawn` | Start a persistent PTY session (REPLs, TUIs, prompts, long jobs). |

### SSH

| Tool | Purpose |
|------|---------|
| `ssh_exec` | Run a command on a remote host (jump host, key/agent, known-hosts policy). |
| `ssh_spawn` | Interactive remote PTY session. |
| `ssh_upload` / `ssh_download` | SFTP transfer (recursive supported). |
| `ssh_forward` | Local (`L`), remote (`R`), or dynamic SOCKS (`D`) forwarding. |
| `ssh_forward_list` / `ssh_forward_close` | Manage active forwards. |
| `ssh_check` | Connectivity probe across the inventory or a host list. |
| `ssh_fanout` | Run a command in parallel across hosts; per-host exit codes in one JSON. |
| `ssh_keyscan` | Fetch host public keys via `ssh-keyscan` (pre-populate `known_hosts` for `strict`). |
| `ssh_hosts` | Resolved host inventory (`~/.ssh/config` + inventory file). |

### Sessions (local PTY and SSH PTY, unified)

| Tool | Purpose |
|------|---------|
| `session_send` | Send input (optionally with Enter) to a session. |
| `session_recv` | Read buffered/new output, with a short wait. |
| `session_resize` | Resize the PTY (cols x rows). |
| `session_kill` | Signal / terminate a session. |
| `session_list` | List active sessions with metadata. |

### Diagnostics

| Tool | Purpose |
|------|---------|
| `server_info` | Server version, effective limits, policy mode, audit path. |
| `audit_tail` | Return the last N audit records (read-only, Tier 0). |

The HTTP transport also exposes `GET /metrics` (Prometheus text format):
`relay_shell_tool_calls_total{tool,tier,mode,outcome}` (counter), plus
`relay_shell_active_sessions`, `relay_shell_active_forwards`, and
`relay_shell_audit_degraded` (gauges). See
[`docs/deployment.md`](docs/deployment.md) §9a.

### Resources

Three MCP resources let clients read inventory and `ssh_config` views
the protocol-native way (no tool call needed):

| URI                                  | meaning                              |
|--------------------------------------|--------------------------------------|
| `relay-shell://inventory`            | Flat list of all known hosts (JSON). |
| `relay-shell://inventory/{host}`     | One host's resolved spec (JSON).     |
| `relay-shell://ssh-config`           | ssh_config path + aliases (JSON).    |

Resource reads are audited (tier 0). See
[`docs/tools.md`](docs/tools.md) for the full reference.

Full reference: [`docs/tools.md`](docs/tools.md).

## Quickstart

Requires Python 3.12+ (CPython, tested on Ubuntu 24.04).

```bash
git clone https://github.com/rmednitzer/relay-shell.git && cd relay-shell
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"

# stdio transport (local agent / Claude Desktop / MCP Inspector)
relay-shell

# HTTP transport (streamable-http on 127.0.0.1:8080)
RELAY_SHELL_TRANSPORT=http relay-shell

# Validate config without starting the transport (useful for image bakes)
relay-shell --check-config

# Drift-detect shipped templates against /etc/... (useful in production cron)
relay-shell --verify-deploy
```

Register with an MCP client (stdio):

```json
{ "mcpServers": { "relay-shell": { "command": "relay-shell" } } }
```

Configuration is environment-driven; see [`.env.example`](.env.example) and
[`docs/deployment.md`](docs/deployment.md).

## Security posture

`relay-shell` runs unsandboxed with the privileges of its service account by design
(see [`docs/adr/0002-no-sandbox-full-access.md`](docs/adr/0002-no-sandbox-full-access.md)):
sandboxing the process would defeat the very capability it exists to provide.
Safety is achieved with **compensating controls**, not by crippling the tool:

- **Audit** - every invocation appended as one JSON line with a SHA-256 hash
  of the output (never the output body), byte length, exit code, request and
  client id, and the assessed tier. Append-only on disk; rotation-safe handler.
- **Tiered authority** - every call is classified Tier 0..3
  ([`docs/adr/0003-tiered-authority.md`](docs/adr/0003-tiered-authority.md)).
  `RELAY_SHELL_POLICY_MODE` selects `open` (default), `guarded`, or `readonly`.
- **Redaction** - audited arguments are scrubbed for tokens, keys, and
  `Authorization` material.
- **Bounds** - timeout and output caps on every tool; bounded session count
  and buffers; idle/lifetime reaping.
- **Optional OAuth 2.1** - DCR with single-client lockdown, PKCE, file-backed
  rotating tokens, lazy expiry (HTTP transport).
- **Edge** - parameterized Caddy config restricts the endpoint to known
  CIDRs with security headers and automated TLS (ACME / Let's Encrypt)
  installed via `deploy/install-edge.sh`; systemd unit applies resource
  caps.

This server grants real administrative power. Run it only as a scoped service
account, only on hosts you are authorized to administer, behind the network
controls in [`docs/deployment.md`](docs/deployment.md). See
[`SECURITY.md`](SECURITY.md) for the threat model and reporting.

If your use case requires maximum model capability, `relay-shell` also supports
an explicit privileged posture (root/sudo workflows). Use that only on isolated
administrative hosts with strict network controls and full audit shipping.

## Layout

```
src/relay_shell/   server, config, audit, policy, redaction, sessions,
                   shelltools, sshpool, inventory, errors, util, auth
deploy/            systemd unit + hardening drop-in, Caddyfile, logrotate, installers
docs/              architecture, tool reference, deployment, ADRs
tests/             unit + integration (in-process SSH server, no network)
```

## Development

```bash
ruff check . && ruff format --check .
mypy
pytest
```

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for scope, branch naming,
the local development loop, and how security-sensitive PRs are
reviewed. [`docs/runbook.md`](docs/runbook.md) is the canonical
procedure for audit, review, validate, enhance, and extend tasks.
Participation is governed by the
[Code of Conduct](CODE_OF_CONDUCT.md).

## AI contributor guidance

- [`AGENTS.md`](AGENTS.md) - repository-wide agent operating contract
- [`CLAUDE.md`](CLAUDE.md) - Claude-focused development and review guidance

## License

Apache-2.0. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
