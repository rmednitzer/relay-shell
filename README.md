# Relay Shell

**Status:** v0.3.0 · Python 3.12 / 3.13 / 3.14 · transports: `stdio` and
`streamable-http` · MCP SDK `mcp>=2,<3` · pin history in
[ADR 0001](docs/adr/0001-runtime-and-sdk.md); validation procedure and its recorded
passes (latest 2026-06-21, before the `mcp` v2 move) in
[ADR 0005](docs/adr/0005-codebase-validation.md).

`relay-shell` is a [Model Context Protocol](https://modelcontextprotocol.io) server that
gives an MCP client (Claude, or any MCP-compatible agent) the full reach of a shell: run any
command on the local host, hold interactive PTY sessions, run scripts, operate a fleet over
SSH, move files with SFTP and open port forwards.

It is **operator infrastructure for hosts you own and administer**, and it is **open by
default**: nothing is refused because of what a command does. It runs with the privileges of
its service account, with no sandbox ([ADR 0002](docs/adr/0002-no-sandbox-full-access.md)).
What it adds is the record and the warning:

- **Every call is audited.** One JSON line with the redacted arguments, a hash and length of
  the output (never the body), the exit code, the client and the assessed tier.
- **Every risky call says so.** A call that ran as Tier 2 (changes state) or Tier 3
  (irreversible), or that used SSH with host-key checking off, gets a trailing `[NOTICE ...]`
  line. `server_info` lists the standing unsafe settings. See
  [ADR 0013](docs/adr/0013-open-by-default-with-unsafe-notices.md).
- **Refusal is opt-in.** `guarded` and `readonly` modes, a deny list and a Tier-3
  confirmation step exist for deployments that want a gate. None is on by default.

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
| `ssh_forward` | Local (`L`), remote (`R`), or dynamic SOCKS (`D`) forwarding; `L`/`D` listen on loopback only. |
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
| `audit_tail` | Return recent audit records as JSONL, optionally filtered by `tool`/`tier`/`denied` (read-only, Tier 0). |
| `operation_confirm` | Arm a Tier-3 confirmation token (opt-in broker, ADR 0009), then re-issue the call. |

The HTTP transport also exposes `GET /metrics` (Prometheus text format):
`relay_shell_tool_calls_total{tool,tier,mode,outcome}`,
`relay_shell_seccomp_notify_events_total{syscall}`, and
`relay_shell_seccomp_notify_overflow_total` (counters), plus
`relay_shell_active_sessions`, `relay_shell_active_forwards`, and
`relay_shell_audit_degraded` (gauges). See
[`docs/deployment.md`](docs/deployment.md) §9a.

### Resources

Three MCP resources expose inventory and `ssh_config` views without a tool call:

| URI                                  | meaning                              |
|--------------------------------------|--------------------------------------|
| `relay-shell://inventory`            | Flat list of all known hosts (JSON). |
| `relay-shell://inventory/{host}`     | One host's resolved spec (JSON).     |
| `relay-shell://ssh-config`           | ssh_config path + aliases (JSON).    |

Resource reads are audited (tier 0).

### Prompts

One MCP prompt, `operating_guide`, carries the detailed "when to use which tool" guidance
(one-shot command vs persistent PTY session, the spawn+session workflow, fleet and transfer
entry points), complementing the concise `instructions` string handed to clients at
initialize. A fetch is audited (tier 0, `prompt:operating_guide`) like a resource read;
listing is not ([ADR 0008](docs/adr/0008-operating-guidance-prompt.md)).

Full reference for every tool, resource and prompt: [`docs/tools.md`](docs/tools.md).

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

# Validate config without starting the transport; prints the unsafe-setting notes
relay-shell --check-config

# Drift-detect shipped templates against /etc/... (useful in production cron)
relay-shell --verify-deploy
```

Register with an MCP client (stdio):

```json
{ "mcpServers": { "relay-shell": { "command": "relay-shell" } } }
```

Configuration is environment-driven (`RELAY_SHELL_*`, optionally a `.env`); see
[`.env.example`](.env.example) and [`docs/deployment.md`](docs/deployment.md).

## What is and is not blocked

With the default configuration the policy layer admits every command on every tool,
including `rm -rf /`, `mkfs`, `dd` to a block device, `shutdown`, `curl | sh` and `sudo`.
`tests/test_notices.py` pins this. The call is classified and audited, and if it is risky
the result ends with a notice:

```text
[exit 0]
...command output...
[NOTICE tier 3 (IRREVERSIBLE), matched an irreversible-operation pattern. It may not be
undoable and ran with no confirmation step; verify the target and take a backup or snapshot
first. Classification is a heuristic, not a boundary]
```

The classifier is a regex heuristic over the command text, not a parse of the shell
language. **A call without a notice is not thereby safe**, and a notice is not a block.

What does still refuse a call are resource bounds and one startup check, each with a
setting, none of them about what the command does:

| Bound | Setting | Behaviour |
|-------|---------|-----------|
| Input size (command + stdin + script + env) | `RELAY_SHELL_MAX_INPUT` (2 MiB) | refused, because the policy scan is synchronous |
| Wall-clock per call | `RELAY_SHELL_MAX_TIMEOUT` (900 s) | killed; use `shell_spawn` / `ssh_spawn` for longer work |
| Live sessions / forwards | `RELAY_SHELL_MAX_SESSIONS` (64), `RELAY_SHELL_MAX_FORWARDS` (64) | a new one is refused at the cap |
| Output returned | `RELAY_SHELL_MAX_OUTPUT` (64 KiB) | truncated, not refused |
| HTTP listener without OAuth on a non-loopback address | `RELAY_SHELL_ALLOW_UNAUTH_NETWORK` | refused at startup unless set |

### Making it stricter

Each of these is opt-in; combine them as the deployment needs.

| Want | Setting |
|------|---------|
| Refuse state-changing calls unless allow-listed | `RELAY_SHELL_POLICY_MODE=guarded` + `RELAY_SHELL_POLICY_ALLOW` |
| Observe only | `RELAY_SHELL_POLICY_MODE=readonly` |
| Refuse specific text (always enforced first, in every mode) | `RELAY_SHELL_POLICY_DENY` |
| Two-step confirmation for Tier-3 calls | `RELAY_SHELL_CONFIRM_TIER3=true` |
| Verified SSH host keys, no per-call downgrade | `RELAY_SHELL_SSH_KNOWN_HOSTS=strict`, `RELAY_SHELL_SSH_ALLOW_WEAKER_KNOWN_HOSTS=false` |
| Tamper-evident audit | `RELAY_SHELL_AUDIT_CHAIN=true`, plus the off-host sync in `deploy/evidence/` |
| Authenticated HTTP transport | `RELAY_SHELL_AUTH_ENABLED=true` (OAuth 2.1) behind the Caddy edge |
| Silence the `[NOTICE]` lines | `RELAY_SHELL_UNSAFE_NOTICES=false` |

## Compatibility matrix

| Surface           | Supported                                                  | Notes                                                                                  |
|-------------------|------------------------------------------------------------|----------------------------------------------------------------------------------------|
| Python            | 3.12 / 3.13 / 3.14                                         | CI runs the full matrix; package floor is `>=3.12`.                                    |
| Host OS (tested)  | Ubuntu 24.04 LTS                                           | Validation is run against this image; the systemd + Caddy installers assume it.        |
| Host OS (dev)     | macOS                                                      | Unsupported for production; `pty`/SSH paths work for local development.                |
| Host OS (other)   | Windows                                                    | Not a host (no PTY contract, no systemd). Windows is supported as an SSH *target* over OpenSSH + PowerShell ([ADR 0011](docs/adr/0011-windows-openssh-powershell.md)). |
| Transports        | `stdio`, `streamable-http`                                 | Stdio is the default. HTTP binds loopback and requires a TLS edge (see `deployment.md`). |
| SDK               | `mcp>=2,<3` (pinned: `requirements.txt`)                   | Range-pinned since the v2 migration (ADR 0001); bumps trigger a fresh validation pass. |
| SSH library       | `asyncssh>=2.23.0,<3` (tested at 2.24.1)                   | Native async; no shell-out to system `ssh` (only `ssh_keyscan` runs `ssh-keyscan`).    |

## Security posture

The server grants real administrative power. Run it only as a scoped service account, only on
hosts you are authorized to administer, behind the network controls in
[`docs/deployment.md`](docs/deployment.md). A privileged (root/sudo) deployment is supported
for isolated administrative hosts with strict network controls and full audit shipping.
[`SECURITY.md`](SECURITY.md) has the threat model and how to report a vulnerability.

Nothing is sandboxed or blocked by default, so the controls keep the record honest and the
surface small:

- **Audit** - one JSON line per invocation, append-only on disk with a rotation-safe handler.
  An optional per-record hash chain ([ADR 0007](docs/adr/0007-audit-hash-chain.md)) makes edits, insertions, reorders and
  interior deletions detectable with `relay-shell --verify-audit`, which is fail-closed;
  tail-truncation needs the off-host copy.
- **Syscall visibility** (optional) - `RELAY_SHELL_SECCOMP_NOTIFY`
  ([ADR 0006](docs/adr/0006-seccomp-notify-audit-channel.md)) adds an audit-only seccomp
  user-notify channel for a spawned child's `execve`, privilege, namespace, mount,
  write-`open` and privilege-relevant `prctl` syscalls. It never blocks a syscall and installs
  only with `CAP_SYS_ADMIN`.
- **Tiered authority** - every call is classified Tier 0..3
  ([ADR 0003](docs/adr/0003-tiered-authority.md)); the tier drives the notice, the audit field
  and, if you enable them, the stricter modes.
- **Redaction** - audited arguments are scrubbed for tokens, keys and `Authorization`
  material. Heuristic; tested with synthetic secrets.
- **Bounds** - timeout and output caps on every tool, bounded session count and buffers,
  idle and lifetime reaping.
- **Optional OAuth 2.1** - dynamic client registration with an operator approval gate, PKCE,
  rotating refresh tokens with reuse detection, file-backed (HTTP transport; **off by
  default**). See [`docs/auth.md`](docs/auth.md).
- **Edge** - a parameterized Caddy config restricts the MCP endpoint to known CIDRs, adds
  security headers, caps the public OAuth request bodies and keeps authorization codes out of
  the access log; automated TLS via ACME. Installed with `deploy/install-edge.sh`; the systemd
  unit applies resource caps.

## Layout

```
src/relay_shell/   server, config, audit, policy, patterns, redaction, broker,
                   sessions, shelltools, sshpool, inventory, seccomp, metrics,
                   verifier, errors, util, auth/ (oauth, resource, admin)
deploy/            systemd unit + hardening drop-in, Caddyfile, logrotate,
                   installers, evidence/ (off-host audit sync), monitoring/
docs/              architecture, tool reference, deployment, auth, runbook,
                   audit shipper, release trust, ADRs
tests/             unit + integration (in-process SSH server, no network)
```

## Development

```bash
ruff check . && ruff format --check .
mypy
pytest
```

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for scope, branch naming, the local development loop
and how security-sensitive PRs are reviewed. [`docs/runbook.md`](docs/runbook.md) is the
canonical procedure for audit, review, validate, enhance and extend tasks, plus the
prioritized backlog. Participation is governed by the [Code of Conduct](CODE_OF_CONDUCT.md).

## AI contributor guidance

[`AGENTS.md`](AGENTS.md) is the repository-wide agent operating contract;
[`CLAUDE.md`](CLAUDE.md) adds Claude-focused development and review guidance.

## License

Apache-2.0. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
