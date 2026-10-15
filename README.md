# Relay Shell

v0.3.0 · Python 3.12 / 3.13 / 3.14 · transports `stdio` and `streamable-http` · MCP SDK
`mcp>=2,<3` · Apache-2.0

`relay-shell` is a [Model Context Protocol](https://modelcontextprotocol.io) server that gives
an MCP client the full reach of a shell: run commands on the local host, hold interactive PTY
sessions, run scripts, operate a fleet over SSH, move files with SFTP and open port forwards.

It is operator infrastructure for hosts you own and administer. It runs with the privileges of
its service account, with no sandbox, and it is **open by default**: no command is refused for
what it does. What it adds is a record and a warning:

- **Every call is audited:** one JSON line with the redacted arguments, the output's hash and
  length (never its body), the exit code, the client and the assessed tier.
- **Every risky call says so:** a call classified Tier 2 (changes state) or Tier 3
  (irreversible), or an SSH call with host-key checking off, ends with a `[NOTICE ...]` line.
  `server_info` lists the standing unsafe settings.
- **Refusal is opt-in:** `guarded` and `readonly` modes, a deny list and a Tier-3 confirmation
  step are available and all off by default.

## Tools

| Local shell | Purpose |
|------|---------|
| `shell_exec` | Run a command with timeout and output caps, cwd, env overlay and stdin. |
| `shell_script` | Run a multi-line bash, sh or python script, optionally under `set -euo pipefail`. |
| `shell_spawn` | Start a persistent PTY session (REPLs, TUIs, prompts, long jobs). |

| SSH | Purpose |
|------|---------|
| `ssh_exec` | Run a command on a remote host (jump host, key or agent, known-hosts policy). |
| `ssh_spawn` | Start an interactive remote PTY session. |
| `ssh_upload` / `ssh_download` | SFTP transfer, recursive supported. |
| `ssh_forward` | Local (`L`), remote (`R`) or dynamic SOCKS (`D`) forward; `L`/`D` listen on loopback only. |
| `ssh_forward_list` / `ssh_forward_close` | List or close active forwards. |
| `ssh_check` | Probe connectivity across the inventory or a host list. |
| `ssh_fanout` | Run one command on many hosts in parallel; per-host exit codes in one JSON. |
| `ssh_keyscan` | Fetch host keys with `ssh-keyscan` to pre-populate `known_hosts`. |
| `ssh_hosts` | Show the resolved inventory (`~/.ssh/config` plus the inventory file). |

| Sessions (local and SSH PTY) | Purpose |
|------|---------|
| `session_send` | Send input, optionally followed by Enter. |
| `session_recv` | Read buffered and new output, with a short wait. |
| `session_resize` | Resize the PTY. |
| `session_kill` | Signal or terminate a session. |
| `session_list` | List active sessions. |

| Diagnostics | Purpose |
|------|---------|
| `server_info` | Version, effective limits, policy mode, audit path, unsafe-setting warnings. |
| `audit_tail` | Read recent audit records, filterable by `tool`, `tier` and `denied`. |
| `operation_confirm` | Arm a Tier-3 confirmation token when that opt-in step is enabled. |

The server also exposes three read-only MCP resources (`relay-shell://inventory`,
`relay-shell://inventory/{host}`, `relay-shell://ssh-config`) and one prompt,
`operating_guide`, with guidance on which tool to use when; resource reads and prompt fetches
are audited too. Full reference: [`docs/tools.md`](docs/tools.md). Over HTTP, `GET /metrics`
serves Prometheus counters and gauges ([`docs/deployment.md`](docs/deployment.md) §9a).

## Quickstart

Requires CPython 3.12 or later; tested on Ubuntu 24.04.

```bash
git clone https://github.com/rmednitzer/relay-shell.git && cd relay-shell
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"

relay-shell                              # stdio transport
RELAY_SHELL_TRANSPORT=http relay-shell   # streamable-http on 127.0.0.1:8080
relay-shell --check-config               # validate config, print unsafe-setting notes
relay-shell --verify-deploy              # compare installed templates with the shipped ones
```

Register with an MCP client (stdio):

```json
{ "mcpServers": { "relay-shell": { "command": "relay-shell" } } }
```

Configuration comes from `RELAY_SHELL_*` environment variables, optionally via a `.env` file;
see [`.env.example`](.env.example) and [`docs/deployment.md`](docs/deployment.md).

## Default behaviour

With the default configuration every command on every tool is admitted, including `rm -rf /`,
`mkfs`, `dd` to a block device, `shutdown`, `curl | sh` and `sudo` (pinned by
`tests/test_notices.py`). The call is classified and audited, and a risky one ends with a
notice:

```text
[exit 0]
...command output...
[NOTICE tier 3 (IRREVERSIBLE), matched an irreversible-operation pattern. It may not be
undoable and ran with no confirmation step; verify the target and take a backup or snapshot
first. Classification is a heuristic, not a boundary]
```

The classifier is a regex heuristic over the command text, not a parse of the shell language.
A call without a notice is not thereby safe, and a notice does not block anything.

Only resource bounds and one startup check refuse a call, none of them based on what the
command does:

| Bound | Setting (default) | Behaviour |
|-------|-------------------|-----------|
| Input size (command, stdin, script, env) | `RELAY_SHELL_MAX_INPUT` (2 MiB) | refused, because the policy scan is synchronous |
| Wall-clock per call | `RELAY_SHELL_MAX_TIMEOUT` (900 s) | killed; use `shell_spawn` / `ssh_spawn` for longer work |
| Live sessions / forwards | `RELAY_SHELL_MAX_SESSIONS` (64), `RELAY_SHELL_MAX_FORWARDS` (64) | a new one is refused at the cap |
| Output returned | `RELAY_SHELL_MAX_OUTPUT` (64 KiB) | truncated, not refused |
| HTTP without OAuth on a non-loopback address | `RELAY_SHELL_ALLOW_UNAUTH_NETWORK` | refused at startup unless set |

Session output buffers are also bounded, and idle sessions (`RELAY_SHELL_SESSION_IDLE_TIMEOUT`,
1800 s) and exited, drained sessions are reaped.

### Making it stricter

Every option below is opt-in and they combine:

| Want | Setting |
|------|---------|
| Refuse state-changing calls unless allow-listed | `RELAY_SHELL_POLICY_MODE=guarded` + `RELAY_SHELL_POLICY_ALLOW` |
| Observe only | `RELAY_SHELL_POLICY_MODE=readonly` |
| Refuse specific text (checked first, in every mode) | `RELAY_SHELL_POLICY_DENY` |
| Two-step confirmation for Tier-3 calls | `RELAY_SHELL_CONFIRM_TIER3=true` |
| Verified SSH host keys, no per-call downgrade | `RELAY_SHELL_SSH_KNOWN_HOSTS=strict`, `RELAY_SHELL_SSH_ALLOW_WEAKER_KNOWN_HOSTS=false` |
| Tamper-evident audit | `RELAY_SHELL_AUDIT_CHAIN=true`, plus the off-host sync in `deploy/evidence/` |
| Authenticated HTTP transport | `RELAY_SHELL_AUTH_ENABLED=true` (OAuth 2.1) behind the Caddy edge |
| Silence the `[NOTICE]` lines | `RELAY_SHELL_UNSAFE_NOTICES=false` |

## Security

The server grants real administrative power. Run it as a scoped service account, only on hosts
you are authorized to administer, behind the network controls in
[`docs/deployment.md`](docs/deployment.md). A privileged (root or sudo) deployment is supported
for isolated administrative hosts with strict network controls and full audit shipping.
[`SECURITY.md`](SECURITY.md) has the threat model and how to report a vulnerability.

Besides the audit record, notices and bounds above:

- **Audit integrity:** the log is append-only on disk with a rotation-safe handler. The optional
  hash chain makes edits, insertions, reorders and interior deletions detectable with
  `relay-shell --verify-audit` (fail-closed); detecting tail truncation needs the off-host copy.
- **Redaction:** audited arguments are scrubbed of tokens, keys and `Authorization` material.
  Heuristic; tested with synthetic secrets.
- **Syscall visibility (optional):** `RELAY_SHELL_SECCOMP_NOTIFY` records a spawned child's
  `execve`, privilege, namespace, mount, write-`open` and privilege-relevant `prctl` syscalls.
  It never blocks a syscall and installs only with `CAP_SYS_ADMIN`.
- **OAuth 2.1 (optional, off by default):** dynamic client registration behind an operator
  approval gate, PKCE, rotating refresh tokens with reuse detection. See
  [`docs/auth.md`](docs/auth.md).
- **Edge:** the Caddy config from `deploy/install-edge.sh` restricts the MCP endpoint to known
  CIDRs, adds security headers, caps public OAuth request bodies, keeps authorization codes out
  of the access log and automates TLS via ACME. The systemd unit applies resource caps.

## Compatibility

| Surface | Supported | Notes |
|---------|-----------|-------|
| Python | 3.12 / 3.13 / 3.14 | CI runs the full matrix. |
| Host OS | Ubuntu 24.04 LTS | Tested; the systemd and Caddy installers assume it. macOS works for development only. |
| Windows | SSH target only | Over OpenSSH with PowerShell 7; not supported as a host (no PTY contract, no systemd). |
| Transports | `stdio`, `streamable-http` | stdio is the default; HTTP binds loopback and needs a TLS edge. |
| MCP SDK | `mcp>=2,<3` | Pinned in `requirements.txt`; a bump triggers a fresh validation pass. |
| SSH library | `asyncssh>=2.23.0,<3` (tested 2.24.1) | Native async; no shell-out to the system `ssh` (only `ssh_keyscan` runs `ssh-keyscan`). |

## Development

```bash
ruff check . && ruff format --check .
mypy
pytest
```

Layout: `src/relay_shell/` (server and modules), `deploy/` (systemd unit, Caddyfile, logrotate,
installers, off-host audit sync, monitoring), `docs/` (start at
[`docs/index.md`](docs/index.md)), `tests/` (unit and integration; an in-process SSH server,
no network).

[`CONTRIBUTING.md`](CONTRIBUTING.md) covers scope, branch naming, the local loop and review of
security-sensitive changes; [`docs/runbook.md`](docs/runbook.md) holds the audit, review and
validation procedures and the backlog. AI agents follow [`AGENTS.md`](AGENTS.md) (with
[`CLAUDE.md`](CLAUDE.md) for Claude). Participation is governed by the
[Code of Conduct](CODE_OF_CONDUCT.md).

## License

Apache-2.0. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
