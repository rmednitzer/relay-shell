# Tool reference

Every tool returns a single string and is audited. `timeout` and output are
clamped to the configured limits. Each tool's default tier is shown; the
effective decision also depends on `RELAY_SHELL_POLICY_MODE` and the deny/allow lists.

**Tier reference** (see [`adr/0003-tiered-authority.md`](adr/0003-tiered-authority.md)):

| Tier | Name          | Meaning                                       |
|------|---------------|-----------------------------------------------|
| 0    | `READ_ONLY`   | Observe only; no local or remote state change.|
| 1    | `REVERSIBLE`  | Low blast radius; trivially undone.           |
| 2    | `STATEFUL`    | Visible impact a user or dependent notices.   |
| 3    | `IRREVERSIBLE`| High blast; rollback expensive or impossible. |

Mode semantics: `open` permits all but still classifies; `guarded`
refuses Tier 2+ unless `RELAY_SHELL_POLICY_ALLOW` matches; `readonly`
permits only Tier 0. `RELAY_SHELL_POLICY_DENY` is always enforced first.

Conventions:

- `host` is an inventory / `ssh_config` alias or `user@host`.
- `known_hosts` is `strict` | `accept-new` | `ignore` (default from
  `RELAY_SHELL_SSH_KNOWN_HOSTS`).
- `jump` is an `ssh_config`-style `user@host[:port]` bastion (asyncssh
  `tunnel`); `ssh_config` `ProxyJump` is also honoured automatically.

Each tool entry below lists the test file that exercises it. Line
numbers are intentionally omitted — they drift; the file name is the
stable handle. The tool-list contract itself lives in
`tests/test_server.py`.

## Choosing a tool

The same guidance the server hands the client at initialize (the FastMCP
`instructions` string) and in each tool's description:

- A command that **runs and exits on its own** → `shell_exec` (local) or
  `ssh_exec` (remote). **Several statements** or a non-bash interpreter →
  `shell_script`.
- **Interactive or long-lived** work that needs a real TTY (a REPL, a TUI, a
  pager, a password prompt, a job you watch) → `shell_spawn` (local) or
  `ssh_spawn` (remote), then drive the returned session id with the
  `session_*` tools. Spawning and the session tools are **one workflow**, not
  alternatives: the spawn creates the PTY; `session_send` / `session_recv`
  drive it; `session_resize` / `session_kill` / `session_list` manage it.
- **Across many hosts** → `ssh_fanout` (and `ssh_check` / `ssh_hosts` to
  discover and probe first).

## Local shell

### `shell_exec`
Run a command on the local host; returns `[exit N]` + combined output.

Tests: `tests/test_shell.py`, `tests/test_tool_wrappers.py`.

| param | type | default | notes |
|-------|------|---------|-------|
| `command` | str | - | the command |
| `timeout` | int | 60 | clamped to `[1, RELAY_SHELL_MAX_TIMEOUT]` |
| `max_output` | int | 65536 | clamped to `[1024, RELAY_SHELL_MAX_OUTPUT_HARD]` |
| `cwd` | str | "" | working directory |
| `stdin` | str | "" | written to the process stdin |
| `merge_stderr` | bool | true | fold stderr into stdout |
| `use_shell` | bool | true | false = exec argv (no shell) |
| `env_json` | str | "" | JSON object overlaid on the environment |

Tier: heuristic (Tier 0..3 from the command text). Example:
`shell_exec(command="df -h")`.

### `shell_script`
Run a multi-line script fed on stdin. `interpreter` is `bash` | `sh` |
`python`. With `strict` and a shell interpreter, `set -euo pipefail` is
prepended. Tier: heuristic from the script text.

Tests: `tests/test_shell.py`, `tests/test_tool_wrappers.py`.

### `shell_spawn`
Start a persistent local PTY (default `/bin/bash`); returns a session id.
Params: `command`, `cols=120`, `rows=40`, `cwd`, `env_json`. Drive it with
the `session_*` tools. Tier 1.

Tests: `tests/test_sessions.py`, `tests/test_tool_wrappers.py`.

## SSH

### `ssh_exec`
Run a command on a remote host; returns `[exit N]` + combined output. Params:
`host`, `command`, `timeout=60`, `user`, `port`, `key_path`, `known_hosts`,
`jump`. Tier: heuristic from the command.

Tests: `tests/test_ssh_integration.py`, `tests/test_tool_wrappers.py`.

### `ssh_spawn`
Open a persistent interactive remote PTY; returns a session id. Params:
`host`, `command` (empty = login shell), `cols`, `rows`, plus the standard
connection params. Tier 1.

Tests: `tests/test_ssh_integration.py`, `tests/test_tool_wrappers.py`.

### `ssh_upload` / `ssh_download`
SFTP transfer. `ssh_upload(host, local_path, remote_path, recursive=false,
timeout=0, ...)`; `ssh_download(host, remote_path, local_path,
recursive=false, timeout=0, ...)`. `timeout` caps the transfer in seconds
(clamped to the server max); `0` (default) means no per-call cap, leaving only
the connection keepalive. A transfer that exceeds the cap returns a
`[TIMEOUT after Ns]` string. Tier 2 (mutating).

Tests: `tests/test_ssh_integration.py`, `tests/test_sshpool_unit.py`,
`tests/test_tool_wrappers.py`.

### `ssh_forward`
Create a port forward. `spec`:

- `L:lport:dhost:dport` - local forward.
- `R:rport:dhost:dport` - remote forward.
- `D:lport` - dynamic SOCKS proxy.

Returns a forward id and the listening port. Tier 2.

Tests: `tests/test_ssh_integration.py`, `tests/test_tool_wrappers.py`.

### `ssh_forward_list` / `ssh_forward_close`
List active forwards (`ssh_forward_list`, Tier 0) / close one by id
(`ssh_forward_close`, Tier 1).

Tests: `tests/test_ssh_integration.py`, `tests/test_tool_wrappers.py`.

### `ssh_check`
Probe connectivity. `hosts` is a comma/space list, or empty for the whole
inventory. Returns `host: ok | UNREACHABLE` per host. Tier 0.

Tests: `tests/test_ssh_integration.py`, `tests/test_tool_wrappers.py`.

### `ssh_fanout`
Run `command` in parallel across `hosts` (comma/space list, or empty for
the whole inventory). Returns one JSON object with per-host
`exit_code` and (truncated) `output`. `concurrency` bounds how many SSH
connections run at once (clamped to `[1, 32]`, default 8); the host
list is capped at 100 per call to bound the outbound burst. Tier
classification reads `command` like a regular `ssh_exec`: `ssh_fanout
rm -rf /` is still Tier 3, `ssh_fanout systemctl restart nginx` is
Tier 2, and the deny list and `guarded`/`readonly` modes see the same
probe text as a single-host call would.

Tests: `tests/test_ssh_fanout_tool.py`.

### `ssh_keyscan`
Shell out to `ssh-keyscan` to fetch each host's public key in
known_hosts line format. `hosts` is a comma/space list (required;
capped at 32 per call to bound the outbound TCP burst); `port`
defaults to 22; `key_types` is a comma list from
`{rsa, ecdsa, ed25519, dsa}` (default `rsa,ecdsa,ed25519`); `timeout`
is the per-host inner ssh-keyscan timeout (clamped to `[1, 60]`).
Hosts must match `[A-Za-z0-9._\-\[\]:]+` (rejecting shell
metacharacters at the boundary); every interpolated token is also
`shlex.quote`d for defence in depth, and a `--` separator is placed
before the host list so a leading-dash hostname cannot become a
getopt-style flag. Useful for pre-populating `~/.ssh/known_hosts` so
a service account can run `strict` without a manual `accept-new`
seeding pass. **Tier 1** (REVERSIBLE): it does not mutate the relay
but it opens caller-chosen outbound TCP connections, which puts it
outside the "observation-only" contract of `readonly` mode. Permitted
in `open` and `guarded`; rejected in `readonly`.

Tests: `tests/test_ssh_keyscan_tool.py`.

### `ssh_hosts`
Resolved inventory (`ssh_config` + JSON inventory). Tier 0.

Tests: `tests/test_inventory.py`, `tests/test_tool_wrappers.py`.

## Sessions (local PTY and SSH PTY, unified)

A session id from `shell_spawn` or `ssh_spawn` works with all of these.

| tool | params | notes |
|------|--------|-------|
| `session_send` | `session_id`, `data`, `enter=true` | `enter` appends `\n` |
| `session_recv` | `session_id`, `timeout=2.0`, `max_bytes=65536` | returns buffered/new output; waits up to `timeout`; returns `""` if nothing yet; reports `[session ... ended, exit=N]` when closed |
| `session_resize` | `session_id`, `cols`, `rows` | resize the PTY |
| `session_kill` | `session_id`, `signal_name="TERM"`, `close=true` | signal and (default) reap |
| `session_list` | - | active sessions with size/age/idle/byte counters |

`session_recv` is Tier 0; `session_list` is Tier 0; the others are Tier 1.

Tests: `tests/test_sessions.py`, `tests/test_tool_wrappers.py`.

## Diagnostics

### `server_info`
Version, transport, policy mode, effective limits, audit path / degraded
flag / format / chain (the tamper-evident hash chain state, ADR 0007),
seccomp-notify state (`notify` enabled, `supported` + `reason`, the per-call
`cap`, the `filter_version`; ADR 0006), the Tier-3 confirmation-broker state
(`confirm.tier3` enabled, `confirm.ttl`, live `confirm.pending` token count;
ADR 0009), SSH defaults (known-hosts mode, connect/keepalive/idle timeouts),
inventory size. Tier 0.

Tests: `tests/test_tool_wrappers.py`, `tests/test_stdio_e2e.py`.

### `audit_tail`
Return recent audit-log records as JSONL (oldest first), optionally filtered.
`lines` defaults to 50 and is clamped to `[1, 1000]` — it is the size of the
scanned window. Optional read-only triage filters narrow *within* that window
(widen `lines` to reach further back): `tool` (exact tool name, e.g.
`shell_exec`; empty = any), `tier` (`0`..`3`; `-1` = any), and `denied`
(`true`/`false`; unset = any). Returns the empty string if the audit file does
not exist, is empty, or nothing in the window matches. Read-only: opens a fresh
fd so the writer's append-only handle is untouched. Useful for an operator MCP
client triaging a session (only denied calls, only one tool) without shelling
into the host. Tier 0. (Chain *verification* stays off the tool surface — it is
the CLI `relay-shell --verify-audit`, an operator/forensic action; see
[ADR 0007](adr/0007-audit-hash-chain.md).)

Tests: `tests/test_audit_tail_tool.py`.

### `operation_confirm`
Second step of the **opt-in Tier-3 confirmation flow** (ADR 0009; off unless
`RELAY_SHELL_CONFIRM_TIER3=true`). Takes a single `token`. When the broker is
enabled, an irreversible (Tier 3) call does not run on first request — it
returns `[CONFIRM REQUIRED tier 3: … token="…" …]` and is audited with
`action=confirm_plan` (no side effect). Pass that token to `operation_confirm`
to arm it, then **re-issue the exact same call** to execute it (audited with
`action=confirm_execute`). Tokens are single-use, bound to the exact operation
(tool + every executor-visible byte), and expire after
`RELAY_SHELL_CONFIRM_TTL` seconds. The raw token is never written to the audit
log (only a short fingerprint). When the broker is disabled, this reports so
and changes nothing. Tier 0 (it arms ephemeral state and authorizes nothing on
its own; the retried call is re-classified and re-admitted from scratch).

Tests: `tests/test_broker.py`, `tests/test_tool_wrappers.py`.

## Resources

Resources are read-only context the client can list and pull on its own
initiative (the protocol-native counterpart to tools). Each read is
audited as tier 0 so the operator sees what context the model is pulling
in even though resource reads do not go through `Relay.run`.

| URI                                     | mime               | audit `tool`              | meaning                                                       |
|-----------------------------------------|--------------------|---------------------------|---------------------------------------------------------------|
| `relay-shell://inventory`               | `application/json` | `resource:inventory`      | Flat JSON list of every host in the merged inventory.         |
| `relay-shell://inventory/{host}`        | `application/json` | `resource:inventory_host` | One host's resolved spec (passthrough for unknown alias).     |
| `relay-shell://ssh-config`              | `application/json` | `resource:ssh-config`     | `{"path": "...", "aliases": [...]}` for the active ssh_config.|

The audit `tool` field is **stable per resource** (no user-controlled
data interpolated): for the templated read, the requested `host` lives
in the audit `args` dict so `redact_args` can scrub embedded secrets
(e.g. `user:password@...`) and the tool-name cardinality stays bounded
for downstream audit consumers.

A client that prefers resources to tools can list hosts the protocol-native
way without invoking `ssh_hosts`. The data shape matches the `ssh_hosts`
tool output so client code can share a renderer. Bodies are bounded by the
same `max_output` cap tools observe through `Relay.run`; an oversize
response is truncated with a `[TRUNCATED ...]` marker the same way tools
truncate.

The `ssh-config` resource lists every alias the active ssh_config file
declares, even if an entry in the inventory file overrides the same
alias's spec - the resource describes the file, not the merged map.

Tests: `tests/test_resources.py`.

## Prompts

A prompt is reusable, client-pullable guidance — the protocol-native home for
*detailed* "when to use which tool" instructions (the concise version is the
FastMCP `instructions` string handed to every client at initialize). One is
registered:

| name              | audit `tool`              | meaning                                                              |
|-------------------|---------------------------|----------------------------------------------------------------------|
| `operating_guide` | `prompt:operating_guide`  | How to choose and drive the tools: one-shot command vs persistent PTY session, the spawn+`session_*` workflow, fleet / file-transfer entry points, and the bounded, audited execution model with its error grammar. |

Like a resource read, a prompt fetch does **not** flow through `Relay.run`
(there is no work to admit, time out, or truncate) but **is** audited as tier 0
so the operator sees what context the model pulls in. The audit `tool` is the
**stable** `prompt:<name>` label; the body is hashed (never written) and
bounded by the same `max_output` cap tools and resources observe.
`prompts/list` returns metadata only and is not audited — the audit fires on
`prompts/get`. See [`adr/0008-operating-guidance-prompt.md`](adr/0008-operating-guidance-prompt.md).

Tests: `tests/test_prompts.py`.

## Syscall-notify audit events (ADR 0006)

When `RELAY_SHELL_SECCOMP_NOTIFY=true` and the host supports it (Linux /
`x86_64` / kernel ≥ 5.5 / `CAP_SYS_ADMIN`), a locally-spawned child — one-shot
(`shell_exec` / `shell_script` / `ssh_keyscan`) or a local PTY session
(`shell_spawn`, where the filter rides the session child for the session's
whole life and the cap applies per session) — is observed by a seccomp
user-notify supervisor that appends *additional* audit lines to the same
JSONL stream. These never replace the per-call tool record - they are a
distinct, narrower shape keyed on `tool`, so log shippers and the ADR 0007
hash chain handle them like any other line:

| audit `tool`              | fields beyond `ts`/`tool`/`tier`/`request_id`                          | meaning                                                                                                   |
|---------------------------|------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------|
| `syscall_notify`          | `pid`, `syscall`, `nr`, `syscall_args` (six raw scalar register values)| one observed-and-continued syscall in the child (`execve`, a privilege/namespace/mount change, a write-`open`, a privilege-relevant `prctl`). No user buffer is dereferenced. |
| `syscall_notify_overflow` | `pid`, `cap`                                                           | emitted once when the child crosses `RELAY_SHELL_SECCOMP_NOTIFY_CAP`; beyond it, emission stops but the child still runs to completion. |

Both are tier 0 (passive observations, not tool calls), and the channel
**never blocks** a syscall. Default off; when unsupported it cleanly no-ops
and `server_info.seccomp.supported` is `false` with a `reason`.

Tests: `tests/test_seccomp.py`.

## Interactive pattern

```text
id  = shell_spawn(command="/bin/bash")              -> "session sh-... started"
      session_send(id, "kubectl get pods", true)
out = session_recv(id, timeout=3)                    -> table
      session_send(id, "exit", true)
      session_kill(id)                                -> "killed and closed"
```

## Errors

Failures are bounded strings, never exceptions:

- `[DENIED tier N (NAME): reason]` - refused by policy.
- `[TIMEOUT after Ns]` - exceeded the (clamped) timeout.
- `[ERROR: ExcType: message]` - any other failure.
- `[TRUNCATED - N bytes total, M shown]` - output exceeded the budget.
