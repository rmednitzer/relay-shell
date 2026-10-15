# Tool reference

Every tool returns a single string and is audited. `timeout` and output are clamped to the
configured limits. Each tool's default tier is shown; the effective decision also depends on
`RELAY_SHELL_POLICY_MODE` and the deny/allow lists.

**Tier reference** (see [`adr/0003-tiered-authority.md`](adr/0003-tiered-authority.md)):

| Tier | Name          | Meaning                                       |
|------|---------------|-----------------------------------------------|
| 0    | `READ_ONLY`   | Observe only; no local or remote state change.|
| 1    | `REVERSIBLE`  | Low blast radius; trivially undone.           |
| 2    | `STATEFUL`    | Visible impact a user or dependent notices.   |
| 3    | `IRREVERSIBLE`| High blast; rollback expensive or impossible. |

Mode semantics: `open` (the default) permits all but still classifies, and the result of an
admitted Tier 2/3 call ends with a `[NOTICE ...]` line saying what is risky about it
([ADR 0013](adr/0013-open-by-default-with-unsafe-notices.md); `RELAY_SHELL_UNSAFE_NOTICES=false`
turns the lines off, the audit record never changes); `guarded` refuses Tier 2+ unless
`RELAY_SHELL_POLICY_ALLOW` matches; `readonly` permits only Tier 0.
`RELAY_SHELL_POLICY_DENY` is always enforced first.

`RELAY_SHELL_POLICY_DENY` and `RELAY_SHELL_POLICY_ALLOW` are Python `re.search` patterns,
unanchored, run over the probe `<tool> <policy text>` (the tool name, a space, then the
tool's policy text). A match anywhere in that text counts, so a pattern such as
`systemctl restart` also matches when those words sit inside another command, an argument or
a heredoc. An `ALLOW` match admits the whole call, whatever else it contains. The policy
text differs per tool and often carries lines after the command:

| Tool | Policy text (newline-joined unless noted) |
|------|------------------------------|
| `shell_exec` | command, stdin, `env_json` |
| `shell_script` / `shell_spawn` | script or command, `env_json` |
| `ssh_exec` / `ssh_spawn` | command, destination host, jump chain, then the canonical IP spellings of the host and hops when they differ |
| `ssh_fanout` | command, the host list, canonical IP spellings |
| `ssh_check` / `ssh_keyscan` | the host list, canonical IP spellings |
| `ssh_upload` / `ssh_download` | `upload <local> <host>:<remote>` / `download <host>:<remote> <local>`, jump chain, canonical IPs |
| `ssh_forward` | `forward <spec>`, jump chain, host, canonical IPs |
| `session_send` | the partial line already typed with the new input appended (concatenated, no newline between) |

Anchor the start only (`(?s)^shell_exec systemctl restart nginx\b`) and never end-anchor an
SSH or transfer pattern with `$`: the host, jump and IP lines follow the command, so the
pattern would never match. For the same reason a fully anchored `DENY` is easy to defeat
with appended text; prefer short substrings there. Neither pattern is a containment
boundary (`SECURITY.md`).

Conventions:

- `host` is an inventory / `ssh_config` alias or `user@host`. A host that is not an
  operator-written alias must be a plain token: letters, digits and `. _ - : % [ ]`, no
  whitespace, quotes or leading `-`; a user may use only letters, digits and `. _ -` (a
  per-call `user` and every `jump` hop are held to the same rules). Anything else is refused before any connection with
  `[ERROR: RelayError: invalid ssh host|user|jump ...]`, because asyncssh substitutes these
  values into the operator's `ProxyCommand` and the `known_hosts` file.
- `known_hosts` is `strict` | `accept-new` | `ignore` (default: the inventory entry's mode,
  else `RELAY_SHELL_SSH_KNOWN_HOSTS`; the audit records the effective mode). `accept-new` is trust-on-first-use: an unknown host is
  accepted and recorded, a host with an existing entry is verified and a changed key is
  refused. `ignore` never verifies. With `RELAY_SHELL_SSH_ALLOW_WEAKER_KNOWN_HOSTS=false` a
  mode weaker than the server default is refused
  (`[ERROR: RelayError: known_hosts=... would weaken ...]`).
- `jump` is an `ssh_config`-style `user@host[:port]` bastion (asyncssh
  `tunnel`); `ssh_config` `ProxyJump` is also honoured automatically. The jump host is
  dialled first, so it is part of the text `RELAY_SHELL_POLICY_DENY` matches against. Only
  `ssh_exec`, `ssh_spawn`, `ssh_upload`, `ssh_download` and `ssh_forward` take the per-call
  connection parameters (`user`, `port`, `key_path`, `known_hosts`, `jump`); `ssh_check`,
  `ssh_fanout` and `ssh_keyscan` use the inventory and server defaults.

Each tool entry below names the test files that exercise it (file names, not line numbers,
which drift). The tool-list contract is `tests/test_server.py`.

## Choosing a tool

The guidance the server hands the client at initialize (the `MCPServer` `instructions` string)
and in each tool's description:

- A command that **runs and exits on its own** → `shell_exec` (local) or
  `ssh_exec` (remote). **Several statements** or a non-bash interpreter →
  `shell_script`.
- **Interactive or long-lived** work that needs a real TTY (a REPL, a TUI, a
  pager, a password prompt, a job you watch) → `shell_spawn` (local) or
  `ssh_spawn` (remote), then drive the returned session id with the `session_*` tools.
  Spawning and the session tools are **one workflow**, not alternatives: the spawn creates
  the PTY; `session_send` / `session_recv` drive it; `session_resize` / `session_kill` /
  `session_list` manage it.
- **Across many hosts** → `ssh_fanout` (and `ssh_check` / `ssh_hosts` to
  discover and probe first).

## Local shell

### `shell_exec`
Run a command on the local host; returns `[exit N]` + combined output.

Tests: `tests/test_shell.py`, `tests/test_tool_wrappers.py`.

| param | type | default | notes |
|-------|------|---------|-------|
| `command` | str | - | the command |
| `timeout` | int | 0 | `0` = `RELAY_SHELL_DEFAULT_TIMEOUT` (60 s unless set); clamped to `[1, RELAY_SHELL_MAX_TIMEOUT]` |
| `max_output` | int | 65536 | clamped to `[1024, RELAY_SHELL_MAX_OUTPUT_HARD]` |
| `cwd` | str | "" | working directory |
| `stdin` | str | "" | written to the process stdin |
| `merge_stderr` | bool | true | fold stderr into stdout |
| `use_shell` | bool | true | false = exec argv (no shell) |
| `env_json` | str | "" | JSON object overlaid on the environment |

Tier: heuristic (Tier 0..3 from the command text). Example:
`shell_exec(command="df -h")`.

### `shell_script`
Run a multi-line script fed on stdin. Params: `script`, `interpreter="bash"` (`bash` | `sh` |
`python`), `strict=true`, `timeout=120`, `cwd`, `env_json`. With `strict` and a shell
interpreter, `set -euo pipefail` (`set -eu` for `sh`, whose dash implementation lacks
`pipefail`) is prepended. Tier: heuristic from the script text.

Tests: `tests/test_shell.py`, `tests/test_tool_wrappers.py`.

### `shell_spawn`
Start a persistent local PTY (default `/bin/bash`); returns a session id.
Params: `command`, `cols=120`, `rows=40`, `cwd`, `env_json`. Drive it with the `session_*`
tools. Tier: heuristic from the command (Tier 1 when nothing matches, as for the default shell).

Tests: `tests/test_sessions.py`, `tests/test_tool_wrappers.py`.

## SSH

### `ssh_exec`
Run a command on a remote host; returns `[exit N]` + combined output. Params:
`host`, `command`, `timeout=0` (`0` = `RELAY_SHELL_DEFAULT_TIMEOUT`), `user`, `port`,
`key_path`, `known_hosts`, `jump`. Tier: heuristic from the command.

Tests: `tests/test_ssh_integration.py`, `tests/test_tool_wrappers.py`.

### `ssh_spawn`
Open a persistent interactive remote PTY; returns a session id. Params:
`host`, `command` (empty = login shell), `cols=120`, `rows=40`, plus the standard connection
params. Tier: heuristic from the command (Tier 1 when nothing matches, as for a login shell).

Tests: `tests/test_ssh_integration.py`, `tests/test_tool_wrappers.py`.

### `ssh_upload` / `ssh_download`
SFTP transfer. `ssh_upload(host, local_path, remote_path, recursive=false,
timeout=0, ...)`; `ssh_download(host, remote_path, local_path,
recursive=false, timeout=0, ...)`. `timeout` caps the transfer in seconds
(clamped to the server max); `0` (default) means no per-call cap, leaving only
the connection keepalive. A transfer that exceeds the cap returns a
`[TIMEOUT after Ns] ...` string whose text says the outcome is unknown (see Errors).
Tier 2 (mutating).

Tests: `tests/test_ssh_integration.py`, `tests/test_sshpool_unit.py`,
`tests/test_tool_wrappers.py`.

### `ssh_forward`
Create a port forward. `spec`:

- `L:lport:dhost:dport` - local forward.
- `R:rport:dhost:dport` - remote forward.
- `D:lport` - dynamic SOCKS proxy.

`L:` and `D:` listen on the relay host's **loopback only** (`127.0.0.1`), never on every
interface, so a forward is not reachable from other hosts; `lport` may be `0` to pick a free
port (the response reports it). An `R:` forward listens on the remote side as that sshd allows
(`GatewayPorts`). At most `RELAY_SHELL_MAX_FORWARDS` (default 64) forwards are active at once.
Returns a forward id and the listening port. Tier 2.

Tests: `tests/test_ssh_integration.py`, `tests/test_tool_wrappers.py`.

### `ssh_forward_list` / `ssh_forward_close`
List active forwards (`ssh_forward_list`, Tier 0) / close one by id
(`ssh_forward_close`, Tier 1).

Tests: `tests/test_ssh_integration.py`, `tests/test_tool_wrappers.py`.

### `ssh_check`
Probe connectivity. `hosts` is a comma/space list, or empty for the whole
inventory. Returns `host: ok | UNREACHABLE` per host. `timeout` is the per-host connect-and-probe
bound (default 5 s); the host list is capped at 100 per call, at most 8 probes run at once, and
each probe's output is capped at 4 KiB (the probe only looks for `ok`). Tier 0 for the inventory
(an alias or the `hostname` of an entry); Tier 1 when any requested host is not in
the inventory, because that dials a caller-chosen address with the relay's keys, so
`readonly` mode refuses it (as it does `ssh_keyscan`).

Tests: `tests/test_ssh_integration.py`, `tests/test_tool_wrappers.py`.

### `ssh_fanout`

Run `command` in parallel across `hosts` (comma/space list, or empty for the whole
inventory). Returns one JSON object with per-host `exit_code` and (truncated) `output`.
`concurrency` bounds how many SSH connections run at once (clamped to `[1, 32]`, default 8);
`timeout` (default 30 s) bounds each host's command, and a host that times out reports the
same `outcome unknown` text as `ssh_exec`. The host list is capped at 100 per call to bound
the outbound burst. Tier classification reads `command` like a regular `ssh_exec`:
`ssh_fanout rm -rf /` is still Tier 3, `ssh_fanout systemctl restart nginx` is Tier 2, and
the deny list and `guarded`/`readonly` modes see the same probe text as a single-host call
would.

When the call is risky (Tier 2/3, or a target dialled with `known_hosts=ignore`) the notices
are in a `"notices"` array inside the JSON object, not in trailing `[NOTICE ...]` lines, so
`json.loads` keeps working ([ADR 0013](adr/0013-open-by-default-with-unsafe-notices.md)).

Tests: `tests/test_ssh_fanout_tool.py`.

### `ssh_keyscan`
Shell out to `ssh-keyscan` to fetch each host's public key in known_hosts line format.
`hosts` is a comma/space list (required; capped at 32 per call to bound the outbound TCP
burst); `port` defaults to 22; `key_types` is a comma list from `{rsa, ecdsa, ed25519, dsa}`
(default `rsa,ecdsa,ed25519`); `timeout` (default 10) is the per-host inner ssh-keyscan
timeout (clamped to `[1, 60]`). Hosts must match `[A-Za-z0-9._\-\[\]:]+` (rejecting shell
metacharacters at the boundary); every interpolated token is also `shlex.quote`d for defence
in depth, and a `--` separator precedes the host list so a leading-dash hostname cannot
become a getopt-style flag. Useful for pre-populating `~/.ssh/known_hosts` so a service
account can run `strict` without a manual `accept-new` seeding pass. **Tier 1**
(REVERSIBLE): it does not mutate the relay but it opens caller-chosen outbound TCP
connections, which puts it outside the "observation-only" contract of `readonly` mode.
Permitted in `open` and `guarded`; rejected in `readonly`.

Tests: `tests/test_ssh_keyscan_tool.py`.

### `ssh_hosts`
Resolved inventory (`ssh_config` + JSON inventory). Tier 0.

Tests: `tests/test_inventory.py`, `tests/test_tool_wrappers.py`.

## Sessions (local PTY and SSH PTY, unified)

A session id from `shell_spawn` or `ssh_spawn` works with all of these.

| tool | params | notes |
|------|--------|-------|
| `session_send` | `session_id`, `data`, `enter=true` | `enter` appends `\n`. The audit record omits `data` (keeping its length) when the session is at a secret prompt such as `sudo`'s; see `RELAY_SHELL_AUDIT_SESSION_INPUT` |
| `session_recv` | `session_id`, `timeout=2.0`, `max_bytes=65536` | returns buffered/new output; waits up to `timeout` (clamped to `[0, 60]` s); `max_bytes` is clamped to `[256, RELAY_SHELL_MAX_OUTPUT_HARD]`; returns `""` if nothing yet; reports `[session ... ended, exit=N]` when closed |
| `session_resize` | `session_id`, `cols`, `rows` | resize the PTY |
| `session_kill` | `session_id`, `signal_name="TERM"`, `close=true` | signal and (default) reap; closing a local PTY escalates SIGTERM, SIGHUP after 0.5 s, SIGKILL at 5 s (including whatever is left of its process group; ADR 0012); `signal_name` is a real signal name with or without the `SIG` prefix (`TERM`, `SIGKILL`, `usr1`); anything else returns `[ERROR: RelayError: unknown signal ...]` and touches nothing |
| `session_list` | - | active sessions with size/age/idle/byte counters |

`session_recv` and `session_list` are Tier 0; `session_resize` and `session_kill` are Tier 1;
`session_send` is classified from its policy text (Tier 1 when nothing matches), so typing
`rm -rf /` into a session is Tier 3.

Sessions are not owned by the client that opened them: under multi-client OAuth every
approved client sees every session in `session_list` and can drive or close it by id. All
approved clients are one trust domain (`SECURITY.md`, "Residual risk"); isolate clients by
running separate instances.

Tests: `tests/test_sessions.py`, `tests/test_tool_wrappers.py`.

## Diagnostics

### `server_info`
Version, transport, policy mode, `warnings` (the permissive settings in effect, ADR 0013),
`runtime` (`uid`, `euid`, `user`, `is_root`, `sudo_binary`), effective `limits` (including
`max_conns` and `max_input`), audit path / `session_input` mode / degraded flag / format /
chain (the tamper-evident hash chain state, ADR 0007) / `intent` (write-ahead records),
seccomp-notify state (`notify` enabled, `supported` + `reason`, the per-call
`cap`, the `filter_version`; ADR 0006), the Tier-3 confirmation-broker state
(`confirm.tier3` enabled, `confirm.ttl`, live `confirm.pending` token count;
ADR 0009), SSH defaults (known-hosts mode and whether a weaker per-call mode is allowed, the
active `ssh_config` path, connect/keepalive/idle timeouts), inventory size. Tier 0.

Tests: `tests/test_tool_wrappers.py`, `tests/test_stdio_e2e.py`.

### `audit_tail`
Return recent audit-log records as JSONL (oldest first), optionally filtered.
`lines` defaults to 50 and is clamped to `[1, 1000]`; it is the size of the scanned window.
Optional read-only triage filters narrow *within* that window (widen `lines` to reach further
back): `tool` (exact tool name, e.g. `shell_exec`; empty = any), `tier` (`0`..`3`; `-1` =
any), and `denied` (`true`/`false`; unset = any). Returns the empty string if the audit file
does not exist, is empty, or nothing in the window matches. It opens a fresh fd, so the
writer's append-only handle is untouched. Tier 0. Chain *verification* stays off the tool
surface: it is the CLI `relay-shell --verify-audit`, an operator/forensic action (see
[ADR 0007](adr/0007-audit-hash-chain.md)).

Tests: `tests/test_audit_tail_tool.py`.

### `operation_confirm`
Second step of the **opt-in Tier-3 confirmation flow** (ADR 0009; off unless
`RELAY_SHELL_CONFIRM_TIER3=true`). Takes a single `token`. When the broker is
enabled, an irreversible (Tier 3) call does not run on first request; it
returns `[CONFIRM REQUIRED tier 3 (IRREVERSIBLE): … token="…" …]` and is audited with
`action=confirm_plan` (no side effect). Pass that token to `operation_confirm`
to arm it, then **re-issue the exact same call** to execute it (audited with
`action=confirm_execute`). Tokens are single-use, bound to the exact operation
(tool + every executor-visible byte) and to the authenticated client that received
them (another OAuth client can neither arm nor consume the token), and expire after
`RELAY_SHELL_CONFIRM_TTL` seconds. The raw token is never written to the audit
log (only a short fingerprint). When the broker is disabled, this reports so
and changes nothing. Tier 0 (it arms ephemeral state and authorizes nothing on
its own; the retried call is re-classified and re-admitted from scratch).

Tests: `tests/test_broker.py`, `tests/test_tool_wrappers.py`.

## Resources

Resources are read-only context the client can list and pull on its own initiative (the
protocol-native counterpart to tools). Each read is audited as tier 0, although resource reads
do not go through `Relay.run`, so the operator sees what context the model pulls in.

| URI                                     | mime               | audit `tool`              | meaning                                                       |
|-----------------------------------------|--------------------|---------------------------|---------------------------------------------------------------|
| `relay-shell://inventory`               | `application/json` | `resource:inventory`      | Flat JSON list of every host in the merged inventory.         |
| `relay-shell://inventory/{host}`        | `application/json` | `resource:inventory_host` | One host's resolved spec (passthrough for unknown alias).     |
| `relay-shell://ssh-config`              | `application/json` | `resource:ssh-config`     | `{"path": "...", "aliases": [...]}` for the active ssh_config.|

The audit `tool` field is **stable per resource** (no user-controlled data interpolated): for
the templated read, the requested `host` lives in the audit `args` dict so `redact_args` can
scrub embedded secrets (e.g. `user:password@...`) and the tool-name cardinality stays bounded
for downstream audit consumers.

The data shape matches the `ssh_hosts` tool output, so client code can share a renderer.
Bodies are bounded by the same `max_output` cap tools observe through `Relay.run`; an oversize
response is truncated with a `[TRUNCATED ...]` marker the same way tools truncate.

The `ssh-config` resource lists every alias the active ssh_config file declares, even if an
entry in the inventory file overrides the same alias's spec: it describes the file, not the
merged map.

Tests: `tests/test_resources.py`.

## Prompts

A prompt is reusable, client-pullable guidance: the protocol-native home for *detailed* "when
to use which tool" instructions (the concise version is the `MCPServer` `instructions` string
handed to every client at initialize). One is registered:

| name              | audit `tool`              | meaning                                                              |
|-------------------|---------------------------|----------------------------------------------------------------------|
| `operating_guide` | `prompt:operating_guide`  | How to choose and drive the tools: one-shot command vs persistent PTY session, the spawn+`session_*` workflow, fleet / file-transfer entry points, and the bounded, audited execution model with its error grammar. |

Like a resource read, a prompt fetch does **not** flow through `Relay.run` (there is no work
to admit, time out, or truncate) but **is** audited as tier 0. The audit `tool` is the
**stable** `prompt:<name>` label; the body is hashed (never written) and bounded by the same
`max_output` cap tools and resources observe. `prompts/list` returns metadata only and is not
audited; the audit fires on `prompts/get`. See [`adr/0008-operating-guidance-prompt.md`](adr/0008-operating-guidance-prompt.md).

Tests: `tests/test_prompts.py`.

## Syscall-notify audit events (ADR 0006)

When `RELAY_SHELL_SECCOMP_NOTIFY=true` and the host supports it (Linux /
`x86_64` / kernel ≥ 5.5 / `CAP_SYS_ADMIN`), a locally-spawned child is observed by a seccomp
user-notify supervisor that appends *additional* audit lines to the same
JSONL stream. The child is a one-shot (`shell_exec` / `shell_script` / `ssh_keyscan`) or a
local PTY session (`shell_spawn`, where the filter rides the session child for the session's
whole life and the cap applies per session). These never replace the per-call tool record - they are a
distinct, narrower shape keyed on `tool`, so log shippers and the ADR 0007
hash chain handle them like any other line:

| audit `tool`              | fields beyond `ts`/`tool`/`tier`/`request_id`                          | meaning                                                                                                   |
|---------------------------|------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------|
| `syscall_notify`          | `pid`, `syscall`, `nr`, `syscall_args` (six register values as signed int64), `syscall_args_hex` (the same six as exact unsigned hex)| one observed-and-continued syscall in the child (`execve`, a privilege/namespace/mount change, a write-`open`, a privilege-relevant `prctl`). No user buffer is dereferenced. |
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

- `[DENIED tier N (NAME): reason]` - refused by policy; `[DENIED tier N (NAME): input is X
  characters, over RELAY_SHELL_MAX_INPUT (Y)]` - the policy text exceeds the input cap and was
  refused before classification.
- `[CONFIRM REQUIRED tier 3 (IRREVERSIBLE): ...]` - only with `RELAY_SHELL_CONFIRM_TIER3=true`;
  see `operation_confirm`.
- `[TIMEOUT after Ns]` - exceeded the (clamped) timeout. For SSH commands and SFTP
  transfers the string continues `outcome unknown: ...`: the client gave up, but the remote
  side may still be running, may have completed, or may have applied part of the change.
  Verify the remote state before retrying a mutation. A local `shell_exec` timeout kills the
  command's process group instead, so its outcome is the partial effects of a killed command.
- `[ERROR: ExcType: message]` - any other failure.
- `[TRUNCATED - N bytes total, M shown]` - output exceeded the budget.
