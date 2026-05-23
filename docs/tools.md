# Tool reference

Every tool returns a single string and is audited. `timeout` and output are
clamped to the configured limits. Each tool's default tier is shown; the
effective decision also depends on `RELAY_SHELL_POLICY_MODE` and the deny/allow lists.

Conventions:

- `host` is an inventory / `ssh_config` alias or `user@host`.
- `known_hosts` is `strict` | `accept-new` | `ignore` (default from
  `RELAY_SHELL_SSH_KNOWN_HOSTS`).
- `jump` is an `ssh_config`-style `user@host[:port]` bastion (asyncssh
  `tunnel`); `ssh_config` `ProxyJump` is also honoured automatically.

## Local shell

### `shell_exec`
Run a command on the local host; returns `[exit N]` + combined output.

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

### `shell_spawn`
Start a persistent local PTY (default `/bin/bash`); returns a session id.
Params: `command`, `cols=120`, `rows=40`, `cwd`, `env_json`. Drive it with
the `session_*` tools. Tier 1.

## SSH

### `ssh_exec`
Run a command on a remote host; returns `[exit N]` + combined output. Params:
`host`, `command`, `timeout=60`, `user`, `port`, `key_path`, `known_hosts`,
`jump`. Tier: heuristic from the command.

### `ssh_spawn`
Open a persistent interactive remote PTY; returns a session id. Params:
`host`, `command` (empty = login shell), `cols`, `rows`, plus the standard
connection params. Tier 1.

### `ssh_upload` / `ssh_download`
SFTP transfer. `ssh_upload(host, local_path, remote_path, recursive=false,
...)`; `ssh_download(host, remote_path, local_path, recursive=false, ...)`.
Tier 2 (mutating).

### `ssh_forward`
Create a port forward. `spec`:

- `L:lport:dhost:dport` - local forward.
- `R:rport:dhost:dport` - remote forward.
- `D:lport` - dynamic SOCKS proxy.

Returns a forward id and the listening port. Tier 2.

### `ssh_forward_list` / `ssh_forward_close`
List active forwards / close one by id. Tier 1.

### `ssh_check`
Probe connectivity. `hosts` is a comma/space list, or empty for the whole
inventory. Returns `host: ok | UNREACHABLE` per host. Tier 0.

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

### `ssh_hosts`
Resolved inventory (`ssh_config` + JSON inventory). Tier 0.

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

## Diagnostics

### `server_info`
Version, transport, policy mode, effective limits, audit path and degraded
flag, SSH defaults, inventory size. Tier 0.

### `audit_tail`
Return the last `lines` records from the audit log as JSONL (oldest first).
`lines` defaults to 50 and is clamped to `[1, 1000]`. Returns the empty
string if the audit file does not exist or is empty. Read-only: opens a
fresh fd so the writer's append-only handle is untouched. Useful for an
operator MCP client debugging a session without shelling into the host.
Tier 0.

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
