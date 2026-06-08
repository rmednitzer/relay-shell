# Architecture

`relay-shell` is a single Python 3.12+ process exposing shell and SSH
operations as MCP tools. It is intentionally thin: the MCP SDK (FastMCP)
owns the protocol and (optional) OAuth edge; `asyncssh` owns SSH; the
operating system owns execution. `relay-shell` owns the parts that make
that combination *safe to operate*: classification, bounding, auditing,
and session lifecycle.

```
MCP client (Claude / Inspector / SDK)
        |
        |  stdio  |  streamable-HTTP (+ optional OAuth 2.1, behind a TLS/CIDR proxy)
        v
   FastMCP (mcp==1.27.1)
        v
   Relay.run()  ── policy.check ──> tier + admit/deny      (deny list first, always)
        |        ── redaction ───> audit args
        |        ── work() ──────> the actual operation
        |        ── truncate ────> output budget
        v        ── audit.record > one JSONL line (hash of output, never body)
   +-----------------------------+-----------------------------+
   | shelltools                  | sshpool (asyncssh)          |
   |  run_command / run_script   |  run / open_process / sftp  |
   | sessions.LocalPtyTransport  |  forwarding / connect cache |
   +-----------------------------+-----------------------------+
                 \                              /
                  \---- SessionRegistry -------/   (unified local + SSH PTYs)
```

## Request lifecycle

Every tool body is identical in shape (`Relay.run`):

1. **Identify** - best-effort `request_id` / `client_id` from the MCP context.
2. **Classify + admit** - `policy.check(tool, text)`. The deny list is applied
   first in every mode. `readonly` permits only Tier 0; `guarded` refuses
   Tier 2+ unless an allow pattern matches; `open` permits all but still
   classifies. A refusal is audited and returned as a `[DENIED ...]` string.
3. **Execute** - the work coroutine runs. `RelayError` and any other exception
   are converted to a bounded `[ERROR: ...]` string; nothing propagates into
   the transport.
4. **Bound** - the body is truncated to the effective output budget (byte
   safe). An `[exit N]` prefix is added when an exit code is meaningful.
5. **Audit** - one JSON line: timestamp, tool, tier, denied flag, redacted and
   length-bounded args, SHA-256 of the final output, output byte length, exit
   code, request and client id. The output body is never written. With
   `RELAY_SHELL_AUDIT_CHAIN=true` the line additionally carries `seq`/`prev`/`chain`
   for tamper-evidence ([ADR 0007](adr/0007-audit-hash-chain.md)); default off
   keeps the record byte-identical.

This is the same discipline a production gateway uses: a tool may fail, time
out, or be denied, but it always returns a single bounded, audited string.

When `RELAY_SHELL_SECCOMP_NOTIFY=true` (and the host supports it),
`Relay.run` also activates a per-call seccomp-notify monitor for the duration
of step 3: a spawned local child's forensically-interesting syscalls are
appended as *additional* `syscall_notify` lines (tier 0) tied to the same
`request_id`, never replacing the per-call record
([ADR 0006](adr/0006-seccomp-notify-audit-channel.md)). It never blocks a
syscall and is default off, so the lifecycle above is otherwise unchanged.

## Modules

| Module | Responsibility |
|--------|----------------|
| `config` | Typed `RELAY_SHELL_*` settings; invalid values fail fast at startup. |
| `util` | Time, hashing, byte-safe truncation, id generation. |
| `patterns` | Version-pinned compiled regex tables for redaction and tier classification. |
| `redaction` | Scrub secrets from audited arguments (consumes `patterns`). |
| `audit` | Rotation-safe append-only JSONL; hash, never body. Optional tamper-evident per-record hash chain + `verify_chain` (ADR 0007). |
| `policy` | Tier 0..3 classification (consumes `patterns`); `open`/`guarded`/`readonly` admission. |
| `metrics` | In-memory Prometheus counter + gauge registry rendered at `GET /metrics` (HTTP only). |
| `seccomp` | Opt-in, audit-only seccomp-notify channel: a version-pinned BPF filter + per-call supervisor that appends `syscall_notify` lines for a spawned child's syscalls, never blocking. `CAP_SYS_ADMIN`-gated, Linux/`x86_64` ([ADR 0006](adr/0006-seccomp-notify-audit-channel.md)). |
| `errors` | Error types and the uniform `[ERROR: ...]` formatter. |
| `sessions` | Local PTY transport + transport-agnostic session registry. |
| `shelltools` | One-shot command/script execution (no PTY). |
| `inventory` | `~/.ssh/config` + JSON inventory parsing and resolution. |
| `sshpool` | asyncssh connection cache, exec, SFTP, forwarding, PTY adapter. |
| `auth/oauth` | Optional file-backed OAuth 2.1 provider (HTTP only). |
| `verifier` | Drift-detection comparator powering `relay-shell --verify-deploy`. |
| `server` | FastMCP assembly, the audited runner, all tool, resource + prompt definitions. |
| `__main__` | Entrypoint; stderr-only logging; transport selection; `--check-config` / `--verify-deploy` CLI flags. |

The canonical list of registered tools lives in
`tests/test_server.py::_EXPECTED`; the MCP resources are registered in
`server.py` under `@mcp.resource("relay-shell://...")`. See
[`docs/tools.md`](tools.md) for the per-tool reference and the resources
section.

### Where the lifecycle maps in code

The five `Relay.run` steps above correspond to specific call sites in
`src/relay_shell/server.py`:

| Step | Where |
|------|-------|
| 1 Identify | `_ctx_ids(ctx)` (best-effort `request_id` / `client_id` from `Context`). |
| 2 Classify + admit | `self.policy.check(tool, policy_text)` from `policy.Policy.check`. |
| 3 Execute | `await work()` - the per-tool coroutine captured by the wrapper. |
| 4 Bound | `truncate(body, self.clamp_output(max_output))` from `util.truncate`. |
| 5 Audit | `self.audit.record(...)` from `audit.AuditLogger.record`. |

Resource reads (`relay-shell://...`) and prompt fetches (`prompts/get`)
do not flow through `Relay.run` - there is no work to admit, time out,
or truncate. They are still audited with `tool="resource:<name>"` /
`tool="prompt:<name>"` and `tier=0` so the operator sees what context
the model is pulling in ([ADR 0008](adr/0008-operating-guidance-prompt.md)
covers the prompt surface). The `Relay.run` body, the resource handlers,
the prompt handlers, and (when `RELAY_SHELL_SECCOMP_NOTIFY` is enabled)
the seccomp-notify supervisor are the only places where audit records are
produced.

## Concurrency and resource model

- Async throughout; SSH is natively async (`asyncssh`), local one-shot
  execution uses `asyncio` subprocesses, local PTYs use a non-blocking master
  fd driven by the event loop (with an executor fallback).
- The session registry bounds the number of sessions, the per-session ring
  buffer, and idle/lifetime, and sweeps opportunistically on create/list so
  there is no fragile always-on reaper task.
- Every tool clamps its own timeout and output to the configured limits;
  background/blocking filesystem work is offloaded with `asyncio.to_thread`.

## Transports

- **stdio** (default): for local agents and desktop clients. Logging goes to
  stderr so stdout stays a clean JSON-RPC channel.
- **streamable-HTTP**: binds loopback by design; terminate TLS and restrict by
  IP at a reverse proxy (see `deployment.md`). OAuth 2.1 is optional and only
  constructed for this transport. The HTTP transport also mounts a
  `GET /metrics` route (Prometheus text exposition); the route bypasses
  OAuth by design and is firewalled by the edge CIDR allowlist.

## Security model

See `SECURITY.md` and the ADRs ([index](adr/README.md)). In short: the
executor is deliberately unsandboxed (that is the capability); safety is
compensating controls plus deployment discipline.

For the operator-facing audit of the guarantees described above (deny
list precedence, audit-record shape, hash-not-body invariant, output
bounds), see [`runbook.md`](runbook.md) §2. The reproducible validation
pass against the upstream `mcp` / `asyncssh` / OAuth surfaces lives in
[ADR 0005](adr/0005-codebase-validation.md), which records the
methodology and the most recent pass outcome.
