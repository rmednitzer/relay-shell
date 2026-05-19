# Architecture

`relay-shell` is a single Python process exposing shell and SSH operations as MCP
tools. It is intentionally thin: the MCP SDK (FastMCP) owns the protocol and
(optional) OAuth edge; `asyncssh` owns SSH; the operating system owns
execution. `relay-shell` owns the parts that make that combination *safe to operate*:
classification, bounding, auditing, and session lifecycle.

```
MCP client (Claude / Inspector / SDK)
        |
        |  stdio  |  streamable-HTTP (+ optional OAuth 2.1, behind a TLS/CIDR proxy)
        v
   FastMCP (mcp==1.26.0)
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
   code, request and client id. The output body is never written.

This is the same discipline a production gateway uses: a tool may fail, time
out, or be denied, but it always returns a single bounded, audited string.

## Modules

| Module | Responsibility |
|--------|----------------|
| `config` | Typed `RELAY_SHELL_*` settings; invalid values fail fast at startup. |
| `util` | Time, hashing, byte-safe truncation, id generation. |
| `redaction` | Scrub secrets from audited arguments. |
| `audit` | Rotation-safe append-only JSONL; hash, never body. |
| `policy` | Tier 0..3 classification; `open`/`guarded`/`readonly` admission. |
| `errors` | Error types and the uniform `[ERROR: ...]` formatter. |
| `sessions` | Local PTY transport + transport-agnostic session registry. |
| `shelltools` | One-shot command/script execution (no PTY). |
| `inventory` | `~/.ssh/config` + JSON inventory parsing and resolution. |
| `sshpool` | asyncssh connection cache, exec, SFTP, forwarding, PTY adapter. |
| `auth/oauth` | Optional file-backed OAuth 2.1 provider (HTTP only). |
| `server` | FastMCP assembly, the audited runner, all tool definitions. |
| `__main__` | Entrypoint; stderr-only logging; transport selection. |

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
  constructed for this transport.

## Security model

See `SECURITY.md` and the ADRs. In short: the executor is deliberately
unsandboxed (that is the capability); safety is compensating controls plus
deployment discipline.
