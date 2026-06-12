# ADR 0001: Runtime, SDK, and SSH library

- Status: Accepted
- Date: 2026-05-19

## Context

`relay-shell` must speak the Model Context Protocol reliably, run arbitrary local
commands and interactive PTYs, and perform full SSH operations (exec, PTY,
SFTP, port forwarding, jump hosts). The choice affects protocol correctness,
type safety, and how much transport/auth code we own versus delegate.

## Decision

- **Python 3.12+** and the **official `mcp` SDK (FastMCP)**, initially pinned
  to `mcp==1.27.1` (a tracked version validated by the test suite), with the
  surrounding stack pinned in `requirements.txt`. FastMCP provides the
  protocol, stdio and streamable-HTTP transports, and an OAuth 2.1 hook. The
  pin moves on a deliberate, tested bump; the *current* validated pin is the
  one recorded in the latest [ADR 0005](0005-codebase-validation.md) outcome
  paragraph, not this line (see Consequences).
- **`asyncssh`** for all SSH. It is pure-Python, asyncio-native, and covers
  the entire required surface (exec, interactive PTY, SFTP, local/remote/
  dynamic forwarding, agent, `ProxyJump`/tunnels, `known_hosts`, keepalive)
  with one dependency and no system `ssh` shelling.
- **Local execution** uses `asyncio` subprocesses and a non-blocking PTY
  master driven by the event loop (executor fallback) - stdlib only.

## Consequences

- One protocol dependency, one SSH dependency; both typed. `ssh_config`
  semantics (including `ProxyJump`) come free via asyncssh's config support.
- Pinning a known-good SDK version trades newest features for reliability;
  upgrades are a deliberate, tested change, not implicit.
- No reliance on a system `ssh` binary or its version quirks; behaviour is
  reproducible across hosts.
- Pin movement (one line per validated bump; the runbook §8.9 trigger):
  - `mcp` 1.27.1 → 1.27.2 (PR #66, 2026-06-04). Validated by the full test
    suite plus the ADR 0005 step-3 upstream-symbol check (FastMCP/`Context`
    kwargs and the nine OAuth provider methods resolve unchanged); recorded
    in the [ADR 0005](0005-codebase-validation.md) 2026-06-12 outcome.

## Rejected

- TypeScript MCP SDK: diverges from the Python execution/SSH ecosystem here.
- Shelling out to system `ssh`/`scp`: brittle parsing, version-dependent
  behaviour, weaker error semantics than `asyncssh`.
- `paramiko`: synchronous core; bridging to async for PTY/forwarding is more
  code and more failure modes than `asyncssh`.
