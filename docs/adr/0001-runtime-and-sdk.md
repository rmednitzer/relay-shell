# ADR 0001: Runtime, SDK, and SSH library

- Status: Accepted
- Date: 2026-05-19

## Context

`mcpx` must speak the Model Context Protocol reliably, run arbitrary local
commands and interactive PTYs, and perform full SSH operations (exec, PTY,
SFTP, port forwarding, jump hosts). The choice affects protocol correctness,
type safety, and how much transport/auth code we own versus delegate.

## Decision

- **Python 3.12** and the **official `mcp` SDK (FastMCP)**, pinned to
  `mcp==1.26.0` (a version proven in production gateways), with the
  surrounding stack pinned in `requirements.txt`. FastMCP provides the
  protocol, stdio and streamable-HTTP transports, and an OAuth 2.1 hook.
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

## Rejected

- TypeScript MCP SDK: diverges from the Python execution/SSH ecosystem here.
- Shelling out to system `ssh`/`scp`: brittle parsing, version-dependent
  behaviour, weaker error semantics than `asyncssh`.
- `paramiko`: synchronous core; bridging to async for PTY/forwarding is more
  code and more failure modes than `asyncssh`.
