# ADR 0012: Cancel-safe session teardown

- Status: Accepted
- Date: 2026-10-14

## Context

A session (`shell_spawn`, `ssh_spawn`) owns a child process or remote channel, a PTY
file descriptor, a reader task and, with the seccomp channel on, a supervisor thread. The
registry removes a session from `_sessions` and then tears it down. Until 2026-10-14 the
removal and the teardown were separate steps in the caller's task, so cancelling the caller
(client disconnect, MCP cancellation, shutdown) between them left a session that no
registry entry points to but whose child, fds and thread were still live. A cancel during
the SIGTERM grace wait also skipped SIGKILL, so a child that ignores SIGTERM outlived its
session (BACKLOG A14-R10).

This ADR records the decision and the STPA trace required by `AGENTS.md` for a change to a
recovery and process-termination control action. It is an analysis of this control loop,
not a certification, and does not replace the threat model in `SECURITY.md`.

## Decision

1. Teardown of sessions already removed from the registry (`close`, the idle sweep,
   `shutdown`) runs as its own task, awaited through `asyncio.shield`, concurrently across
   the sessions, with a strong reference held until it finishes. A cancelled caller stops
   waiting; the teardown continues.
2. `LocalPtyTransport.aclose` sends SIGKILL to the process group if it is cancelled while
   waiting for SIGTERM to take effect, then propagates the cancellation.

Rejected alternatives: **no change** (leaves the leak); **catch the cancel and tear the
rest down inline** (a second cancel can interrupt that too, and `suppress(CancelledError)`
would swallow a real cancellation); **register-then-pop under one lock** (the registry
lock is not held across the awaited teardown, by design, so a slow child does not block
`add`/`list`); **synchronous best-effort kill** (cannot close the PTY fd or join the
supervisor thread).

## STPA analysis

### Purpose, boundary, stakeholders

Purpose: when a session ends by any route, its child, descriptors and monitor thread end
with it, and the registry never claims a session it no longer owns. Boundary: the relay
process (`SessionRegistry`, the transports, the seccomp monitor) and the OS processes it
spawned; the remote host's process after an SSH channel closes is outside it. Stakeholders:
the operator (host stays usable, audit complete), MCP clients, and whoever owns the host
whose capacity the leaked processes consume.

### Losses and hazards

- L-1 Unaccounted code keeps running under the service account after its session was
  closed or abandoned (an unobserved, unaudited process).
- L-2 The relay exhausts a resource (processes, fds, threads, `max_sessions` accounting) and
  stops serving.
- L-3 A session the operator believes closed is still driving an interactive shell.
- H-1 A session is absent from the registry while its child is alive.
- H-2 A session is in the registry while its transport is closed or dead (accounting
  drifts).
- H-3 A termination request is acknowledged to the caller before the child is gone.

### Safety constraints

- SC-1 (H-1) Once a session leaves the registry, its teardown runs to completion
  independent of the caller's lifetime.
- SC-2 (H-1, H-3) A cancelled teardown still terminates the child, with SIGKILL if SIGTERM
  was not enough.
- SC-3 (H-2) A failing teardown step never prevents the remaining steps or the remaining
  sessions.
- SC-4 (L-2) Teardown work is bounded in time (5 s SIGTERM grace, 2 s after SIGKILL) and
  runs concurrently, so one stuck child cannot delay the rest.

### Control structure

Controllers: the MCP client (requests close or disconnects), the tool wrapper (`session_kill`,
`ssh_spawn`, `shell_spawn`), the idle sweep and `shutdown` (automatic). Controlled
processes: the child process and its PTY or SSH channel. Control actions: SIGTERM, SIGKILL,
close PTY, cancel reader, stop monitor, unpin SSH connection. Feedback: `proc.wait()` result
and `returncode`, reader EOF, and `exit_code` in `session_list`. Process model: the
registry's `_sessions` map and `Session.closed`.

### Unsafe control actions

| ID | Type | Unsafe control action | Constraint |
|----|------|----------------------|------------|
| UCA-1 | Not provided | The teardown of a removed session is never run because the caller was cancelled | SC-1 |
| UCA-2 | Not provided | SIGKILL is not sent after a cancel during the SIGTERM wait | SC-2 |
| UCA-3 | Too early | The session is removed (and `max_sessions` slot freed) before the child is gone | SC-1, SC-4 (accepted: the slot frees at removal; the shielded teardown follows immediately) |
| UCA-4 | Too late / too long | One session's 5 s grace delays the teardown of the others | SC-4 |
| UCA-5 | Wrong order | The PTY fd is closed before the reader task is cancelled | SC-3 (reader is cancelled and awaited first; fd closes in `aclose`'s `finally`) |
| UCA-6 | Provided unsafely | A close signals a process group that is no longer the session's | Accepted, see CS-5 |

### Causal scenarios

- CS-1 (UCA-1) The idle sweep pops N sessions, the client disconnects during the first
  teardown, the cancel unwinds the loop and N-1 sessions are never touched. Addressed by
  the shielded task. Test: `test_cancelled_sweep_still_tears_down_every_doomed_session`.
- CS-2 (UCA-1) `close()` is cancelled while `transport.aclose()` awaits. Test:
  `test_cancelled_close_still_finishes_teardown`.
- CS-3 (UCA-1) The server stops while a request is mid-teardown. Test:
  `test_cancelled_shutdown_still_tears_down_every_session`.
- CS-4 (UCA-2) A child traps SIGTERM; the close is cancelled during the 5 s wait. Test:
  `test_cancelled_aclose_kills_a_term_ignoring_child` (a real child).
- CS-5 (UCA-6) A child calls `setsid` or double-forks out of the PTY child's process group,
  so `killpg` does not reach it. Not addressed: the analysis assumes the session child and
  its descendants share the process group (`start_new_session=True`). Escapees survive a
  close exactly as they do without this change.
- CS-6 (UCA-1) The event loop is torn down mid-teardown. The shielded task dies with the
  loop; fds are released by process exit. Residual, not addressed.
- CS-7 (UCA-4) A second cancel interrupts the grace wait. The SIGKILL path in `aclose`
  covers the local PTY; `SshProcessTransport.aclose` relies on `terminate()` and the channel
  close, with no SIGKILL equivalent (the remote process is outside the boundary).

### Assumptions and limits

The shielded task assumes the loop keeps running until the teardown ends; `asyncio.shield`
protects against caller cancellation, not against loop shutdown. SIGKILL is best-effort
(`ProcessLookupError` and `PermissionError` are ignored). Remote processes after an SSH
channel closes are the remote host's concern. A leaked process in a different process group
is not detected. Human intervention: `session_list` shows leftover registry entries;
`ps` on the host shows leftovers outside it.

## Threat analysis

Trust boundary: the MCP transport. A client that opens many sessions and disconnects
repeatedly attacks availability (STRIDE: denial of service, resource exhaustion). The
shielded teardown bounds the cost per session (SC-4) and keeps accounting honest; the
`max_sessions` cap and the idle reaper are the other bounds. No new input, privilege or
information path is added. Plausible path versus observed: the leak was reproduced in
tests with cancellation; no exploitation observed.

## Consequences

- A cancelled `session_kill`/`close` may return before the child is gone; the audit record
  already says `cancelled`, and the teardown finishes in the background.
- Tests for each scenario above live in `tests/test_sessions_cancel.py`.
- Rollback: revert the commit; behaviour returns to the previous leak-prone sequence.
