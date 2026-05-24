# ADR 0006: Syscall-level audit channel via seccomp-bpf notification mode

- Status: Proposed
- Date: 2026-05-24

## Context

ADR 0002 establishes the **service account** — not an in-process sandbox —
as the trust boundary, and ADR 0003 adds a tier classifier that records
the *intended* blast radius of each tool call. Together they cover the
MCP-side of the request: what the model asked for, how the runner
classified it, what bytes flowed back, and the SHA-256 of the output.

What they do *not* cover is anything the spawned process does after
`asyncio.create_subprocess_*` returns. Once a child is running (a one-shot
`shell.run`, a script body, a PTY session, or an SSH session's local
half), the kernel sees every syscall but `relay-shell` sees only the
combined stdout/stderr and the exit code. Two failure modes follow:

1. **Audit gap on the child side of the boundary.** A long-running script
   may open files, exec further processes, mount/unmount, set/clear
   capabilities, or call `prctl(PR_SET_DUMPABLE, 0)` — none of which
   appear in the audit trail. The hash-of-output invariant from ADR 0002
   is preserved, but a forensic question of the form "did the child
   shell out to `nc` after the first stdout line?" cannot be answered
   from `audit.jsonl` alone.
2. **No structured channel for the host's own monitoring.** Operators
   shipping `audit.jsonl` to a SIEM (see `docs/audit-shipper.md`) have
   no way to correlate syscall-level activity with the tool call that
   spawned it. Linux `auditd` runs at the host level and produces
   syscall events for every process on the box; matching those to a
   `relay-shell` `request_id` requires PID-tree walking, which is racy
   under fast-exiting children.

B-021 in `docs/runbook.md` §7.5 flagged seccomp-bpf notification mode as
a way to close the first gap without re-introducing a sandbox. This ADR
records the design constraints **before** any code lands, per the ADR
README criteria ("A change to the audit-record shape... needs an ADR").

## Decision (Proposed)

Add an **audit-only** seccomp-bpf channel using user-notify mode
(`SECCOMP_RET_USER_NOTIF`, Linux >= 5.0). The channel is:

- **Notify-only, never block.** Every notified syscall is allowed to
  continue via `SECCOMP_USER_NOTIF_FLAG_CONTINUE` (Linux >= 5.5). The
  notify handler emits an audit event and returns; it does not gate the
  syscall, does not rewrite arguments, and does not kill the child. This
  preserves ADR 0002 verbatim: the executor still runs unsandboxed, the
  service account is still the boundary.
- **Opt-in.** Disabled by default. A new `RELAY_SHELL_SECCOMP_NOTIFY`
  setting (default `off`) turns it on. When `off`, no seccomp filter
  is installed on the child and the spawn path is byte-identical to
  today.
- **Linux-only.** Macs and BSDs silently no-op the setting (logged once
  at startup with the host's `uname -s`). The runbook documents the
  supported kernel floor (5.5 for `ADDFD`/`CONTINUE`; 6.0+ recommended
  for stable `seccomp_notify_id_valid` semantics).
- **Narrow syscall set.** The filter notifies on a small,
  forensically-interesting list — `execve`, `execveat`, `openat` with
  `O_WRONLY|O_RDWR|O_CREAT`, `mount`, `umount2`, `setuid`/`setgid`,
  `unshare`, `prctl` (with capability-relevant `option` values), and
  `ptrace`. Everything else stays in the default `SECCOMP_RET_ALLOW`
  path with no kernel-userspace round-trip. The list is checked into
  `src/relay_shell/seccomp.py` and version-pinned the way
  `patterns.py` is.
- **Bounded audit volume.** The notify handler writes one JSON event
  per notification into the same `audit.jsonl` stream with
  `tool="syscall_notify"` and `tier=0` (a passive observation, not a
  call). The event carries the originating `request_id`, the child
  PID, the syscall name and numeric arguments (no buffer
  dereferencing — that requires `PIDFD_GETFD` and re-introduces a
  sandbox-shaped attack surface). A per-call event cap
  (`RELAY_SHELL_SECCOMP_NOTIFY_CAP`, default 256) bounds the worst
  case — beyond the cap, the channel records a single
  `syscall_notify_overflow` line and stops emitting for that call.
- **Failure isolation.** If the supervisor's notify socket dies, the
  child continues unaffected (the kernel falls back to `ALLOW` for
  every subsequent notification once the listener is gone). The audit
  pipeline records `degraded=true` on the next call, identically to
  the existing `AuditLogger` degraded path.

## Consequences

- The audit record schema grows a new event type (`syscall_notify`,
  `syscall_notify_overflow`). Documented in `docs/architecture.md`
  §"Request lifecycle" and `docs/tools.md` §"Audit shape". The
  existing per-call record is unchanged — the new events are
  *additional* lines, not replacement fields, so log shippers and
  off-host parsers built against the current shape keep working.
- The runbook §2 audit pass gains a step under §3 (Upstream surface
  validation): assert that the kernel-side constants the filter uses
  (`SECCOMP_RET_USER_NOTIF`, `SECCOMP_USER_NOTIF_FLAG_CONTINUE`) are
  present in `libseccomp`'s headers on the build host. This catches a
  silently-downgraded kernel.
- The HTTP `/metrics` endpoint (ADR 0001 / B-012) gains two counters:
  `relay_shell_seccomp_notify_events_total{syscall="..."}` and
  `relay_shell_seccomp_notify_overflow_total`, so an operator can
  alert on a chatty child or a per-call cap that needs bumping.
- The `verifier` (`relay-shell --verify-deploy`, B-020) gains a check
  that warns when `RELAY_SHELL_SECCOMP_NOTIFY=on` is set on a host
  whose kernel is below 5.5; the verifier already speaks the env-var
  vocabulary so this is a one-row addition.
- The CI matrix (B-009, Python 3.12/3.13/3.14) does not need a new
  axis; the seccomp code path is gated behind the env var and skipped
  in CI by default. A dedicated `seccomp` pytest mark covers the
  Linux-only tests; CI runs them on the `ubuntu-latest` leg only.

## Rejected alternatives

- **Seccomp filter mode (`SECCOMP_RET_KILL_PROCESS` /
  `SECCOMP_RET_ERRNO`).** This *is* a sandbox — exactly the posture
  ADR 0002 rejects. A kill-on-violation filter would make every new
  syscall added by a kernel upgrade a potential outage and would
  require maintaining a denylist big enough to cover the long tail of
  what an operator's scripts legitimately do. Notify-mode keeps the
  capability and adds visibility without taking on the kill-list
  maintenance burden.
- **eBPF tracing via `bpftrace` / `tracee` / a custom `BPF_PROG_TYPE_KPROBE`
  program.** Heavier dependency surface (kernel headers, BTF on older
  kernels, a privileged loader process), and the per-event payload
  carries kernel pointers we would have to peer-dereference to
  attribute to a `relay-shell` call. Seccomp-notify ties events to
  the *child PID we just spawned*, which is the attribution we
  actually want; eBPF would deliver firehose-scoped events we then
  have to filter back down to one PID tree.
- **`ptrace(PTRACE_SEIZE)` per child.** Quadratic single-stepping cost
  on syscall-heavy workloads (a `find /` would crawl), a well-known
  DoS surface (the tracer can be stalled by an uncooperative tracee),
  and Linux limits one tracer per task — adoption would conflict
  with operators running their own `strace`/`gdb` on the same child.
  seccomp-notify is the kernel's purpose-built mechanism for this
  exact case.
- **Lean on host `auditd`.** Already runs on most production hosts,
  and the operator should keep it on — but it sees every process on
  the box, not just `relay-shell` children, and the attribution back
  to a `relay-shell` `request_id` requires PID-tree walking that is
  racy under fast-exiting children. The two channels are
  complementary, not substitutes: `auditd` covers host-level events,
  the seccomp-notify channel covers per-call attribution.
- **A separate "syscall_audit.jsonl" sink.** Splitting the audit trail
  across files makes off-host shipping (ADR-aligned with
  `docs/audit-shipper.md`) and forensic correlation harder. One
  append-only stream with a discriminator on `tool` is consistent
  with the existing resource-read events (`tool="resource:<name>"`,
  see `docs/architecture.md`).

## Validation outcome

Deferred until status moves from Proposed to Accepted. Per ADR 0005,
acceptance requires the four-step validation pass (code index,
quality gates, upstream surface validation, behavior validation) to
run against the implementation; the findings table from that pass
lands in the same PR that flips the Status line above. Until then,
this ADR is a design contract for the implementing PR, not a record
of executed work.

## Operational notes (forward-looking)

These notes will move into `deployment.md` when the ADR is Accepted;
recording them here keeps the rationale next to the decision while the
implementation is still being shaped.

- **Kernel floor check.** The installer (`deploy/install-edge.sh`
  pattern) gains a `uname -r` comparison against `5.5`. Below the
  floor, the installer warns and forces `RELAY_SHELL_SECCOMP_NOTIFY=off`
  rather than silently producing an unfiltered child.
- **`libseccomp` packaging.** Add `python-libseccomp` (Debian/Ubuntu)
  to the `[seccomp]` extras in `pyproject.toml`. The bare install
  remains dependency-clean; the extra is required only for the new
  channel.
- **Off-host shipping.** No change to `docs/audit-shipper.md`: the new
  events ride the same JSONL stream the three existing recipes
  already tail, and the schema discriminator (`tool` field) is
  exactly what Vector/Fluent Bit/`journal-remote` already key on.
