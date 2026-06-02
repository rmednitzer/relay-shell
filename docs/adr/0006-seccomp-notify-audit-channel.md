# ADR 0006: Syscall-level audit channel via seccomp-bpf notification mode

- Status: Accepted (Proposed 2026-05-24)
- Date: 2026-06-02

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

## Decision

Add an **audit-only** seccomp-bpf channel using user-notify mode
(`SECCOMP_RET_USER_NOTIF`, first available in Linux 5.0; the effective
floor for this design is **Linux >= 5.5** because
`SECCOMP_USER_NOTIF_FLAG_CONTINUE` lands there). The channel is:

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
  at startup with the host's `uname -s`). The runbook will document the
  supported kernel floor (5.5 for `ADDFD`/`CONTINUE`; 6.0+ recommended
  for stable `seccomp_notify_id_valid` semantics) when the implementing
  PR lands.
- **Narrow syscall set.** The filter notifies on a small,
  forensically-interesting list — `execve`, `execveat`, `openat` with
  `O_WRONLY|O_RDWR|O_CREAT`, `mount`, `umount2`, `setuid`/`setgid`,
  `unshare`, `prctl` (with capability-relevant `option` values), and
  `ptrace`. Everything else stays in the default `SECCOMP_RET_ALLOW`
  path with no kernel-userspace round-trip. The list will live in a
  dedicated module under `src/relay_shell/` and be version-pinned the
  way `patterns.py` is; the exact filename is the implementing PR's
  call.
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
  `syscall_notify_overflow`). The implementing PR will document the
  new shape in `docs/architecture.md` §"Request lifecycle" and
  `docs/tools.md` §"Audit shape". The existing per-call record is
  unchanged — the new events are *additional* lines, not replacement
  fields, so log shippers and off-host parsers built against the
  current shape keep working.
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

Accepted 2026-06-02 with the implementing PR (runbook §7.5 B-021). The
channel ships in `src/relay_shell/seccomp.py` (version-pinned
`SECCOMP_FILTER_VERSION`, like `patterns.py`), wired into the local
executor via a per-call `ContextVar`, with additive `syscall_notify` /
`syscall_notify_overflow` audit lines and two bounded `/metrics`
counters. The four-step ADR 0005 pass ran green against the
implementation:

1. **Code index** — one new module, no new tool (the 21-tool contract is
   unchanged; this is an audit *event*, not a tool). `server_info` grows a
   `seccomp` block; `Settings` grows `seccomp_notify` / `seccomp_notify_cap`.
2. **Quality gates** — `ruff` / `ruff format` / `mypy --strict` clean;
   `pytest` green; coverage holds the 90% floor (`seccomp.py` ~97% with the
   portable unit suite alone; the privileged paths carry a `# pragma: no
   cover` or are exercised by the `seccomp`-marked end-to-end tests).
3. **Upstream surface validation** — the kernel ABI constants
   (`SECCOMP_FILTER_FLAG_NEW_LISTENER = 1<<3`,
   `SECCOMP_RET_USER_NOTIF`, `SECCOMP_USER_NOTIF_FLAG_CONTINUE`, the notify
   ioctl numbers, and the 80/24/64 struct sizes) were validated against a
   live `Linux 6.18 / x86_64` host; `platform_support()` re-checks the
   struct sizes via `SECCOMP_GET_NOTIF_SIZES` at runtime and disables the
   channel on a mismatch (the "silently-downgraded kernel" guard this ADR
   called for).
4. **Behavior validation** — `seccomp`-marked end-to-end tests drive a real
   child and assert that `execve` and a write-`openat` are observed and
   allowed to continue, a read-only `open` is *not* notified, the per-call
   cap emits one overflow marker while the child still runs to completion,
   and the events extend the ADR 0007 hash chain.

### Refinements adopted at implementation (deltas from the Decision)

- **No `libseccomp` dependency.** The forward-looking note proposed a
  `python-libseccomp` extra; the channel is implemented in pure `ctypes`
  instead, so the bare and `[dev]` installs gain **zero** new dependencies.
  The `[seccomp]` extra is therefore unnecessary and was not added.
- **`CAP_SYS_ADMIN`-gated, never `no_new_privs`.** A seccomp filter installs
  with `CAP_SYS_ADMIN` *or* by latching `no_new_privs`. Latching
  `no_new_privs` would silently disable set-uid escalation in audited
  children (`sudo` would break) — a capability regression this project
  forbids and one the Decision's "preserves ADR 0002 verbatim" claim cannot
  tolerate. The channel therefore activates **only** with `CAP_SYS_ADMIN`
  (e.g. running as root, a supported privileged posture) and installs
  without `no_new_privs`, so set-uid/`sudo` semantics are unchanged. Without
  `CAP_SYS_ADMIN` the channel cleanly no-ops.
- **`x86_64` only in v1.** Only syscall-number tables we can validate on a
  live host ship; any other arch makes `platform_support()` report
  unsupported and the channel no-op, so a guessed number can never notify
  the wrong syscall. `aarch64` is a recorded follow-up (runbook §7.5).
- **Syscall set.** Implemented unconditionally: `execve`, `execveat`,
  `ptrace`, `mount`, `umount2`, `unshare`, `setns`, `chroot`, `pivot_root`,
  `setuid`/`setgid`/`setreuid`/`setregid`/`setresuid`/`setresgid`; plus
  `openat`/`open` gated on a write/create flag (`O_WRONLY|O_RDWR|O_CREAT`).
  `prctl` option-filtering is **deferred** (it needs per-argument BPF
  predicates and has volume concerns); recorded as a follow-up. The
  privilege/namespace coverage is broader than the Decision's sketch.
- **Runtime support check placement.** The Decision put a kernel-floor check
  in the `verifier` (`--verify-deploy`); that command does template *drift*
  detection only. The runtime check instead lives in `platform_support()`,
  is surfaced by `server_info.seccomp` (`supported` + `reason`), logged once
  at startup, and reflected by `--check-config`.
- **Scope (v1).** The one-shot local executor (`shell_exec` / `shell_script`
  / `ssh_keyscan`). Long-lived PTY sessions and the SSH-local half are a
  recorded follow-up (runbook §7.5).

## Operational notes (as accepted)

Operator-facing detail now lives in `docs/deployment.md` §6a; the as-built
rationale is captured here next to the decision.

- **Activation prerequisites, not a kernel-floor installer check.** The
  channel self-gates at runtime via `platform_support()`
  (Linux / `x86_64` / kernel ≥ 5.5 / `CAP_SYS_ADMIN` / a matching notify
  ABI). When `RELAY_SHELL_SECCOMP_NOTIFY=on` but a prerequisite is missing,
  it logs once at startup, `server_info.seccomp.supported` is `false` with a
  `reason`, and local spawns are byte-identical to the off path — there is
  no separate installer `uname -r` gate to drift out of sync.
- **No `libseccomp` packaging step.** The pure-`ctypes` implementation needs
  no system package; there is nothing to add to a base image beyond a kernel
  that meets the floor and the `CAP_SYS_ADMIN` posture.
- **Off-host shipping.** No change to `docs/audit-shipper.md`: the new
  events ride the same JSONL stream the three existing recipes already tail,
  and the schema discriminator (`tool` field) is exactly what
  Vector/Fluent Bit/`journal-remote` already key on.
