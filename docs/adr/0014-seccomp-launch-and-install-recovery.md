# ADR 0014: Fresh-process syscall auditing and installer recovery qualification

- Status: Accepted
- Date: 2026-10-20

## Context

The optional audit channel installs a filter in Python's `preexec_fn` while the
parent already has supervisor threads. CPython explicitly warns this can deadlock
before exec. Monitor shutdown also joins synchronously in async tool paths.
`creat` and `openat2` are absent from the filter. The installer mutates its venv
in place, while the existing rehearsal restores only that venv, not service state.

## Decision

Use an absolute copy of the installed `seccomp.py` as a fresh interpreter launcher
with `-I -S`, no site startup and no caller module search path. Pass exact target
argv and only the listener-handshake and exec-status descriptors. No Python
callback runs between the threaded parent's fork and exec. The launcher installs
the existing CAP_SYS_ADMIN-only filter and execs the target in the same process
and process group. The off path is unchanged. A close-on-exec error pipe preserves
missing/denied executable errors; a bounded startup failure kills/reaps the owned
launcher group. No retry can duplicate a target effect. Restore Python-modified
signal defaults before target exec. Installation refusal remains degraded auditing,
not refusal of the target. The service identity and full shell authority remain.

Move supervisor stop/join into an owned worker task and await its completion under
cancellation. Filter version 3 adds unconditional `creat` and `openat2` notifications.
`openat2` carries flags behind a pointer; never dereference them or claim these
notifications establish write intent. Read-only calls are also recorded. The
existing event cap still bounds emission; every notification receives CONTINUE.

Extend the required release rehearsal with the actual installer on a fresh
GitHub-hosted disposable VM, using synthetic configuration/OAuth/SSH/audit state.
Force reinstall the locally built wheel without resolving dependencies so a
same-version source change cannot silently retain old bytes. Test a repeat
installation after deliberately altering the installed module, inject partial dependency loss at the runtime-install
boundary, detect failure, restore complete state at its original absolute paths,
and verify dependency consistency, OAuth token loading, MCP shell execution and
continued audit chaining. Refuse pre-existing paths/accounts and occupied ports.
Only a source-bound receipt leaves the job. No operational host is involved.

## Alternatives and consequences

- No change retains known deadlock/event-loop and audit-coverage gaps.
- A native compiled launcher could reduce startup overhead but adds compiler,
  platform and shipped-binary provenance requirements. The fresh interpreter is
  already a runtime dependency; accept its opt-in startup overhead.
- Disable the optional channel: simpler but removes useful capability; rejected.
- Atomic installer replacement and automatic rollback are separate designs.
  This change qualifies explicit recovery and does not claim atomicity.

Rollback is a source/workflow revert before deployment. An operational upgrade
still requires stopping the service and a retained consistent state/environment
snapshot. Hosted CI is not a live-host recovery qualification. Edge TLS, real
OAuth issuance/refresh, off-host anchors, full-host disaster recovery and restore
of physical append-only filesystem flags remain separate evidence.

## STPA and threat analysis

Extend ADR 0012's L-1 (unaccounted execution), L-2 (capacity loss), H-1/H-3 and
SC-1/SC-2/SC-4 with these scoped constraints:

| Constraint | Unsafe control action / causal scenario | Evidence |
| --- | --- | --- |
| SC-7: auditing must not strand spawn behind inherited Python locks | UCA-10: spawn provided with a Python post-fork callback in a threaded parent | `arm` exposes no preexec callback; actual launcher isolation and privileged command/PTY tests |
| SC-8: monitor cleanup must not block unrelated async work or disappear on cancellation | UCA-11: synchronous join delays all clients; cancelled cleanup loses ownership | async heartbeat/cancellation test plus existing PTY teardown and detached-listener tests |
| SC-9: newer open entry points must not silently evade declared coverage | UCA-12: notification omitted for creat/openat2; pointer flags misrepresented as write intent | BPF positive/foreign-arch controls and native syscalls with observed CONTINUE results |
| SC-10: recovery must restore the declared state before restart | UCA-13: restart after partial pip replacement with stale config/state | actual installer interruption, identical content/mode/owner/symlink snapshot comparison, dependency/OAuth/MCP/audit postconditions |

STRIDE: caller-controlled cwd/PYTHONPATH must not replace launcher imports (tampering,
privilege misuse); exact argv avoids shell reinterpretation; descriptors close at
exec/cleanup (disclosure/resource exhaustion); partial upgrades must not be reported
as successful (repudiation/integrity). Test data and receipts contain no real host
identifiers or credentials. The worker remains unsandboxed; same-UID mutation is
not prevented. The supervisor/listener is still availability-critical: loss of
all listener owners produces ENOSYS, and detached-listener capacity remains finite.
Those ADR 0006 residuals are not fixed by launch isolation.

## Primary contracts

- https://docs.python.org/3/library/subprocess.html#popen-constructor
- https://docs.kernel.org/userspace-api/seccomp_filter.html
- https://man7.org/linux/man-pages/man2/openat2.2.html

### Cross-version refinement (2026-10-20)

The separate `rehearse_upgrade.py` job extends SC-10 for one admitted v0.3.0
fixture (SDK 1.28.1) to current source on Ubuntu 24.04/Python 3.12. The signed source
and newly qualified frozen closure are distinct identities. Its package advisory
is handled by the fixture-specific source/live stateless checks described in the
fixture README; this does not alter current-runtime vulnerability gates.

- SC-11: missing audience binding is not repaired by silently trusting legacy
  grants. Hash migration preserves confidentiality improvement, but old access
  and refresh grants must be refused; an existing approved client reauthorizes
  through the actual HTTP PKCE/token routes. Wrong verifiers/resources, replayed
  refresh grants and revoked credentials must fail. UCA-14 is accepting an old
  grant merely because it survived on disk.
- SC-12: rollback must account for state accepted after the snapshot. Preserve the
  complete latest audit tail, restore the consistent baseline runtime/configuration,
  and reset authorization codes/access/refresh grants while stopped. Verify old
  and current credentials are refused before issuing a fresh baseline grant.
  UCA-15 is replaying snapshot credentials or discarding post-upgrade audit evidence.

Alternatives: no cross-version claim remains honest but leaves migration unknown;
binary-only downgrade can mix incompatible stores; blindly restoring every snapshot
file can revive revoked credentials and lose audit records. The chosen fixture
uses explicit consistent restoration plus declared grant invalidation and audit
retention. Its reauthorization is deliberate state loss, not transparent rollback.
It does not cover arbitrary versions, operational TLS/clients, new-client/revocation
policy reconciliation beyond this case, or automatic rollback. The old version's
security policy is not promoted to the current product policy.

Cross-version review refinement: SC-13 requires the complete installed target
distribution inventory, not only application/SDK identities or `pip check`.
UCA-16 is reporting an upgrade complete while legacy-only dependencies remain
importable. The dedicated venv is reconciled as the service UID; failures stop
installation and require snapshot recovery. Operator tools belong outside this
venv. The rehearsal independently checks the resulting inventory.

### Installer failure recovery decision (2026-10-20)

Extend SC-10/SC-13 with SC-14: an ordinary failed installation or handled
termination must restore the prior runtime and managed configuration before
returning failure, without starting a service or changing OAuth/SSH/audit state.
UCA-17 is leaving a partially replaced runtime after a detected installation
failure; CS-17 includes pip failure, managed-file installation failure and TERM.
UCA-18 is restoring a snapshot while a service writes state: require stopped
service feedback before mutation and restoration. Serialize cooperating installers.
The operator must prevent external service starts throughout installation.

No change preserves manual-only recovery. Atomic directory replacement needs
relocatable venv entry points and a separate commit protocol; defer it. Select
root-private snapshots of the venv and managed configuration, an EXIT rollback
handler and explicit signal exits. Build first without mutating the runtime.
Keep failure snapshots for intervention; success removes its own snapshot. Never
roll back audit records, OAuth stores or SSH trust. Reject symlinked top-level
managed targets. Root copies bytes but never executes the service-owned Python.
The service remains stopped after either outcome.

Rollback failure must retain evidence and report failure; it must not claim
recovery. SIGKILL, host loss, filesystem exhaustion/corruption, processes outside
the systemd unit and external starts are outside this automatic guarantee. Keep
full explicit snapshot recovery qualification for those cases. Root/service UID
compromise remains outside this maintenance transaction trust model. Revert the
installer/source before deployment to remove this behavior; never delete retained
failure snapshots until recovery is independently verified.
