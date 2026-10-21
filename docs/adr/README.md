# Architecture Decision Records

These decisions shape the trust boundary, the runtime, and the
operator-facing posture of `relay-shell`. Read them in order the first time;
revisit one when its subject area changes.

The format follows [Michael Nygard's ADR
template](https://github.com/joelparkerhenderson/architecture-decision-record/blob/main/locales/en/templates/decision-record-template-by-michael-nygard/decision-record-template-by-michael-nygard.md):
context, decision, consequences. Each ADR has a `Status` line at the
top. Status values:

| Status      | Meaning                                                  |
|-------------|----------------------------------------------------------|
| Proposed    | Drafted, not yet adopted.                                |
| Accepted    | Adopted; the codebase reflects the decision.             |
| Superseded  | Replaced by a later ADR; see `Superseded by` line.       |
| Deprecated  | No longer applicable; kept for history.                  |

## Index

| ADR | Title | Status | Date | Subject |
|-----|-------|--------|------|---------|
| [0001](0001-runtime-and-sdk.md) | Runtime, SDK, and SSH library | Accepted | 2026-05-19 | Why Python 3.12 + the official `mcp` SDK + `asyncssh`, with the alternatives that were rejected (`paramiko`, building a transport from scratch). |
| [0002](0002-no-sandbox-full-access.md) | Unsandboxed, full-access posture | Accepted | 2026-05-19 | Why the executor runs without a meaningful internal sandbox: the project exists to give an MCP client real administrative power, so the safety story is compensating controls (audit, tier policy, redaction, bounds, deployment discipline). 2026-10-06 clarification: the full-root execution contract for host-administrator deployments. 2026-10-14 addendum: the caller is told what is unsafe (ADR 0013). |
| [0003](0003-tiered-authority.md) | Tiered authority | Accepted | 2026-05-19 | The four-tier classification (read-only / reversible / stateful / irreversible) plus `open` / `guarded` / `readonly` admission modes that consume it. The deny list is enforced first in every mode. 2026-10-14 update (A14-C9, `PATTERNS_VERSION` 16): classifier tuning, both directions, still heuristic. |
| [0004](0004-edge-tls-automation.md) | Automated TLS at the edge | Accepted | 2026-05-20 | Why `deploy/install-edge.sh` provisions Caddy + ACME (Let's Encrypt) for the HTTP transport, and why certbot+cron and native TLS in the Python service were rejected. |
| [0005](0005-codebase-validation.md) | Codebase validation against known-good sources | Accepted | 2026-05-24 | A repeatable validation pass against the upstream `mcp` / `asyncssh` / OAuth surfaces, the audit record schema, and the documented redaction / tier behavior. Dated outcomes were appended through 2026-06-21; later pin bumps are listed in ADR 0001 and later passes are the dated reports under `audit/`. |
| [0006](0006-seccomp-notify-audit-channel.md) | Syscall-level audit channel via seccomp-bpf notification mode | Accepted | 2026-06-02 | An audit-only seccomp-bpf channel (notify-mode, never blocking) that closes the audit gap on the child side of `asyncio.create_subprocess_*` without re-introducing a sandbox. Shipped in `src/relay_shell/seccomp.py` (pure `ctypes`, no new deps): opt-in via `RELAY_SHELL_SECCOMP_NOTIFY` (default off), `CAP_SYS_ADMIN`-gated so set-uid/`sudo` posture is preserved, Linux/`x86_64`/kernel ≥ 5.5, additive `syscall_notify` / `syscall_notify_overflow` audit lines (extend the ADR 0007 chain) plus two bounded `/metrics` counters. Proposed 2026-05-24; accepted with the implementing PR (runbook §7.5 B-021). Follow-ups landed 2026-06-09 (filter version 2): `prctl` notified for privilege-relevant options via an eq-any predicate (B-024) and coverage extended to local PTY sessions, whose transport adopts the monitor for the session lifetime (B-026). 2026-10-14 correction (A14-R4): a closed listener makes the kernel fail notified syscalls with `ENOSYS`, not allow them, so a stopped monitor now hands its listener to a detached server that keeps answering CONTINUE while a backgrounded process still holds the filter. |
| [0007](0007-audit-hash-chain.md) | Tamper-evident audit log via per-record hash chaining | Accepted | 2026-06-01 | An opt-in (`RELAY_SHELL_AUDIT_CHAIN`, default off), additive per-record hash chain (`seq`/`prev`/`chain`) that makes edits, insertions, reorders, and interior deletions of the on-disk audit log detectable by recomputation; the fail-closed `relay-shell --verify-audit` also rejects a missing / empty / head-truncated log by default (`--segment` for a rotation segment; tail-truncation needs the off-host copy), closing the integrity gap left by `chattr +a` + off-host shipping against the ADR 0002 residual-risk attacker. `jsonl` only; a CLI verb, not an MCP tool. |
| [0008](0008-operating-guidance-prompt.md) | Operating-guidance MCP prompt, audited like a resource read | Accepted | 2026-06-08 | Adds one MCP prompt (`operating_guide`) as the canonical home for detailed "when to use which tool" guidance (one-shot vs PTY session, the spawn+`session_*` workflow, fleet/transfer entry points), beyond the concise `instructions` string and per-tool descriptions. A fetch is a model-context pull, so it is audited (tier 0, stable `tool="prompt:<name>"`) and bounded by the same `max_output` cap, bypassing `Relay.run` as resource reads do; `prompts/list` returns metadata only and does not audit. No audit-record-shape change, only a new `prompt:` `tool` namespace alongside `resource:` / `syscall_notify`. |
| [0009](0009-tier3-confirmation-broker.md) | Opt-in two-step confirmation broker for Tier-3 operations | Accepted | 2026-07-15 | Adapts a plan → authorize → execute broker into `Relay.run`: an opt-in (`RELAY_SHELL_CONFIRM_TIER3`, default off), additive gate that makes a Tier-3 (IRREVERSIBLE) call return a single-use, TTL-bounded token instead of running, requiring an `operation_confirm(token)` arm step then a re-issue of the exact same call to execute. Bound to the exact operation, `sha256(tool \0 op_key)` where `op_key` is the policy text plus the full audited argument set (target and connection identity; transfers, forwards and `ssh_spawn` carry `user`/`port`/`key_path`/`jump` since 0.4.0), so the central gate covers every present/future Tier-3 tool with no per-wrapper param; layered *after* the deny list + mode check (never a bypass); audited `confirm_plan` / `confirm_execute` via a new optional `action` field (default-off byte-identical). Adds one tool (`operation_confirm`, 21 → 22) and `src/relay_shell/broker.py`. Rollback/verify-command pairing deferred to ADR 0010. 2026-10-14 follow-up (A14-C10b): tokens are also bound to the planning OAuth `client_id`, so a second client cannot arm or consume another client's token (STPA trace in the ADR). |
| [0010](0010-rollback-verify-broker.md) | Rollback / verify pairing for the confirmation broker (BRK-2) | Proposed | 2026-07-15 | The other half of the sibling brokers deferred from ADR 0009: pairing a Tier-3 op with a bound `verify_command` / `rollback_command` and auto-rollback on verify failure. **Decision: defer.** Specifies the design and the seven invariants any build must satisfy (chiefly: rollback/verify are themselves fully deny-list/tier-gated, never a policy-bypass channel; bound into the confirmation identity; three distinct audit records; bounded non-recursive loop), plus the concrete triggers (an autonomous/unattended deployment; operator-requested operation-bound remediation) that would move it to Accepted. Marginal value over a model sequencing verify/rollback itself is low until a trigger is real; no code. |
| [0011](0011-windows-openssh-powershell.md) | Windows targets via OpenSSH + PowerShell 7 | Accepted | 2026-07-15 | Adopts Windows-over-OpenSSH-with-`pwsh` as a first-class target class. Execution + SFTP already work (asyncssh passes the raw command to the remote's own shell, no POSIX wrapping); the gap was that the tier classifier (`patterns.py`) was POSIX-only, so pwsh destructive cmdlets (`Remove-Item -Recurse -Force`, `Clear-Disk`, `Stop-Computer`, `Remove-Service`, …) under-classified as Tier 1 and escaped `guarded`/`readonly` mode and the ADR 0009 broker. Increments A (pwsh-aware Tier-2/3 + priv-esc patterns; same anchoring/ReDoS discipline, POSIX byte-identical, `PATTERNS_VERSION` 9→10, paired FP tests) + B (docs §8b) landed with this ADR; increment C (PowerShell `-Credential`/`-AsPlainText` redaction, `PATTERNS_VERSION` 10→11) landed later; encoding/PTY (D/E) are documented caveats (pwsh is UTF-8). No translation layer, no new transport/tool. Classification stays heuristic. Tracked as WIN-1. |
| [0012](0012-cancel-safe-session-teardown.md) | Cancel-safe session teardown | Accepted | 2026-10-14 | Sessions removed from the registry (`close`, idle sweep, `shutdown`) are torn down by their own shielded, concurrent task, and `LocalPtyTransport.aclose` SIGKILLs on cancel, so a cancelled caller can no longer strand a live child, PTY fd or monitor thread. Since 0.4.0 a close sends SIGTERM, SIGHUP after 0.5 s (interactive shells ignore SIGTERM; closing one went from 5.01 s to 0.50 s) and SIGKILL at 5 s, and also kills what is left of the session's process group once the leader has exited. Carries the STPA trace (losses, hazards, constraints, UCAs, causal scenarios, tests). Residuals: a child that leaves the process group, loop shutdown mid-teardown, no SIGKILL equivalent for SSH channels. Tracked as A14-R10. |
| [0013](0013-open-by-default-with-unsafe-notices.md) | Open by default, with notices about what is unsafe | Accepted | 2026-10-14 | The default policy admits every command (pinned by tests); the caller is told, in a trailing `[NOTICE ...]` line, when an admitted call ran as Tier 2/3 or with host-key verification off, and `server_info` reports the permissive settings. Audit records are unchanged. Carries the STPA trace. Residual: the classifier is a heuristic, and a command without a notice is not thereby safe. |
| [0014](0014-seccomp-launch-and-install-recovery.md) | Fresh-process syscall auditing and installer recovery qualification | Accepted | 2026-10-20 | No threaded-parent Python preexec callback; async monitor cleanup; filter v3; actual disposable installer interruption and full service-state restoration. |

## When to write an ADR

Any of the following needs an ADR before code lands:

- A new transport (e.g. unix-socket alongside `stdio` / `streamable-http`).
- A new auth provider (e.g. JWT static-keys alongside the file-backed OAuth 2.1).
- A change to the audit-record shape or to the no-sandbox posture.
- A new policy category (not just another verb in the existing
  `TIER2_PATTERN` / `TIER3_PATTERN`; see `docs/runbook.md` §6.4).

Routine additions (a new tool, a new redaction pattern, a tightened test)
do not need an ADR; they go through the normal review loop. The runbook §6 has
recipes per case.

## How to write one

1. Number sequentially. Next free number is **0015**.
2. Filename pattern: `NNNN-short-slug.md`.
3. Required header:

   ```
   # ADR NNNN: <Title>

   - Status: Accepted
   - Date: YYYY-MM-DD
   ```

4. Sections: `Context`, `Decision`, `Consequences`, `Rejected
   alternatives` (when applicable).
5. Reference the ADR by number in code or other docs, not by file path; the
   number is the canonical handle.
| [0014](0014-seccomp-launch-and-install-recovery.md) | Fresh-process syscall auditing and installer recovery qualification | Accepted | 2026-10-20 | Removes threaded-parent pre-exec filter installation; qualifies installer recovery and documents its limits. |

## Cross-references

- `docs/architecture.md` - request lifecycle, module table, and how
  the ADRs map onto the runtime.
- `docs/runbook.md` §6 - extension recipes that may require an ADR
  before code lands.
- `SECURITY.md` - the threat model and how ADRs 0002 / 0003 constrain it.
