# AGENTS.md

This repository is designed for AI-assisted operations and development. This file
defines the required behavior for any coding/ops agent working in this repo.

## 1) Mission

`relay-shell` is an MCP server for high-capability local shell and SSH operations
with strong auditability and bounded execution. The project goals are:

1. Maximum useful operator capability (including privileged/root workflows when required)
2. Reliable execution and error containment
3. Audit-first observability
4. Reasonable, explicit security controls without disabling core capability

## 2) Non-negotiable operating principles

1. **Never bypass auditability intentionally.**
2. **Never introduce hidden execution paths.** All tool paths must remain visible and auditable.
3. **Preserve capability.** Do not reduce shell/SSH/root/sudo viability unless explicitly requested.
4. **Prefer explicit bounded behavior.** Timeouts, output limits, and session caps must remain enforced.
5. **Fail closed where practical, fail safe everywhere else.** Denials must be explicit; failures must not crash transport.

## 3) Trusted baseline references

Use these as decision anchors for changes:

- Model Context Protocol docs: https://modelcontextprotocol.io
- GitHub Actions hardening: https://docs.github.com/actions/security-guides/security-hardening-for-github-actions
- GitHub CodeQL: https://docs.github.com/code-security/code-scanning/introduction-to-code-scanning/about-code-scanning-with-codeql
- GitHub dependency review: https://docs.github.com/code-security/supply-chain-security/understanding-your-software-supply-chain/about-dependency-review
- OWASP Logging Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html
- OWASP Secrets Management Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html

## 4) Implementation standards

### Reliability

- Keep tool responses deterministic and bounded.
- Do not allow uncaught exceptions to escape tool boundaries.
- Preserve current behavior: return structured text errors instead of transport failures.
- Add/adjust tests with any behavior change.

### Security

- Keep argument redaction in audit pipeline.
- Do not log command output bodies in audit logs (hash + length only).
- Keep policy denylist precedence intact in all modes.
- Treat privilege escalation wrappers (`sudo`, `doas`, `pkexec`) as elevated risk during policy classification.

### Capability model (required)

This project supports multiple deployment postures:

- **Scoped mode**: unprivileged service account + constrained sudoers
- **Privileged mode**: full root/system-level operation where operators require it

Agents must preserve support for both.

### GitHub hygiene

- Keep CI passing (ruff, mypy, pytest).
- Keep security scanning enabled (CodeQL, dependency review, pip-audit,
  gitleaks secret scanning).
- Prefer pinned major action versions and least-privilege workflow permissions.

## 5) Change workflow for agents

1. Read impacted modules and tests first.
2. Run current quality gates before edits.
3. Make minimal, targeted changes.
4. Re-run lint, type-check, and tests.
5. Run security/review validation for PR changes.
6. Update docs when behavior or operating guidance changes.

`docs/runbook.md` is the executable procedure for sections 1, 4, and 6
above: §2 (Audit), §3 (Review), §4 (Validate), §5 (Enhance), §6
(Extend). Prefer extending the backlog in `docs/runbook.md` §7 over
inventing scope mid-PR.

## 6) Repo-specific technical map

- `src/relay_shell/__main__.py`: entrypoint; stderr-only logging; transport selection; `--check-config` / `--verify-deploy` CLI flags
- `src/relay_shell/server.py`: tool + resource registration; audited execution wrapper; `/metrics` route on HTTP
- `src/relay_shell/config.py`: typed `RELAY_SHELL_*` settings; fail-fast on invalid values
- `src/relay_shell/policy.py`: Tier 0..3 classification + admission control (consumes `patterns`)
- `src/relay_shell/broker.py`: opt-in Tier-3 confirmation broker (ADR 0009); issues/verifies single-use, TTL-bounded confirmation tokens so an irreversible call is gated behind `operation_confirm`, layered *after* the deny/mode check (never a bypass)
- `src/relay_shell/audit.py`: append-only JSONL audit sink (hash of output, not body)
- `src/relay_shell/redaction.py`: argument secret scrubbing (consumes `patterns`)
- `src/relay_shell/patterns.py`: version-pinned compiled regex tables for redaction + tier classification (`PATTERNS_VERSION` is a monotonic counter)
- `src/relay_shell/metrics.py`: in-memory Prometheus counter + gauge registry rendered at `GET /metrics` (HTTP only)
- `src/relay_shell/seccomp.py`: opt-in, audit-only seccomp-notify channel (ADR 0006); `CAP_SYS_ADMIN`-gated BPF USER_NOTIF filter + per-call supervisor that appends `syscall_notify` lines, never blocking. `SECCOMP_FILTER_VERSION` is a monotonic counter
- `src/relay_shell/errors.py`: `RelayError` hierarchy and uniform `[ERROR: ...]` formatter
- `src/relay_shell/shelltools.py`: one-shot local command/script execution
- `src/relay_shell/sessions.py`: local PTY transport + unified session registry
- `src/relay_shell/inventory.py`: `~/.ssh/config` + JSON inventory parsing and resolution
- `src/relay_shell/sshpool.py`: asyncssh connection cache, SFTP, port forwarding, PTY adapter
- `src/relay_shell/auth/oauth.py`: optional file-backed OAuth 2.1 provider (HTTP only)
- `src/relay_shell/verifier.py`: drift-detection comparator powering `relay-shell --verify-deploy`
- `src/relay_shell/util.py`: time, hashing, clamping, byte-safe truncation, id generation
- `tests/`: authoritative behavior contract (unit + in-process SSH integration). The canonical list of registered MCP tools lives in `tests/test_server.py::_EXPECTED` — treat that constant as source of truth when adding, removing, or renaming a tool.
- `deploy/`: systemd unit + hardening drop-in, Caddyfile, logrotate, installers
- `docs/adr/`: accepted design decisions (runtime/SDK, no-sandbox, tiering, edge TLS)
- `docs/runbook.md`: maintenance procedures (audit / review / validate / enhance / extend) and the prioritized backlog

## 7) Definition of done

A change is done only when:

1. CI-equivalent checks pass locally (`ruff`, `mypy`, `pytest`)
2. Security and review validation are executed
3. No capability regressions are introduced unintentionally
4. Documentation reflects the resulting behavior and posture
