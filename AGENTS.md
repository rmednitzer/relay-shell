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
- Keep security scanning enabled (CodeQL, dependency review).
- Prefer pinned major action versions and least-privilege workflow permissions.

## 5) Change workflow for agents

1. Read impacted modules and tests first.
2. Run current quality gates before edits.
3. Make minimal, targeted changes.
4. Re-run lint, type-check, and tests.
5. Run security/review validation for PR changes.
6. Update docs when behavior or operating guidance changes.

## 6) Repo-specific technical map

- `src/relay_shell/server.py`: tool registration + audited execution wrapper
- `src/relay_shell/policy.py`: tiering + admission control
- `src/relay_shell/audit.py`: append-only JSONL audit sink
- `src/relay_shell/redaction.py`: argument secret scrubbing
- `src/relay_shell/shelltools.py`: one-shot local command/script execution
- `src/relay_shell/sessions.py`: long-lived PTY session lifecycle
- `src/relay_shell/sshpool.py`: SSH connection reuse, SFTP, forwarding
- `tests/`: authoritative behavior contract

## 7) Definition of done

A change is done only when:

1. CI-equivalent checks pass locally (`ruff`, `mypy`, `pytest`)
2. Security and review validation are executed
3. No capability regressions are introduced unintentionally
4. Documentation reflects the resulting behavior and posture
