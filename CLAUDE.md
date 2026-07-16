# CLAUDE.md

Claude-specific collaboration guide for `relay-shell`.

## Objective

Deliver robust, auditable, high-capability shell/SSH tooling for MCP clients, with
support for real-world privileged administration (including root and sudo) when
operators intentionally choose that posture.

## Core behavior expectations

1. Prefer surgical changes over broad rewrites.
2. Maintain compatibility with existing tools and response formats.
3. Keep security controls explicit, not implicit.
4. Preserve operational power; add safeguards and visibility instead of disabling features.

## Required development loop

1. Inspect relevant source + tests. For any change touching `policy`,
   `redaction`, `audit`, `patterns`, `broker`, or the `Relay.run` body, step 1
   is `docs/runbook.md` §2 (Audit) — those modules are the trust boundary.
2. Run baseline checks (`ruff check .`, `ruff format --check .`, `mypy`, `pytest -q`).
3. Implement minimal safe improvements.
4. Add/adjust tests for changed behavior.
5. Re-run checks.
6. Validate with review/security scanners before finalizing.

## Coding guidance

### Error handling

- Do not leak raw tracebacks to end users by default.
- Prefer structured, bounded error strings through existing error helpers.
- Keep exceptions contained inside tool execution wrappers.

### Auditability

- Audit every tool call through the central runner.
- Keep redaction applied to audited arguments.
- Never write command output bodies to audit logs.
- Include meaningful metadata when safe (`request_id`, `client_id`, exit code, tier).

### Security posture

- Keep policy denylist first and global.
- Keep `open`, `guarded`, `readonly` mode semantics stable.
- Treat privileged execution cues (`sudo`, `doas`, `pkexec`) as elevated-risk commands.
- Do not remove SSH host verification controls; only make behavior more explicit.

### Capability posture

The project intentionally supports:

- local shell execution
- SSH command/session execution
- file transfer and forwarding
- privileged admin flows (including root and sudo) when deployment allows

Do not constrain these capabilities unless explicitly requested.

## GitHub optimization checklist

- CI workflow has least-privilege `permissions`.
- Security workflows exist for CodeQL, dependency review, dependency CVE
  scanning (pip-audit), and secret scanning (gitleaks).
- Dependency update automation is configured.
- Docs clearly explain secure deployment and privileged deployment tradeoffs.

## Trusted references

- MCP: https://modelcontextprotocol.io
- GitHub Actions hardening: https://docs.github.com/actions/security-guides/security-hardening-for-github-actions
- CodeQL: https://docs.github.com/code-security/code-scanning/introduction-to-code-scanning/about-code-scanning-with-codeql
- Dependency review: https://docs.github.com/code-security/supply-chain-security/understanding-your-software-supply-chain/about-dependency-review
- OWASP logging: https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html
- OWASP secrets management: https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html

## When uncertain

Default to:

1. preserving current capability,
2. improving auditability,
3. tightening explicit safeguards,
4. adding tests and documentation,
5. extending the backlog in `docs/runbook.md` §7 over inventing scope mid-PR.
