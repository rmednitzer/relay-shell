---
name: Bug report
about: A tool behaves incorrectly, a guarantee is violated, or output is wrong.
title: "[bug] "
labels: ["bug"]
---

<!--
For security-sensitive bugs (audit-trail evasion, policy bypass, secret
leak, transport / auth issues) use the "Security report" template or a
private advisory instead. See SECURITY.md.
-->

## What happened

<!-- What did the tool do, and what was wrong about it? Paste the relevant
`[ERROR: ...]` / `[DENIED: ...]` string if there was one. -->

## Expected behavior

<!-- What should have happened, and where is that contract documented
(`docs/tools.md`, an ADR, a runbook section)? -->

## Reproduction

```text
# Minimal command or MCP tool call that reproduces the issue.
# If reproducing through an MCP client, include the tool name and
# arguments. Redact any real secrets before pasting.
```

## Environment

- `relay-shell` version (`relay-shell --help` or `pyproject.toml`):
- Python version (`python --version`):
- OS / distro:
- Transport (`stdio` / `http`):
- Policy mode (`RELAY_SHELL_POLICY_MODE`):
- MCP client (Claude Desktop / Inspector / SDK / other):

## Audit record (if relevant)

<!-- One JSON line from `audit.jsonl` if applicable. Strip the args
field if it might contain anything sensitive; the rest of the record
(timestamp, tool, tier, output_sha256, output_len, exit_code) is
generally safe to share. -->

```json
```

## Logs / additional context

<!-- Anything else that helps. User-facing output is intentionally bounded,
so the server's stderr is usually more informative than a stack trace. -->
