<!--
Thanks for contributing to relay-shell.

Before opening this PR, walk the runbook §3.1 checklist below. The
checklist enforces the project's "documentation moves with code" rule:
new tools, env vars, and modules must be reflected in every cross-
referenced source in the same PR.

Run the local loop before pushing:

    ruff check . && ruff format --check . && mypy && pytest -q

Reference: docs/runbook.md
-->

## Summary

<!-- One or two sentences explaining what changes and why. Link the
backlog item if applicable: "Closes B-007 from docs/runbook.md". -->

## Type of change

- [ ] Bug fix
- [ ] New capability (tool / transport / auth provider)
- [ ] Security hardening
- [ ] Documentation
- [ ] Build, CI, or release automation
- [ ] Refactor / cleanup (no behavior change)

## Runbook §3.1 checklist

- [ ] CI is green on the PR head commit (lint, type-check, tests,
      CodeQL, dependency-review, pip-audit, gitleaks).
- [ ] No new file is undocumented in `docs/architecture.md` module
      table.
- [ ] No new tool is missing from `docs/tools.md`,
      `tests/test_server.py::_EXPECTED`, and the README capability
      tables.
- [ ] No new env var is missing from `.env.example`, `Settings`, and
      `docs/deployment.md`.
- [ ] No new dependency is added without a justification in the PR body
      and a pinned version in `requirements.txt`.

## Security-sensitive diff (runbook §3.3)

Tick if this PR touches any of: `patterns.py`, `audit.py`, `redaction.py`,
`policy.py`, the `Relay.run()` body or a resource handler in `server.py`,
`auth/oauth.py`, `metrics.py`, `seccomp.py`, `deploy/install*.sh`, or
`deploy/Caddyfile`. (Full list with rationale: runbook §3.3.)

- [ ] This PR is security-sensitive.

If ticked, also confirm:

- [ ] `/security-review` was run on the diff (or the manual checklist
      in runbook §3.3 was walked).
- [ ] Audit-record fields unchanged (`ts, tool, tier, denied, args,
      output_sha256, output_len, exit_code`); output body still hashed
      only.
- [ ] `policy_text` passed to `Relay.run()` covers every byte the
      executor will see (command + stdin + env_json + script body).
- [ ] Redaction patterns have paired over-scrub and under-scrub tests.

## Test plan

<!-- How was this verified locally? Which tests were added or changed?
For UI-less server changes the full local loop is usually enough;
for behavior changes, name the new test(s). -->

- [ ] `ruff check . && ruff format --check . && mypy && pytest -q`
      passes locally.
- [ ] New behavior has a paired test (under `tests/`).
