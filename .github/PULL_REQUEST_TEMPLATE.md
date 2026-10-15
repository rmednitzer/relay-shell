<!--
Walk the runbook §3.1 checklist below. It enforces "documentation moves with
code": new tools, env vars and modules must be reflected in every
cross-referenced source in the same PR.

Run the local loop before pushing:

    ruff check . && ruff format --check . && mypy && pytest -q

Reference: docs/runbook.md
-->

## Summary

<!-- What changes and why, in one or two sentences. Link the backlog item
if applicable: "Closes F-6 from docs/runbook.md". -->

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
- [ ] A new permissive setting has a matching entry in `notices.config_warnings`, and the
      default configuration still refuses no command (ADR 0013).
- [ ] No new dependency is added without a justification in the PR body
      and a pinned version in `requirements.txt`.

## Security-sensitive diff (runbook §3.3)

Tick if this PR touches any of: `patterns.py`, `audit.py`, `redaction.py`,
`policy.py`, the `Relay.run()` body or a resource handler in `server.py`,
`auth/oauth.py`, `metrics.py`, `seccomp.py`, `broker.py`, `sshpool.py`, `verifier.py`,
`deploy/install*.sh`, `deploy/Caddyfile`, `deploy/evidence/*`, or the release/SBOM
workflows and their tooling locks. (Full list with rationale: runbook §3.3.)

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

<!-- How was this verified locally? For behavior changes, name the new
test(s); for other server changes the full local loop is usually enough. -->

- [ ] `ruff check . && ruff format --check . && mypy && pytest -q`
      passes locally.
- [ ] New behavior has a paired test (under `tests/`).
