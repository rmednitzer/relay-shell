# Contributing to relay-shell

Thanks for the interest. `relay-shell` is a small, security-sensitive
project; the rules here exist to keep it that way without making
contribution painful.

Participation is governed by the
[Code of Conduct](CODE_OF_CONDUCT.md) — Contributor Covenant 2.1.

Most of the procedural detail lives in [`docs/runbook.md`](docs/runbook.md).
This document is the entry point: scope, branch naming, the local
loop, the docs-with-code requirement, and how security-sensitive PRs
are handled. For the step-by-step procedure for any of those, follow
the runbook section linked inline.

## Scope

`relay-shell` is operator infrastructure for shell and SSH operations
over MCP. We accept changes that:

- Add or improve **tools** (local shell, SSH, sessions, diagnostics).
- Add or improve **transports**, **auth providers**, or **policy
  heuristics**.
- Improve **auditability**, **redaction**, **bounds**, or **error
  containment**.
- Improve **deployment** (systemd, edge TLS, log shipping, packaging).
- Improve **documentation**, **tests**, or **release automation**.

We do **not** accept changes that reduce capability without an explicit
compensating control, hide execution paths from the audit pipeline,
weaken the deny list, or introduce an internal sandbox (see
[`docs/adr/0002-no-sandbox-full-access.md`](docs/adr/0002-no-sandbox-full-access.md)).

Before opening a non-trivial PR, check whether the change is already in
the backlog at [`docs/runbook.md`](docs/runbook.md) §7. If it is, the
PR description should reference the backlog item (e.g. "Closes B-007").
If not, consider opening an issue first. The repository ships a
feature-request issue template (under `.github/ISSUE_TEMPLATE/`) that
lists the questions a feature proposal should answer.

## Branch naming

- Develop on a fresh branch from `main` per logical change. Do not
  reuse a previous task branch.
- Use a short, descriptive slug: `claude/contributing-md`,
  `fix/audit-append-only`, `feat/ssh-keyscan`.
- One backlog item per branch unless two items are inseparable.

## Local loop

The canonical sequence runs in seconds (matches `docs/runbook.md` §4.1):

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"

ruff check .
ruff format --check .
mypy
pytest -q
```

Requires CPython 3.12+.

### Pre-commit

The repository ships a `.pre-commit-config.yaml` that mirrors the
local loop above (plus a forbidden-imports check that fails if anything
imports `requests` or `urllib3` — those would block the event loop).
Install it once after the venv setup:

```bash
pre-commit install            # set up the git hook
pre-commit run --all-files    # one-time sweep
```

The hooks are advisory locally and mandatory in CI. Pre-commit cuts a
round-trip you would otherwise lose when CI catches a missing `ruff
format` or a strict-typing regression on a remote runner.

A green local loop is the bar before pushing. If something fails in CI
but not locally, that is a CI-config bug; fix that, not the test. The
full validation phase (targeted runs, coverage, manual smokes) is in
[`docs/runbook.md`](docs/runbook.md) §4.

## Documentation moves with code

If a PR changes the externally observable surface, the documentation
changes in the same PR. The full cross-reference checklist lives in
[`docs/runbook.md`](docs/runbook.md) §3.1 and in the PR template; the
short version:

| If you change                | Also update                                                                            |
|------------------------------|----------------------------------------------------------------------------------------|
| Add or remove a tool         | `docs/tools.md`, `tests/test_server.py::_EXPECTED`, README capability tables, `_INSTRUCTIONS` in `server.py` |
| Add or remove an env var     | `.env.example`, `Settings`, `docs/deployment.md`                                       |
| Add or change a module       | `docs/architecture.md` module table                                                    |
| Add a runtime dependency     | `requirements.txt` (pinned) + a justification in the PR body                           |
| Change audit-record fields   | `docs/architecture.md` request lifecycle, `tests/test_audit.py`, runbook §2.3          |
| Change a redaction/tier pattern | `src/relay_shell/patterns.py` (bump `PATTERNS_VERSION`), paired over-scrub/under-scrub (redaction) or positive/near-miss (policy) tests in `tests/test_patterns.py`, runbook §6.4 (policy heuristics) / §6.5 (redaction rules) |

If the PR adds a new `.md` file, also add a §8 entry to the runbook so
the next maintainer knows what "done" means for that file.

## Tests

Every behavior change has a paired test. The recipes for the common
cases are in [`docs/runbook.md`](docs/runbook.md) §6. Two patterns
worth calling out explicitly:

- **Redaction patterns** require an over-scrub **and** an under-scrub
  test. The `test_redact_cli_flag_does_not_eat_next_flag` family is
  the model. Past PRs have repeatedly broken adjacent argv tokens.
- **Policy regexes** require a positive **and** a near-miss negative
  test. The deny list, not the heuristics, is the security guarantee;
  heuristics are advisory in `open` mode.

`pytest-asyncio` mode is `auto`; coroutines do not need a marker.

## Security-sensitive PRs

A PR is security-sensitive if it touches any of: `audit.py`,
`redaction.py`, `policy.py`, the `Relay.run()` body in `server.py`,
`auth/oauth.py`, `deploy/install*.sh`, or `deploy/Caddyfile`. The
PR-template checklist (under `.github/`) has a section for these;
tick it and walk the runbook §3.3 checklist before requesting review.

For PRs that touch the audit-record shape, the policy admission path,
or anything that writes systemd units / EnvironmentFiles, expect a
second reviewer and a slower merge cadence. That is the trade-off for
running unsandboxed by design.

For suspected vulnerabilities, **do not open a public issue with a
working exploit**. Open a private security advisory on the repository
(`Security` tab → `Report a vulnerability`) or open an issue without
exploit detail and request a private channel. The disclosure process,
scope, and indicative response targets live in
[`SECURITY.md`](SECURITY.md).

## Architecturally significant changes

Adding a new transport, a new auth provider, or any change to the
audit format requires an ADR under `docs/adr/` before code lands.
The runbook §6.2-6.5 recipes describe what each new category needs.
A change to the no-sandbox posture is out of scope; open an issue for
discussion before writing the ADR.

## Reviewing your own PR

Before requesting review, read the diff as if it were someone else's:

- Does every new branch in `policy.py` / `redaction.py` have a test?
- Does the PR description say *why*, not just *what*?
- Is anything in `[Unreleased]` in `CHANGELOG.md`?
- If you added a tool, does `tests/test_server.py::_EXPECTED` reflect
  it and does the `len()` assertion still pass?

These all keep showing up in the runbook §3.4 "common review
failures" list; catching them yourself saves a round trip.

## Code style and discipline

- `ruff check . && ruff format --check .` must pass. The line length
  is 100, target version is `py312`.
- `mypy` is strict for the package and relaxed only for
  `relay_shell.server` (FastMCP) and `asyncssh` (no stubs). Prefer
  narrowing an override in `pyproject.toml` over `# type: ignore` in
  the file.
- No new runtime dependency without a justification in the PR body.
- Tools never raise into the transport. Always return a bounded string.

## License

By contributing you agree your contribution is licensed under
Apache-2.0, matching the rest of the project. See
[`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
