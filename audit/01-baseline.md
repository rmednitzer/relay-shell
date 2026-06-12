# Phase 1: Validation baseline (2026-06-12 full pass)

Read-only baseline established at HEAD `6bb3518` before any change in this
pass. This is the regression reference for every later commit. All commands
were executed in this session inside the project venv unless stated.

## Build from clean state

| Step | Command | Outcome |
|---|---|---|
| venv (first attempt) | `python3 -m venv .venv && pip install -e ".[dev]"` | FAILED: default `python3` is 3.11.15; pip refused with `Package 'relay-shell' requires a different Python: 3.11.15 not in '>=3.12'` |
| venv (working) | `python3.12 -m venv .venv && .venv/bin/pip install -q -e ".[dev]"` | OK (`INSTALL_OK`, Python 3.12.3) |

Resolved tool versions in the venv (`ruff --version`, `mypy --version`,
`pytest --version`, `pip show mcp ruff`): ruff 0.15.17, mypy 2.1.0,
pytest 9.0.3, mcp 1.27.2.

Note: `requirements.txt` pins `ruff==0.15.16` as the validated mirror, but a
fresh resolve of the `dev` extra (`ruff>=0.8`) now lands 0.15.17. Harmless
today (all gates green) but the mirror is one notch stale.

## Quality gates (check-only)

| Gate | Command | Result |
|---|---|---|
| Lint | `.venv/bin/ruff check .` | PASS ("All checks passed!") |
| Format | `.venv/bin/ruff format --check .` | PASS ("46 files already formatted") |
| Types | `.venv/bin/mypy` (strict per pyproject) | PASS ("Success: no issues found in 19 source files") |

## Test suite

Command: `.venv/bin/pytest` (default addopts `-q -m "not fuzz"`).

- Result: **339 passed, 13 deselected, 1 warning in 36.23 s**. Zero
  failures, zero errors, zero skips.
- The 13 deselected tests are the `fuzz`-marked hypothesis suite (nightly
  CI job). Run separately in this session: see `audit/02-security-findings.md`
  for the result alongside the other security tooling.
- The `seccomp`-marked live tests executed (not skipped) because this
  container runs with CAP_SYS_ADMIN on x86_64 / kernel 6.18.5.
- Flaky candidates: none observed; two consecutive full runs in this
  session both passed (the second under coverage).
- Warning noise: one `StarletteDeprecationWarning` from
  `tests/test_metrics.py:15` ("Using `httpx` with `starlette.testclient`
  is deprecated; install `httpx2` instead"). Upstream deprecation, not a
  failure; tracked as finding Q-003.

## Coverage

Commands (runbook §4.3, subprocess collection wired via
`coverage_subprocess.pth` + `COVERAGE_PROCESS_START`):

```
coverage erase && coverage run -m pytest -q && coverage combine && coverage report
```

- **TOTAL 93%** (2370 statements, 162 missed); configured floor
  `fail_under = 90` passes.
- Per-module lows: `auth/oauth.py` 84%, `sessions.py` 86%, `__main__.py`
  87%, `inventory.py` 90%. Trust-boundary modules: `policy.py`,
  `redaction.py`, `patterns.py`, `metrics.py` at 100%; `audit.py` 94%;
  `server.py` 95%; `seccomp.py` 97%.
- Matches the documented expectation in `pyproject.toml` (~92%) and
  runbook §4.3 (gaps in `sessions.py` OS-specific fallbacks and
  `auth/oauth.py` HTTP-only paths).

## CI reproduction and drift

`ci.yml` runs ruff check + format check, `mypy`, and coverage-gated pytest
on Python 3.12 / 3.13 / 3.14. Reproduced locally on 3.12 (above),
including the subprocess-coverage `.pth` step, with identical commands.

Drift notes:

- Python 3.14 is not installed in this environment (`ls /usr/bin/python*`
  shows 3.10 to 3.13), so the 3.14 leg is `[UNVERIFIED]` locally; it is
  covered in CI per `ci.yml`.
- CI ruff resolves from the `dev` extra floor (currently 0.15.17), while
  `.pre-commit-config.yaml` pins `v0.15.16` and `requirements.txt` pins
  `0.15.16`. No behavioral difference observed (both pass), but the three
  sources can skew; recorded as finding Q-001.
- `pip-audit.yml`, `nightly-fuzz.yml` reproduce cleanly (Phase 2).
- `release.yml` / `sbom.yml` are tag-driven and not reproducible here
  (no tag, no OIDC); their logic was reviewed by reading only.

## Baseline summary (the regression bar)

| Metric | Value |
|---|---|
| ruff check / format | clean / clean |
| mypy --strict | 0 errors, 19 files |
| pytest (default) | 339 passed, 13 deselected, 36.23 s |
| coverage | 93% (floor 90) |
| Python | 3.12.3 (venv) |
