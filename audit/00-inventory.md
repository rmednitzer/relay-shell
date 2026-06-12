# Phase 0: Recon and inventory (2026-06-12 full pass)

Read-only repository map for the 2026-06-12 audit pass. Every figure below
was produced by a command run in this session; commands are cited inline.
Branch note: the task template requested `audit/2026-06-12-full-pass`, but
this session's execution harness pins all development to
`claude/bold-bell-9h5luz`, so that branch carries the pass (recorded here
rather than silently deviating).

## What this repository is

`relay-shell` is a Python MCP (Model Context Protocol) server exposing local
shell and SSH operations as MCP tools, with an audit / policy / redaction
trust boundary around a deliberately unsandboxed executor (ADR 0002). One
package, no services besides the optional HTTP transport.

## Component map

| Component | Location | Notes |
|---|---|---|
| Server assembly + 21 tools | `src/relay_shell/server.py` | every tool runs through `Relay.run` (policy -> work -> truncate -> audit) |
| Config | `src/relay_shell/config.py` | pydantic-settings, `RELAY_SHELL_*` env vars, frozen |
| Audit sink + hash chain | `src/relay_shell/audit.py` | JSONL/CEF/LEEF formats, opt-in tamper-evident chain (ADR 0007) |
| Policy tiers | `src/relay_shell/policy.py` | Tier 0..3, `open`/`guarded`/`readonly`, deny list first |
| Pattern tables | `src/relay_shell/patterns.py` | redaction + tier regexes, `PATTERNS_VERSION = "4"` |
| Redaction | `src/relay_shell/redaction.py` | argument scrubbing before audit |
| Local execution | `src/relay_shell/shelltools.py` | one-shot command/script, process-group kill |
| PTY sessions | `src/relay_shell/sessions.py` | local PTY transport + bounded registry |
| SSH pool | `src/relay_shell/sshpool.py` | asyncssh connection cache, SFTP, forwards |
| Inventory | `src/relay_shell/inventory.py` | ssh_config + JSON inventory resolver |
| Seccomp notify channel | `src/relay_shell/seccomp.py` | opt-in audit-only syscall observation (ADR 0006) |
| Metrics | `src/relay_shell/metrics.py` | hand-rolled Prometheus exposition (HTTP only) |
| Deploy drift verifier | `src/relay_shell/verifier.py` | `relay-shell --verify-deploy` |
| OAuth 2.1 provider | `src/relay_shell/auth/oauth.py` | file-backed, optional, HTTP transport only |
| CLI entrypoint | `src/relay_shell/__main__.py` | `relay-shell` script, `--check-config` / `--verify-deploy` / `--verify-audit` |
| Deploy assets | `deploy/` | systemd unit + hardening drop-in, Caddyfile, logrotate, two installers |
| Docs | `docs/` | architecture, tools, deployment, runbook, audit-shipper, 8 ADRs |
| CI | `.github/workflows/` | 7 workflows (see below) |

Sizes (`wc -l src/relay_shell/*.py src/relay_shell/auth/*.py`,
`ls ... | wc -l`): 19 source files, 5920 lines; 27 test files
(`tests/*.py` including `conftest.py`), 6305 lines. Test code outweighs
source code.

## Languages, build system, entry points

- Language: Python (`requires-python = ">=3.12"`, classifiers 3.12/3.13/3.14
  in `pyproject.toml`). Ancillary: Bash (`deploy/install*.sh`,
  `scripts/healthcheck.sh`), systemd units, Caddyfile, YAML (CI), JSON5
  (renovate).
- Build backend: `hatchling` (`[build-system]` in `pyproject.toml`); wheel
  force-includes `deploy/` as `relay_shell/_deploy` for the drift verifier.
- Entry point: console script `relay-shell = relay_shell.__main__:main`;
  also `python -m relay_shell`. Transports: `stdio` (default) and
  `streamable-http`.

## Dependency posture

From `pyproject.toml` and `grep -c '==' requirements.txt`:

- Runtime deps (7): `mcp==1.27.2` (pinned), `pydantic>=2.11`,
  `pydantic-settings>=2.7`, `asyncssh>=2.18`, `uvicorn>=0.34`,
  `starlette>=0.47`, `anyio>=4.6`.
- Optional `[http]`: `PyJWT>=2.10`, `cryptography>=44`.
- Dev extra (8): pytest, pytest-asyncio, hypothesis, ruff, mypy,
  coverage[toml], pre-commit, PyJWT/cryptography.
- `requirements.txt`: 14 `==`-pinned entries acting as the validated
  resolve mirror (no hash pinning; no `poetry.lock`/`uv.lock` style
  lockfile). Renovate (`renovate.json5`) plus the `pip-audit.yml` and
  `dependency-review.yml` workflows manage updates and CVE exposure.

## CI configuration

`.github/workflows/` (read this session):

| Workflow | Trigger | Jobs / gates |
|---|---|---|
| `ci.yml` | push main, PR | py 3.12/3.13/3.14 matrix: ruff check + format, mypy --strict, pytest with coverage (subprocess collection, fail_under=90) |
| `codeql.yml` | push main, PR, weekly | CodeQL python |
| `dependency-review.yml` | PR | dependency-review-action |
| `pip-audit.yml` | push main, PR, daily | `pip-audit --strict` over `[dev,http]` resolve |
| `nightly-fuzz.yml` | daily | `pytest -m fuzz` (hypothesis) |
| `sbom.yml` | tag `v*` | CycloneDX SBOM attached to release |
| `release.yml` | tag `v*` | signed-tag verify -> build+test -> OIDC publish to PyPI (`pypi` environment) |

All workflows pin actions to full commit SHAs and declare least-privilege
`permissions:` blocks (verified by reading each file; `sbom.yml` needs
`contents: write` to upload release assets, `codeql.yml` needs
`security-events: write`).

## Container / IaC

No Dockerfile, no Kubernetes, no Terraform (`find . -type f` listing shows
none). Deployment is systemd + Caddy on a host, driven by
`deploy/install.sh` and `deploy/install-edge.sh`.

## Test layout

`tests/` is flat, one module per source module plus integration suites:
`test_stdio_e2e.py` (real subprocess MCP client), `test_ssh_integration.py`
(in-process asyncssh server), `test_fuzz.py` (hypothesis, behind `-m fuzz`),
`test_seccomp.py` (portable BPF simulator + privileged `seccomp`-marked
live tests). `pytest` config in `pyproject.toml`: `asyncio_mode = "auto"`,
default run deselects `fuzz`.

## Toolchain actually available in this environment

Recorded from `python3 --version`, `ls /usr/bin/python*`, `command -v uv`
and the venv bootstrap in this session:

- OS: Linux 6.18.5 (container; no systemd services running).
- Pythons on PATH: 3.10, 3.11 (default `python3` = 3.11.15), 3.12, 3.13.
  No 3.14 interpreter, so the CI 3.14 matrix leg is not reproducible here.
- `uv` present at `/root/.local/bin/uv`; project venv created with
  `python3.12 -m venv .venv` (first attempt with default `python3` failed:
  `Package 'relay-shell' requires a different Python: 3.11.15 not in '>=3.12'`).
- System-wide ruff 0.15.8 / mypy 1.19.1 / pytest 9.0.2 exist on PATH but the
  baseline uses the project venv's pinned versions (see
  `audit/01-baseline.md`).
- `gh` CLI not available in this environment; GitHub interaction goes
  through the session's GitHub MCP tooling.
- `.env.example` exists in the tree but is unreadable in this session
  (the harness denies reads of `.env*` paths), so cross-checks that
  involve its contents are marked `[UNVERIFIED]` in later phases.

## Git state at audit start

`git log --oneline | wc -l`, `git log -1 --format='%H %ci'`, `git status`:
50 commits, HEAD `6bb3518b02e6881e69b5452ed912a9de140643f3`
(2026-06-09 20:05:48 +0200, "Close backlog B-024/B-026 ... (#87)"),
working tree clean. Branches: `main` and `claude/bold-bell-9h5luz`
(this session), both tracking origin.

## Prior assurance work (context for this pass)

- `audit/2026-05-27-engagement.md` and `audit/2026-06-01-engagement.md`:
  frozen engagement packs; the 2026-06-01 pack carries one outstanding
  operator action (F-G2, branch protection on `main`).
- `docs/adr/0005-codebase-validation.md`: running record of validation
  passes (2026-05-24, 2026-05-31, 2026-06-01).
- `docs/runbook.md` §7: the live backlog; §8: per-file docs maintenance
  plan.
