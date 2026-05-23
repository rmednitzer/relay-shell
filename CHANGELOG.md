# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `audit_tail` MCP tool (Tier 0, read-only). Returns the last N
  records from the audit log as JSONL, oldest first. `lines` defaults
  to 50 and is clamped to `[1, 1000]`. Opens a fresh read-only fd so
  the writer's append-only handle is untouched. Lets an operator MCP
  client debug a session without shelling into the host. The audit
  log's "output body never written" invariant is preserved end-to-end
  (regression test in `tests/test_audit_tail_tool.py`).
- CI now runs the full check matrix on Python **3.12, 3.13, and
  3.14** instead of 3.12 alone. The package floor stays `>=3.12`
  (declared in `pyproject.toml`); the matrix surfaces interpreter-
  specific regressions early. `fail-fast: false` keeps every entry's
  result visible so a single 3.14 wheel gap does not mask a 3.13
  regression. Classifiers in `pyproject.toml` updated to advertise
  the three supported versions on PyPI.
- `relay-shell --check-config` CLI flag. Loads `RELAY_SHELL_*` settings,
  constructs the server (audit sink, policy, inventory, OAuth if
  enabled) without starting a transport, and exits 0 on success or 2
  on any initialization failure - including a degraded audit sink.
  Intended for CI pipelines that bake an image so a misconfiguration
  fails the build rather than crashes the running service at start.
  Documented in `README.md` (Quickstart) and `docs/deployment.md` §2.
  Four `subprocess.run`-based tests in `tests/test_main.py` exercise
  the new flag and close T-001 (the previously-untested
  print-and-return-2 path in `__main__.main()`).
- `CODE_OF_CONDUCT.md` adopting the Contributor Covenant 2.1. The
  file is a thin pointer to the canonical upstream URL so wording
  changes track automatically; it documents scope, the
  enforcement-reporting channel (private GitHub security advisory,
  same as vulnerability reports), and the Community Impact Guidelines
  link. Cross-linked from `README.md` and `CONTRIBUTING.md`.
- `docs/adr/README.md` indexing every ADR (number, title, status, date,
  one-line subject) and documenting when a new ADR is required, the
  filename convention, and the next free number. Cross-linked from
  `docs/architecture.md` and `docs/runbook.md` §6.
- `.pre-commit-config.yaml` mirroring the CI quality loop: `ruff`,
  `ruff format`, `mypy --strict` (local hook against the project's
  venv), plus standard hygiene hooks. A new banned-imports rule under
  `[tool.ruff.lint.flake8-tidy-imports.banned-api]` refuses to let
  `requests` or `urllib3` enter the codebase synchronously - they
  would block the event loop. `pre-commit` is in the dev extras;
  `CONTRIBUTING.md` documents the one-shot install.

### Fixed

- `Authorization:` redaction no longer leaks the bearer / Basic /
  Signature value. The pattern previously consumed only the first
  whitespace-delimited token after `:`/`=`, so
  `Authorization: Bearer <token>` collapsed to
  `Authorization: [REDACTED] <token>` and the value survived in the
  audit log. The widened pattern handles three input shapes uniformly:
  the bare HTTP header form (value runs to end-of-line), the quoted
  CLI flag form `-H "Authorization: ..."` (value stops at the
  surrounding closing quote), and the JSON dict literal form
  `{"Authorization": "..."}` (value stops at its own closing quote).
  The value class consumes past commas so AWS Signature v4 and Digest
  challenge-response schemes do not strand the trailing
  `Signature=<hex>` / `response="<hash>"` fields. `PATTERNS_VERSION`
  bumped to `"2"`. Regression tests in `tests/test_patterns.py`
  cover Bearer, Basic, SigV4, Proxy-Authorization, single-quoted CLI,
  JSON-dict, and multi-header inputs.

### Changed

- Redaction and tier-classification regex tables moved into a dedicated
  `src/relay_shell/patterns.py` module. `redaction.py` and `policy.py`
  now consume the published `REDACTION_*` / `TIER*_PATTERN` /
  `PRIV_ESC_PATTERN` names; the executor bodies are unchanged.
  `PATTERNS_VERSION` is a monotonic counter that audit consumers can
  read to detect a pattern-set upgrade. `tests/test_patterns.py`
  anchors compile-time shape and provides paired over-scrub /
  under-scrub cases per family. No behavior change.

### Added

- `.github/workflows/sbom.yml` generates a CycloneDX SBOM (JSON + XML,
  CDX spec 1.5) of the resolved Python environment on every `v*` tag
  push and attaches both files to the GitHub release. Cheap
  supply-chain signal; no runtime change. A `workflow_dispatch` input
  lets the workflow attach an SBOM to an existing tag after the fact.
- `docs/audit-shipper.md` with one worked example each for Vector,
  Fluent Bit, and `journalctl` → `systemd-journal-remote`. Cross-linked
  from `SECURITY.md` and `docs/deployment.md` §6 so the "ship the log
  off-host" instruction now points at concrete configs that preserve
  the append-only posture and rotation behavior.
- Coverage measurement in CI with a 75% floor. Configuration lives in
  `pyproject.toml` and enables subprocess collection so the stdio e2e
  contributes; the CI workflow drops a small `coverage_subprocess.pth`
  during install. Current measured baseline is ~78%; `coverage report`
  fails the CI step below 75. See `docs/runbook.md` §4.3 for the local
  recipe and §7.2 B-022 for the path to raising the floor to 85%.
- `CONTRIBUTING.md` covering scope, branch naming, the local-loop
  recipe, the documentation-moves-with-code requirement, and the
  security-sensitive-PR review path. The runbook remains the canonical
  procedure; `CONTRIBUTING.md` is the entry point that links into it.
- GitHub PR template and bug / feature / security issue templates under
  `.github/`. The PR template encodes the runbook §3.1 cross-reference
  checklist and the §3.3 security-sensitive-diff confirmations so they
  travel with every PR.
- Maintenance runbook at `docs/runbook.md` covering audit, review,
  validate, enhance, and extend procedures, a prioritized backlog
  (capability, quality, ops, docs, security hardening), and a per-file
  `.md` update plan.
- Automated TLS at the edge: `deploy/Caddyfile` is now parameterized via
  env variables and `deploy/install-edge.sh` provisions Caddy with ACME
  (Let's Encrypt by default) for hands-off issuance and renewal.
- ADR 0004 documenting the edge-TLS automation choice and rejected
  alternatives (certbot + cron, native TLS in the Python service).

### Changed

- `.env.example` and `docs/deployment.md` document the new
  `RELAY_SHELL_EDGE_*` variables and the one-shot install flow.
- Bumped MCP SDK: `mcp` 1.26.0 → 1.27.1 (tracked by Dependabot, validated
  by the existing test suite). ADR 0001 and `docs/architecture.md` updated
  to match the actual pin.

### Fixed

- `shell_exec` no longer permits policy/audit bypass through `stdin` or
  `env_json`: the policy-text probe now includes both, so a deny pattern
  that matches a command also matches the same payload smuggled in via
  stdin or an environment variable.
- Audit log creation uses `O_APPEND | O_CREAT` so the sink opens
  successfully on files hardened with `chattr +a`; the pre-create no
  longer races a stat/chmod path that an append-only attribute would
  reject.
- Argument redaction now covers single-dash long-name CLI flags
  (`-token=val`, `-password val`) and dash-prefixed secret values
  (`--token -abc123`), with escape-aware quoted-value handling. Compact
  `-p<value>` is redacted only inside MySQL-family invocations to avoid
  over-redacting `-p22` (ssh), `-p1-1000` (nmap), and similar overloads.
- File OAuth provider writes its JSON store with explicit `0o700`
  directory and `0o600` file modes regardless of the caller's umask.

### Security

- Treat the audit log as evidence only until shipped off-host; the
  bundled logrotate config drops and restores the append-only attribute
  across rotation. See `docs/deployment.md` §6.

## [0.1.0] - 2026-05-19

### Added

- Initial release: a Model Context Protocol server for shell and SSH
  operations, built on the official `mcp` SDK (FastMCP), `asyncssh`, and
  `pydantic-settings`.
- Local shell: `shell_exec`, `shell_script`, `shell_spawn`.
- SSH: `ssh_exec`, `ssh_spawn`, `ssh_upload`, `ssh_download`,
  `ssh_forward` (L/R/D), `ssh_forward_list`, `ssh_forward_close`,
  `ssh_check`, `ssh_hosts`.
- Unified session control for local and SSH PTYs: `session_send`,
  `session_recv`, `session_resize`, `session_kill`, `session_list`.
- `server_info` diagnostics tool.
- Append-only JSONL audit log with SHA-256 output hashing, argument
  redaction, and a rotation-safe handler.
- Tiered-authority policy layer (`open` / `guarded` / `readonly`) with
  always-on deny list and Tier 0..3 classification.
- Optional OAuth 2.1 provider for the HTTP transport: DCR with
  single-client lockdown, PKCE, file-backed rotating tokens, lazy expiry.
- stdio and streamable-HTTP transports.
- Deployment assets: systemd unit + hardening drop-in, reference Caddyfile,
  logrotate config, idempotent installer.
- Test suite: unit coverage plus an in-process `asyncssh` integration
  fixture (no network, no live credentials).
- Documentation: architecture, full tool reference, deployment guide, and
  three ADRs (runtime/SDK choice, no-sandbox posture, tiered authority).
