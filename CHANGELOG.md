# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- ADR 0005 documenting a repeatable validation pass against upstream
  known-good sources (the `mcp` SDK surface, `asyncssh.connect` kwargs,
  the OAuth provider contract, the audit-record schema, and canonical
  redaction / tier-classification samples). The ADR records the
  methodology, the 2026-05-24 outcome (all four steps green: 21 tools
  registered, 195 tests pass, 89% coverage with subprocess collection,
  every upstream symbol resolves on the pinned versions), and the
  three small documentation-drift findings the pass surfaced
  (`requirements.txt` pin staleness, runbook §4.3 coverage figure,
  runbook §3.4 obsolete tool-count reference). All three resolved in
  this PR. The next free ADR number is **0006**.
- README "Status" line under the title (version, supported Python
  matrix, transports, MCP SDK pin, last-validation date with ADR
  pointer) and a "Compatibility matrix" block (Python / host OS /
  transport / SDK / SSH library). Runbook §8.1 status updated.
- `SECURITY.md` "Disclosure timeline" subsection under "Reporting a
  vulnerability" (acknowledge in 7 days, fix or mitigation plan in
  30 days of triage, public advisory + credit when shipped). The
  reporter can request a faster window in their initial report.
  Runbook §8.2 status updated.
- `docs/architecture.md` cross-link to ADR 0005 (and the existing
  runbook §2 pointer) in the security-model section so the
  validation methodology is one click away from the request-
  lifecycle diagram. Runbook §8.6 status updated.
- `docs/tools.md` per-tool "Tests: ..." lines for every registered
  tool (and the resources section), each pointing at the test
  file(s) that exercise it. File paths only — line numbers drift.
  Runbook §8.7 status updated and the cross-check list extended to
  cover the new lines.
- `docs/deployment.md` §0 "Pre-flight checklist" (service account
  name, audit-dir writability + filesystem support for `chattr +a`,
  DNS A/AAAA, ports 80/443, SSH keypair, off-host audit shipper),
  §11 "Backup and restore" subsection (OAuth state dir,
  `/etc/relay-shell/` EnvironmentFile, audit log + rotations), and
  a cross-link to runbook §4.6 from the §9 Health section.
  Runbook §8.8 status updated.
- `docs/adr/0004-edge-tls-automation.md` "Operational notes"
  appendix listing the `journalctl -u caddy` and
  `caddy validate --config /etc/caddy/Caddyfile` invocations
  operators reach for during ACME troubleshooting and Caddyfile
  drift checks. Runbook §8.12 status updated.
- `.github/workflows/release.yml` cuts a PyPI release on a signed `v*`
  tag push. Three gated jobs: **verify** (annotated + GPG/SSH-signed
  tag, verified by GitHub; tag matches `[project] version` in
  `pyproject.toml`, read from the tagged commit); **build** (dev
  install, full test suite, `python -m build` + `twine check`);
  **publish** uses `pypa/gh-action-pypi-publish` for OIDC trusted
  publishing (no long-lived `PYPI_TOKEN` secret) in the `pypi` GitHub
  environment, so a required-reviewer approval gates the actual upload.
  A `workflow_dispatch` input lets an operator re-run an existing tag
  if PyPI was briefly down; the publish step passes `skip-existing:
  true` so the re-run is idempotent. The per-release procedure
  (version bump + sign-tag + push) is documented in
  `docs/runbook.md` §6.4. Closes B-005.
- Property-based fuzz suite for `redact` and `classify` (the audit /
  policy primitives). 13 hypothesis-driven invariants: `redact` is
  idempotent, never raises, preserves text without secret shape, kills
  Bearer / URL-creds / CLI-flag / `key=value` markers; `classify` is
  total, escalates to IRREVERSIBLE on any tier-3 substring, keeps the
  read-only tools at tier 0 under any command, and stays at REVERSIBLE
  on tag-free random text. Lives behind the `fuzz` pytest marker so the
  default `pytest` run skips it (`addopts = "-q -m 'not fuzz'"`); a new
  `.github/workflows/nightly-fuzz.yml` runs the suite daily with
  `HYPOTHESIS_PROFILE=ci` (5000 examples per property, ~55s wall) so
  the security-sensitive primitives keep finding latent counterexamples
  without slowing PR CI. `hypothesis` added to dev extras. Closes B-010.
- Three MCP **resources** so clients that prefer resources to tools can
  list hosts the protocol-native way:
  `relay-shell://inventory` (flat host list, JSON),
  `relay-shell://inventory/{host}` (one host's resolved spec, JSON), and
  `relay-shell://ssh-config` (`{"path": "...", "aliases": [...]}` for the
  active ssh_config file). The data shape matches the `ssh_hosts` tool
  output so client renderers can be shared. Each read is audited as
  tier 0 with a STABLE `tool` field per resource
  (`resource:inventory`, `resource:inventory_host`, `resource:ssh-config`) -
  the host parameter for the templated read is carried in `args` so
  redaction runs and tool-name cardinality stays bounded for downstream
  audit consumers. Resource bodies are bounded by the same `max_output`
  cap tools observe through `Relay.run`. The ssh-config alias list comes
  from the raw ssh_config parse (inventory overrides do not suppress
  aliases the file declares). Documented in `docs/tools.md` and the
  README capability table. Closes B-004.
- `GET /metrics` endpoint on the HTTP transport, in Prometheus text
  exposition format. Four metric names:
  `relay_shell_tool_calls_total{tool,tier,mode,outcome}` (counter),
  `relay_shell_active_sessions`, `relay_shell_active_forwards`,
  `relay_shell_audit_degraded` (gauges, read live at scrape time).
  Gauges close over the underlying registries (`SessionRegistry.count()`,
  `SshPool.forward_count()`, `AuditLogger.degraded`) so the metric never
  disagrees with the source. Hand-rolled exposition (no
  `prometheus_client` dep). The route is registered via
  `FastMCP.custom_route`, bypasses OAuth by design (same posture as
  health checks), and is gated on `RELAY_SHELL_TRANSPORT=http` - stdio
  servers do not mount it. The audit log remains the source of truth;
  metrics are for dashboards and reset on restart. Documented in
  `docs/deployment.md` §9a. Closes B-012.
- `relay-shell --verify-deploy` CLI subcommand. Compares each shipped
  deploy template (systemd unit + drop-in, logrotate, Caddyfile) against
  the file the installer placed on the host (`/etc/systemd/system/...`,
  `/etc/logrotate.d/...`, `/etc/caddy/Caddyfile`) and exits 0 if every
  entry matches byte-for-byte or 2 if any `DRIFT`, `MISSING`, or
  `ABSENT_TEMPLATE` row is reported. The Caddyfile's
  `# relay-shell:install-edge:managed` marker line is stripped before
  comparison so a Caddyfile placed by `install-edge.sh` reads as OK.
  `--json` switches to machine-readable output for log shippers /
  cron-driven drift detection; `--templates-dir` and `--install-prefix`
  let the same logic run inside image-bake CI. Templates are shipped
  inside the wheel via a `[tool.hatch.build.targets.wheel.force-include]`
  mapping (`deploy/` → `relay_shell/_deploy`), with an editable-install
  fallback that walks up from the package file. Closes B-020.
- `ssh_fanout` MCP tool. Runs a command in parallel across hosts (or
  the whole inventory) with bounded concurrency (default 8, clamped
  to `[1, 32]`) and returns one JSON object with per-host `exit_code`
  and truncated `output`. The host list is capped at 100 per call to
  bound the outbound SSH burst. Tier classification reads `command`
  via `policy_text` like a regular `ssh_exec`, so the deny list and
  `guarded`/`readonly` modes see the same probe text - `ssh_fanout rm
  -rf /` is still Tier 3 and still refused. Closes B-002.
- `ssh_keyscan` MCP tool (Tier 1, REVERSIBLE). Shells out to
  `ssh-keyscan` to fetch each host's public key in known_hosts line
  format - useful for pre-populating `~/.ssh/known_hosts` so a service
  account can run `strict` without a manual `accept-new` seeding pass.
  Inputs are validated at the boundary (hostnames against
  `[A-Za-z0-9._\-\[\]:]+`, port in 1..65535, key types from the OpenSSH
  set, host count capped at 32 per call to bound the outbound TCP
  burst); every interpolated token is also `shlex.quote`d and a `--`
  separator precedes the host list. Documented in `docs/tools.md` and
  the README capability table. Closes B-001.
- `audit_tail` MCP tool (Tier 0, read-only). Returns the last N records
  from the audit log as JSONL, oldest first. `lines` defaults to 50 and
  is clamped to `[1, 1000]`. Opens a fresh read-only fd so the writer's
  append-only handle is untouched. Lets an operator MCP client debug a
  session without shelling into the host. The audit log's "output body
  never written" invariant is preserved end-to-end (regression test in
  `tests/test_audit_tail_tool.py`). Closes B-003.
- CI now runs the full check matrix on Python **3.12, 3.13, and 3.14**
  instead of 3.12 alone. The package floor stays `>=3.12` (declared in
  `pyproject.toml`); the matrix surfaces interpreter-specific
  regressions early. `fail-fast: false` keeps every entry's result
  visible so a single 3.14 wheel gap does not mask a 3.13 regression.
  Classifiers in `pyproject.toml` updated to advertise the three
  supported versions on PyPI. Closes B-009.
- `relay-shell --check-config` CLI flag. Loads `RELAY_SHELL_*` settings,
  constructs the server (audit sink, policy, inventory, OAuth if
  enabled) without starting a transport, and exits 0 on success or 2
  on any initialization failure - including a degraded audit sink.
  Intended for CI pipelines that bake an image so a misconfiguration
  fails the build rather than crashes the running service at start.
  Documented in `README.md` (Quickstart) and `docs/deployment.md` §2.
  Four `subprocess.run`-based tests in `tests/test_main.py` exercise
  the new flag and close T-001 (the previously-untested
  print-and-return-2 path in `__main__.main()`). Closes B-013.
- `CODE_OF_CONDUCT.md` adopting the Contributor Covenant 2.1. The file
  is a thin pointer to the canonical upstream URL so wording changes
  track automatically; it documents scope, the enforcement-reporting
  channel (private GitHub security advisory, same as vulnerability
  reports), and the Community Impact Guidelines link. Cross-linked
  from `README.md` and `CONTRIBUTING.md`.
- `docs/adr/README.md` indexing every ADR (number, title, status, date,
  one-line subject) and documenting when a new ADR is required, the
  filename convention, and the next free number. Cross-linked from
  `docs/architecture.md` and `docs/runbook.md` §6.
- `.pre-commit-config.yaml` mirroring the CI quality loop: `ruff`,
  `ruff format`, `mypy --strict` (local hook against the project's
  venv), plus standard hygiene hooks. A new banned-imports rule under
  `[tool.ruff.lint.flake8-tidy-imports.banned-api]` refuses to let
  `requests` or `urllib3` enter the codebase synchronously - they would
  block the event loop. `pre-commit` is in the dev extras;
  `CONTRIBUTING.md` documents the one-shot install.
- `.github/workflows/sbom.yml` generates a CycloneDX SBOM (JSON + XML,
  CDX spec 1.5) of the resolved Python environment on every `v*` tag
  push and attaches both files to the GitHub release. Cheap supply-
  chain signal; no runtime change. A `workflow_dispatch` input lets the
  workflow attach an SBOM to an existing tag after the fact. Closes B-006.
- `docs/audit-shipper.md` with one worked example each for Vector,
  Fluent Bit, and `journalctl` → `systemd-journal-remote`. Cross-linked
  from `SECURITY.md` and `docs/deployment.md` §6 so the "ship the log
  off-host" instruction now points at concrete configs that preserve
  the append-only posture and rotation behavior. Closes B-011.
- Coverage measurement in CI with subprocess collection enabled (the
  stdio e2e contributes). Configuration lives in `pyproject.toml`; the
  CI workflow drops a small `coverage_subprocess.pth` during install.
  See `docs/runbook.md` §4.3 for the local recipe. Closes B-007.
- `CONTRIBUTING.md` covering scope, branch naming, the local-loop
  recipe, the documentation-moves-with-code requirement, and the
  security-sensitive-PR review path. The runbook remains the canonical
  procedure; `CONTRIBUTING.md` is the entry point that links into it.
  Closes B-015.
- GitHub PR template and bug / feature / security issue templates under
  `.github/`. The PR template encodes the runbook §3.1 cross-reference
  checklist and the §3.3 security-sensitive-diff confirmations so they
  travel with every PR. Closes B-016.
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

- `requirements.txt` pins refreshed to the actually-resolved set
  produced by `pip install -e ".[dev]"` against the pyproject.toml
  lower bounds (the previous file claimed `starlette==1.0.0` /
  `PyJWT==2.12.1` / `ruff==0.15.13` while pip resolved `1.1.0` /
  `2.13.0` / `0.15.14`; the file header now describes itself as
  validated against the development matrix rather than as a strict
  lockfile, and points at ADR 0005 for the validation date).
- `docs/runbook.md` §4.3 coverage figure refreshed from the stale
  "CI floor: 75%, current ~78%" to "CI floor: 85%, current ~89%"
  (matches `pyproject.toml`'s `fail_under = 85` and the measured
  subprocess-collected coverage). §3.4 "common review failures"
  obsolete `len(names) == 18` reference updated to `21` (matches
  `tests/test_server.py:36`).
- `docs/runbook.md` §8 status table updated: §8.1 (README), §8.2
  (SECURITY.md), §8.6 (architecture.md), §8.7 (tools.md), §8.8
  (deployment.md), §8.12 (ADR 0004) and a new §8.12a (ADR 0005)
  move their "still open" items into "done", with the validation-
  cadence note attached to §8.12a so each subsequent ADR-0005 pass
  appends a dated outcome paragraph instead of overwriting prior
  ones. §8.18 (ADR README) records the next-free-number bump to
  0006.
- `docs/adr/README.md` adds the ADR 0005 index row and bumps the
  next-free-number marker to **0006**.
- CI coverage floor raised to 85% (from the initial 75%). The new
  `tests/test_tool_wrappers.py` module calls every `@mcp.tool()` wrapper
  in `server.py` through `mcp.call_tool()` with arguments that produce
  either valid output or a structured error string - either way
  exercises the wrapper body, the audit path, the policy probe, and the
  truncate path for every tool. `server.py` coverage lifted from ~65%
  to ~95% and overall coverage to ~88%. Closes B-022 (partial; the
  remaining gap is concentrated in `sshpool.py` at ~68% and tracked as
  a follow-up in `docs/runbook.md` §7.2).
- Redaction and tier-classification regex tables moved into a dedicated
  `src/relay_shell/patterns.py` module. `redaction.py` and `policy.py`
  now consume the published `REDACTION_*` / `TIER*_PATTERN` /
  `PRIV_ESC_PATTERN` names; the executor bodies are unchanged.
  `PATTERNS_VERSION` is a monotonic counter that audit consumers can
  read to detect a pattern-set upgrade. `tests/test_patterns.py`
  anchors compile-time shape and provides paired over-scrub / under-
  scrub cases per family. No behavior change. Closes B-019.
- `.env.example` and `docs/deployment.md` document the new
  `RELAY_SHELL_EDGE_*` variables and the one-shot install flow.
- Bumped MCP SDK: `mcp` 1.26.0 → 1.27.1 (tracked by Dependabot, validated
  by the existing test suite). ADR 0001 and `docs/architecture.md`
  updated to match the actual pin.

### Fixed

- `Authorization:` redaction no longer leaks the bearer / Basic /
  Signature value. The pattern previously consumed only the first
  whitespace-delimited token after `:`/`=`, so
  `Authorization: Bearer <token>` collapsed to
  `Authorization: [REDACTED] <token>` and the value survived in the
  audit log. The widened pattern handles three input shapes uniformly:
  the bare HTTP header form (value runs to end-of-line), the quoted CLI
  flag form `-H "Authorization: ..."` (value stops at the surrounding
  closing quote), and the JSON dict literal form
  `{"Authorization": "..."}` (value stops at its own closing quote).
  The value class consumes past commas so AWS Signature v4 and Digest
  challenge-response schemes do not strand the trailing
  `Signature=<hex>` / `response="<hash>"` fields. `PATTERNS_VERSION`
  bumped to `"2"`. Regression tests in `tests/test_patterns.py` cover
  Bearer, Basic, SigV4, Proxy-Authorization, single-quoted CLI, JSON-
  dict, and multi-header inputs. Closes B-023.
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
