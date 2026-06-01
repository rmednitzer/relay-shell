# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Tamper-evident audit log (opt-in). `RELAY_SHELL_AUDIT_CHAIN=true`
  (requires `RELAY_SHELL_AUDIT_FORMAT=jsonl`) appends a per-record hash
  chain — `seq`, the previous record's `prev` hash, and a `chain` hash
  over the canonical record body — so an edit, insertion, reorder, or
  interior deletion of the on-disk log is detectable by recomputation,
  including from a shipped-off-host copy. Head-truncation is caught by the
  genesis anchor (`relay-shell --verify-audit --require-genesis` fails a log
  that should start at genesis but does not); tail-truncation and cross-file
  durability remain the off-host shipper's job, since a single file cannot
  prove its own newest record is the true end. The chain resumes across
  restarts and rotation while the process runs; a rotation immediately
  followed by a restart re-anchors at genesis (a visible seam, not a silent
  gap). Verify with `relay-shell --verify-audit [--audit-path PATH]
  [--require-genesis] [--json]` (exit 0 intact / 2 broken), mirroring
  `--check-config` / `--verify-deploy`; it is a CLI verb, not an MCP tool, so
  the 21-tool contract is unchanged. `server_info.audit` now also reports
  `format` and `chain`. Default off keeps the record byte-identical to prior
  releases. See [ADR 0007](docs/adr/0007-audit-hash-chain.md). Tests in
  `tests/test_audit.py` (chain emit/resume + `verify_chain` tamper /
  head-truncation / tail-truncation cases), `tests/test_config.py` (the
  `jsonl`-required validator), and `tests/test_main.py` (the CLI, incl.
  `--require-genesis`). Closes runbook §7.5 B-023.
- `RELAY_SHELL_SSH_IDLE_TIMEOUT` (default 1800s) drops a cached SSH
  connection that has not been used for that many seconds the next
  time `SshPool.connect()` is consulted. Mirrors the shape of
  `SessionRegistry._sweep`: opportunistic sweeping on every connect,
  no always-on background task. A value of `0` disables idle eviction
  (closed connections are still purged on the next sweep so a
  re-connect attempt does not return a dead handle). Long-running
  deployments that fan out across a large host inventory should leave
  the reaper on so the pool does not accumulate idle handles to hosts
  it will not contact again. `server_info.ssh` now reports
  `connect_timeout`, `keepalive`, and `idle_timeout` alongside the
  existing `known_hosts_default` / `inventory_hosts` / `ssh_config`
  fields. Closes runbook §5.1 C-001.
- Property-based tests for `truncate` (UTF-8 boundary safety, prefix
  invariant, marker presence) live in `tests/test_util.py` next to
  the hand-picked cases; ~300 examples per property keeps the default
  `pytest` run under a second. Closes runbook §5.3 T-005.
- Regression tests pinning the `[session ... ended]` and
  `[session ... ended, exit=N]` marker shape that closed sessions
  return via `session_recv`. Client renderers grep for these markers;
  the tests freeze both branches so a future refactor cannot silently
  change either string. Closes runbook §5.3 T-003.
- Fault-injection test for `close_forward()` when the underlying
  listener's `close()` / `wait_closed()` raise: the pool's
  `contextlib.suppress(Exception)` swallows the failure and the tool
  still returns the structured `closed forward {fid}` message and
  drops the handle from the registry. Closes runbook §5.3 T-004.
- Drift-prevention tests asserting the registered tool set equals the
  set documented in `docs/tools.md`, the README capability tables,
  and the `_INSTRUCTIONS` string at the bottom of `server.py`. A
  missed update on any of the four fails a PR rather than ships
  silently. Closes runbook §5.1 C-002 / C-004.
- `.github/CODEOWNERS` routes review on trust-boundary paths
  (`audit.py`, `redaction.py`, `policy.py`, `patterns.py`, `server.py`,
  `verifier.py`, `metrics.py`, `auth/`), deployment artifacts
  (`deploy/install*.sh`, `Caddyfile`, `systemd/`), and CI/governance
  manifests to `@rmednitzer`. Advisory until paired with branch
  protection requiring CODEOWNERS review (follow-up).
- MCP resource reads (`relay-shell://inventory*`, `ssh-config`) now
  tick the `relay_shell_tool_calls_total` Prometheus counter with
  `tool=resource:<name>`, `tier=0`, `mode=<policy-mode>`,
  `outcome=ok`. Resource cardinality is bounded by the three
  registered URIs, so the counter stays low-cardinality; a flood of
  resource reads is now visible on `/metrics` instead of being
  audit-only. (Phase-2 F-13)

### Changed

- Documentation-consistency pass (runbook §8): added a "change a
  redaction/tier pattern" row to the `CONTRIBUTING.md` documentation-
  moves-with-code table (bump `PATTERNS_VERSION`, paired tests in
  `tests/test_patterns.py`); refreshed the ADR-index subject for ADR
  0005 in `docs/adr/README.md` to name both the 2026-05-24 and
  2026-05-31 validation passes; generalized the runbook §8.12a
  maintenance note so it stays self-maintaining across future passes;
  and aligned `CLAUDE.md`'s trusted-reference list with `AGENTS.md` by
  adding the OWASP Secrets Management Cheat Sheet (the canonical source
  behind the redaction control). Also fixed a pre-existing duplicate
  `### 6.4` heading in the runbook (the release recipe was renumbered to
  §6.6) so the §6.4 cross-references resolve unambiguously. No code or
  behavior change.
- Documentation-consistency follow-up (runbook §8): corrected a stale
  `fail_under=85` inline comment in the §4.3 coverage recipe to `90`
  (the floor moved to 90 in B-022 and the §4.3 header already read 90;
  only the recipe comment lagged), and added a runbook §8.20 inventory
  entry for the `audit/<date>-engagement.md` assurance packs.
  `audit/2026-05-27-engagement.md` had landed in #60 without the
  "a new `.md` file gets a §8 entry" cross-reference that
  `CONTRIBUTING.md` requires; §8.20 now records the frozen-record
  convention and how the packs relate to ADR 0005 validation passes.
  No code or behavior change.
- `Relay.connect_kwargs` accepts an optional `connect_timeout` keyword;
  the `ssh_check` and `ssh_fanout` wrappers no longer hand-roll the
  dict literal to inject the probe-level timeout. Zero / negative
  overlays are dropped so `SshPool.connect` falls back to
  `settings.ssh_connect_timeout` (the historical default). Closes
  runbook §5.1 C-003.
- `_INSTRUCTIONS` (the FastMCP server hint string) spells out
  `ssh_forward_list` / `ssh_forward_close` instead of the
  `ssh_forward(/list/close)` shorthand, so the C-004 drift-prevention
  test can see every registered tool by name. The protocol-level
  overview is otherwise unchanged.
- `Inventory` constructor parameter renamed from `ssh_config_path` to
  `ssh_config` so the field name matches `Settings.ssh_config` it is
  fed from. The `ssh_config_file` property (resolved-iff-exists) is
  unchanged in semantics and gained a docstring distinguishing the
  two views. Closes runbook §5.1 C-005.
- `build_server(settings)` attaches the constructed `Relay` to the
  returned `FastMCP` as `mcp.relay`. `__main__._check_config` now
  reads the audit-degraded flag from there instead of constructing a
  second `Relay` (which previously double-opened the audit file and
  double-loaded the inventory); the graceful-shutdown path in `main()`
  reads from the same attribute.

### Fixed

- `SshPool.connect` is now single-flight on the cache key: two
  concurrent callers for the same `user@host:port` await one
  underlying `asyncssh.connect` instead of dialling twice and
  silently leaking the losing connection. The in-flight future is
  cleared on success and on failure (including cancellation) so a
  retry after a transient error re-dials cleanly. Regression tests in
  `tests/test_sshpool_unit.py`.
- `SshPool.run` terminates the remote process on `TimeoutError` and
  bounds `proc.wait_closed()` with its own 5-second deadline (2s on
  the post-terminate cleanup). Previously a timeout left the remote
  `create_process` parked on the SSH connection until the connection
  itself died, and `wait_closed()` was unbounded.
- `FileOAuthProvider` now serializes every read-modify-write against
  `clients.json` / `codes.json` / `tokens.json` with an
  `asyncio.Lock`. Concurrent HTTP-transport register-client, token
  issuance, refresh rotation, and revoke no longer lost-update each
  other. The atomic `tmp+replace` in `_Store.save` already covered
  disk consistency for one writer; the lock closes cross-coroutine
  consistency. Regression test in `tests/test_oauth.py`.
- `__main__.main()` runs `relay.sessions.shutdown()` and
  `relay.ssh.close_all()` in a `finally` block after the transport
  exits. Long-running PTY sessions and SSH forwards are now reaped on
  `SIGTERM`/`KeyboardInterrupt` instead of relying on GC / process
  exit.
- `AuditLogger.__init__` closes the prior `WatchedFileHandler` before
  removing it from the process-global `relay_shell.audit` logger.
  Each re-init (`--check-config`, multi-AuditLogger tests) used to
  leak one open fd until the next GC pass. Regression test in
  `tests/test_audit.py`.
- `sessions.py` module docstring corrected: the lost-wakeup invariant
  is enforced by the single-threaded asyncio event loop, not by
  ``_sink`` acquiring the buffer lock (it never did). Documents the
  actual property and the condition under which it would no longer
  hold (reader moved off the event loop). (Phase-2 F-10)
- `verifier.verify_pair` now reads templates and installed files with
  explicit `encoding="utf-8"` and returns a structured `Finding`
  (status `MISSING`, detail `could not read: <err>`) if `read_text`
  raises after `is_file()` returned True. Closes a TOCTOU
  permission-denied window where `verify_deploy`'s "never raises"
  contract would have been violated. Regression test in
  `tests/test_verifier.py`. (Phase-2 F-14, F-R1)

### Security

- Closed the audit log's in-record integrity gap. `chattr +a` and
  off-host shipping protect the file, but neither makes a *single altered
  record* detectable, and the shipper has a flush window the ADR 0002
  residual-risk attacker (service-account / root compromise) can exploit
  by clearing the append-only attribute, editing, and restoring it. The
  opt-in per-record hash chain above
  ([ADR 0007](docs/adr/0007-audit-hash-chain.md)) adds in-record
  tamper-evidence that does not depend on the filesystem attribute that
  attacker can clear; recomputation localizes the alteration even from the
  shipped copy. Surfaced as gap G-1 in the ADR 0005 2026-06-01 validation
  outcome.
- Argument redaction now collapses the common structurally-anchored
  provider secret shapes when they arrive *bare* in an audited argument
  (a JSON body, a log line, or a flag the CLI-flag prefix list does not
  name), closing the gap where only `--password`/`Bearer`-prefixed or
  GitHub/OpenAI/AWS/Slack tokens were scrubbed: Google API key (`AIza`),
  Google OAuth token (`ya29.`), Stripe `sk_`/`rk_` keys, GitLab
  `glpat-`, npm `npm_`, PyPI `pypi-`, and JWTs (`ey<hdr>.ey<payload>`).
  The OpenAI `sk-` shape was widened to also cover the
  `sk-proj-`/`sk-svcacct-`/`sk-admin-` prefixes whose internal hyphen
  previously broke the match. Anchors and length floors track the
  canonical secret-scanning rulesets (gitleaks / GitHub secret
  scanning); each shape is structure-anchored (prefix + length floor),
  never anchored on the value's character class. `PATTERNS_VERSION`
  bumped `"3"` → `"4"`. Paired over-scrub / under-scrub tests in
  `tests/test_patterns.py` and a bare-in-args scenario in
  `tests/test_redaction.py`; `redact` idempotency and the no-leak
  invariant verified on every new shape. Surfaced as finding F-004 in
  the ADR 0005 2026-05-31 validation outcome.
- `shell_script` and `shell_spawn` tool wrappers now include `env_json`
  in `policy_text` (mirroring `shell_exec`) and in `audit_args`. An
  operator `RELAY_SHELL_POLICY_DENY` pattern matching only env content
  (e.g. `LD_PRELOAD`) now denies the call; the audit record carries
  `env_json` through `redact_args`. Paired regression tests in
  `tests/test_tool_wrappers.py`.
- Documented (`SECURITY.md` §Scope) that MCP resource reads
  (`relay-shell://inventory*`, `relay-shell://ssh-config`) are
  audit-logged but not subject to `RELAY_SHELL_POLICY_MODE` /
  `RELAY_SHELL_POLICY_DENY`. The exposed data matches a Tier-0 tool's;
  admission-control the transport CIDR allowlist or refuse the resource
  list entirely if needed.
- Documented (`SECURITY.md` §Deployment requirements) that operator-
  supplied `RELAY_SHELL_POLICY_DENY` / `_ALLOW` patterns are compiled
  with stdlib `re` without timeout and run on the event loop; a
  catastrophic-backtracking pattern is a self-inflicted DoS. Operators
  should prefer simple anchored literals.
- All GitHub Actions across `ci.yml`, `codeql.yml`,
  `dependency-review.yml`, `nightly-fuzz.yml`, `release.yml`, and
  `sbom.yml` are now pinned by 40-character commit SHA with a trailing
  `# vN` comment indicating the semver tag at pin time. Removes the
  tag-rewrite class of supply-chain attack and aligns with the
  OpenSSF Scorecard `Pinned-Dependencies` check and the GitHub Actions
  security-hardening guide. `pypa/gh-action-pypi-publish` migrated
  from the `@release/v1` branch reference (which follows a moving
  branch) to the SHA of `v1.13.0`. Dependabot keeps updating SHA +
  comment together as new tags ship.
- `release.yml` build job now produces a Sigstore-signed in-toto
  build-provenance attestation via `actions/attest-build-provenance`
  (SHA-pinned). Closes the SLSA v1.2 Build Track L3 gap identified in
  the Phase-3 cross-check: PyPI OIDC trusted publishing already gave
  L2, and this step adds a verifier-checkable provenance record in
  Sigstore's public transparency log linking the workflow run +
  release commit to every artifact under `dist/`. Job-level
  `permissions: id-token: write, attestations: write, contents: read`
  was added with an explicit `contents: read` to avoid widening the
  inherited workflow scope.

## [0.1.0] - 2026-05-25

### Added

- ADR 0006 (Proposed) recording the design contract for a syscall-level
  audit channel via seccomp-bpf notification mode (`SECCOMP_RET_USER_NOTIF`
  with `SECCOMP_USER_NOTIF_FLAG_CONTINUE`). Notify-only, never blocking;
  opt-in via `RELAY_SHELL_SECCOMP_NOTIFY` (default `off`); Linux >= 5.5;
  narrow syscall set (`execve`, `openat` for write, `mount`, `setuid`,
  `unshare`, `prctl`, `ptrace`, ...); additive audit-record shape
  (`tool="syscall_notify"`, new overflow event) so existing log shippers
  keep working. Closes the audit gap on the child side of
  `asyncio.create_subprocess_*` without re-introducing a sandbox —
  ADR 0002's trust boundary stays verbatim. The runbook backlog entry
  B-021 now points at the ADR; promotion to Accepted is gated on the
  implementing PR and its ADR 0005 §"Decision" step 5 validation
  outcome. ADR README next-free marker bumped to **0007**;
  runbook §8.18 status updated.
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
  this PR. The next-free-ADR marker landed at **0006** in this entry
  and was bumped to **0007** by the ADR 0006 entry above.
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
  `docs/runbook.md` §6.6. Closes B-005.
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

### Changed

- Raised the CI coverage floor from 85% to 90% (`fail_under` in
  `pyproject.toml`). Closes backlog B-022. New fault-injection tests
  in `tests/test_ssh_integration.py` exercise port-forwarding
  (`L:` / `R:` / `D:` / invalid spec, plus `close_forward`),
  `accept-new` known-hosts persistence (single-write + idempotency
  on reconnect), `SshProcessTransport.resize` / `.signal` on a live
  remote process, `run()` timeout, `_known_hosts_arg` resolution
  in `strict` / `ignore` / `accept-new` modes, and the
  `keepalive` / `client_keys` / `ssh_config` connect-option
  branches. `sshpool.py` coverage lifted from ~69% to ~96%,
  overall from ~89% to ~92%. Runbook §4.3 and §7.2 status updated.
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
