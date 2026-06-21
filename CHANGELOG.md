# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `docs/auth.md` — an authentication-lifecycle guide for the OAuth 2.1 layer:
  how a client registers (DCR), authorizes with PKCE, obtains tokens, and
  **stays authenticated via refresh-token rotation** (1 h access / rolling
  30 d refresh), plus lazy expiry, restart persistence, the re-auth ceiling,
  revocation, and single-client lockdown. States prominently that auth is
  **opt-in and off by default** (`RELAY_SHELL_AUTH_ENABLED=false`, HTTP
  transport only) — a fresh install never stands up an (un)authenticated
  listener implicitly. Cross-linked from the README OAuth bullet,
  `SECURITY.md`, and `deployment.md` §5; inventory entry added at runbook
  §8.22. Docs only.
- CI secret scanning via `.github/workflows/gitleaks.yml` (audit pass finding
  TOOL-3). Runs on push to `main`, PRs, and a daily schedule. Self-contained
  and supply-chain careful: a pinned gitleaks (8.30.1) is installed by
  discovering the exact release asset from the release's own checksums file
  and verifying the tarball before extracting — no hardcoded checksum, no
  third-party action or license endpoint; `permissions: contents: read`;
  `gitleaks detect -c .gitleaks.toml` fails the job on any finding. Making it
  a required check is a repo-owner branch-protection decision.
- `.gitleaks.toml` allowlist for the repository's synthetic secret fixtures
  (audit pass finding TOOL-1). This project is a redaction tool and ships fake
  secret-shaped values in `tests/`, the runbook redaction sample, and the
  audit evidence; the config (extending the default ruleset) allowlists only
  those documented locations so the `gitleaks` job above (and any local
  `gitleaks detect -c .gitleaks.toml`) is not drowned in known fixtures.
  `src/` is not allowlisted, so a real secret committed there still trips.
- Seccomp-notify follow-ups (`SECCOMP_FILTER_VERSION` 2; closes runbook
  §7.5 B-024 and B-026, recorded in
  [ADR 0006](docs/adr/0006-seccomp-notify-audit-channel.md) §"Follow-ups
  landed 2026-06-09"):
  - `prctl` joined the notified set, gated on privilege-relevant `option`
    values (`PR_SET_DUMPABLE`, `PR_SET_KEEPCAPS`, `PR_SET_SECCOMP`,
    `PR_CAPBSET_DROP`, `PR_SET_SECUREBITS`, `PR_SET_NO_NEW_PRIVS`,
    `PR_CAP_AMBIENT`) via a new eq-any BPF argument predicate, so
    high-volume benign options (`PR_SET_NAME`, glibc's `PR_SET_VMA`) never
    trap. Paired positive / near-miss tests run portably through a small
    classic-BPF interpreter in `tests/test_seccomp.py` (near-misses include
    the numerically-adjacent `GET` twins), plus a `seccomp`-marked live
    test; option values validated against a live host's `<linux/prctl.h>`.
  - The channel now covers local PTY sessions: `shell_spawn` children get
    the same filter, the session transport adopts the monitor for the
    session's lifetime (released in `aclose()`, on the failure path too),
    events keep the spawning call's `request_id`, and
    `RELAY_SHELL_SECCOMP_NOTIFY_CAP` bounds events per session. The
    "SSH-local half" deferred from B-021 was resolved as vacuous:
    `asyncssh` runs in-process and `sshpool` spawns no local child, so
    there is nothing local to observe on that path. The off path stays
    byte-identical; the audit-record shape is unchanged.
- Syscall-level audit channel (opt-in), implementing
  [ADR 0006](docs/adr/0006-seccomp-notify-audit-channel.md) (now Accepted).
  `RELAY_SHELL_SECCOMP_NOTIFY=true` installs a seccomp-bpf **user-notify**
  filter (`SECCOMP_RET_USER_NOTIF` + `SECCOMP_USER_NOTIF_FLAG_CONTINUE`) on
  locally-spawned children (`shell_exec` / `shell_script` / `ssh_keyscan`)
  and appends one additive `syscall_notify` audit line per observed syscall:
  `execve`, `execveat`, `ptrace`, `mount`, `umount2`, `unshare`, `setns`,
  `chroot`, `pivot_root`, the `set[re|res]?[ug]id` family, and `open`/`openat`
  gated on a write/create flag. It **never blocks** a syscall — the supervisor
  always answers CONTINUE — so ADR 0002's no-sandbox posture is preserved.
  The channel activates **only** when the process holds `CAP_SYS_ADMIN` and so
  installs the filter *without* latching `no_new_privs`: set-uid/`sudo`
  behaviour in audited children is unchanged. Linux / `x86_64` / kernel ≥ 5.5;
  anywhere else it cleanly no-ops and `server_info.seccomp` reports
  `supported=false` with a `reason`. `RELAY_SHELL_SECCOMP_NOTIFY_CAP`
  (default 256) bounds the per-call event volume — beyond it, one
  `syscall_notify_overflow` line is written and emission stops while the
  child still runs to completion. The events ride the same JSONL stream
  (and the ADR 0007 hash chain) as tool-call records, carry only raw scalar
  register arguments (no buffer dereference), and the per-call record stays
  byte-identical, so existing log shippers keep working. Two bounded
  `/metrics` counters added: `relay_shell_seccomp_notify_events_total{syscall}`
  and `relay_shell_seccomp_notify_overflow_total`. Implemented in pure
  `ctypes` — **no new runtime dependency**; default off keeps the spawn path
  byte-identical. The 21-tool contract is unchanged (this is an audit event,
  not a tool). Tests in `tests/test_seccomp.py` (portable BPF/parse/dispatch
  unit tests + `seccomp`-marked end-to-end tests that auto-skip without
  `CAP_SYS_ADMIN`), plus `tests/test_audit.py`, `tests/test_config.py`, and
  `tests/test_metrics.py`. Closes runbook §7.5 B-021. `prctl` option-filtering,
  `aarch64`, and PTY/SSH-local coverage are recorded follow-ups (runbook §7.5).
- `ssh_upload` / `ssh_download` gain an explicit `timeout=` parameter (clamped
  to the server max), mirroring `ssh_exec`. A hung SFTP transfer was previously
  bounded only by the connection-level keepalive; the per-call cap is threaded
  through `SshPool.sftp_put` / `sftp_get` via `asyncio.wait_for` and a
  timed-out transfer returns a `[TIMEOUT after Ns]` string. `0` (the default)
  disables the per-call cap, so existing callers are unaffected. The clamped
  value is recorded in `audit_args`. Wiring tests in
  `tests/test_sshpool_unit.py` assert the cap fires (put + get) and that
  `timeout=0` completes. Closes runbook §7.1 F-6.
- Tamper-evident audit log (opt-in). `RELAY_SHELL_AUDIT_CHAIN=true`
  (requires `RELAY_SHELL_AUDIT_FORMAT=jsonl`) appends a per-record hash
  chain — `seq`, the previous record's `prev` hash, and a `chain` hash
  over the canonical record body — so an edit, insertion, reorder, or
  interior deletion of the on-disk log is detectable by recomputation,
  including from a shipped-off-host copy. `--verify-audit` is fail-closed: a
  missing / empty log or a head-truncated chain (non-genesis start) exits 2
  by default (`--segment` accepts a rotation segment); tail-truncation and
  cross-file durability remain the off-host shipper's job, since a single
  file cannot prove its own newest record is the true end. The chain resumes across
  restarts and rotation while the process runs; a rotation immediately
  followed by a restart re-anchors at genesis (a visible seam, not a silent
  gap). Verify with `relay-shell --verify-audit [--audit-path PATH]
  [--segment] [--json]` (fail-closed: exit 0 only for a clean genesis chain;
  exit 2 for missing / empty / broken / head-truncated), mirroring
  `--check-config` / `--verify-deploy`; it is a CLI verb, not an MCP tool, so
  the 21-tool contract is unchanged. `server_info.audit` now also reports
  `format` and `chain`. Default off keeps the record byte-identical to prior
  releases. See [ADR 0007](docs/adr/0007-audit-hash-chain.md). Tests in
  `tests/test_audit.py` (chain emit/resume + `verify_chain` tamper /
  head-truncation / tail-truncation cases), `tests/test_config.py` (the
  `jsonl`-required validator), and `tests/test_main.py` (the fail-closed CLI, incl.
  `--segment` / missing / unchained). Closes runbook §7.5 B-023.
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

- Documentation consistency sweep (all living `.md` + comments) after the
  2026-06-21 backlog run; docs only, no code/behavior change:
  - **B-005 reconciliation**: runbook §4.7 said "PyPI publish automation
    (B-005) is still open", contradicting §6.6 and the `[0.1.0]` "Closes B-005"
    entry — the `release.yml` OIDC trusted-publishing pipeline has existed since
    0.1.0. §4.7 now points to §6.6; the only remaining operator action is the
    one-time PyPI trusted-publisher claim (documented in §6.6).
  - `docs/deployment.md`: the §4 edge security-header list now includes
    `Content-Security-Policy` (EDGE-2); the §4a installer note records the
    `/etc/relay-shell` `0750` hardening (DEP-2) and the
    `RELAY_SHELL_EDGE_CADDY_GPG_FPR` key-pin (DEP-1).
  - `.github/PULL_REQUEST_TEMPLATE.md` + `CONTRIBUTING.md`: the
    security-sensitive-diff trigger list now matches runbook §3.3 (adds
    `patterns.py`, `metrics.py`, `seccomp.py`), and the PR-template CI checklist
    matches §3.1 (adds `pip-audit`, `gitleaks`).
  - runbook §2.6 limits snippet adds `RELAY_SHELL_MAX_FORWARDS` (the SSH-3
    cap, reported by `server_info`). Verified the rest is current: tool count
    21, `PATTERNS_VERSION` 7, `mcp==1.27.2`, ADR next-free 0009, the new
    redaction shapes and `docs/auth.md` cross-links. Frozen records
    (`audit/*.md`, ADR bodies, released CHANGELOG entries) left as authored.
- Validation pass (2026-06-21) recorded in
  [ADR 0005](docs/adr/0005-codebase-validation.md): re-ran the steps 1-4
  upstream-surface + behavior checks on the pinned `mcp==1.27.2` /
  `asyncssh==2.23.1` — `ruff` / `ruff format` / `mypy --strict` clean,
  `pytest` 342 passed (+13 fuzz), `coverage` 93% (floor 90%), 21 tools /
  3 resources / 1 prompt, audit-record schema and output-hash-only invariant
  intact. One documentation-drift finding (DOC-1): `docs/runbook.md` §8.18
  named the ADR next-free-number marker as "0008" while `docs/adr/README.md`
  has read "0009" since ADR 0008 landed; corrected §8.18 to match. Docs only.
- Backlog reconciliation: the canonical backlog (`docs/runbook.md` §7) now
  records the 2026-06-12 audit-pass closures where they belong — §7.2 gains
  the QUAL-1/REL-1 notes, §7.5 gains SEC-1, TOOL-1+TOOL-3 (which also closes
  the 2026-06-01 pack's deferred P1-2 gitleaks CI gate), SEC-2, and the
  F-G2-verified status note; §8 gains a per-file entry (§8.21) for
  `BACKLOG.md`. In `BACKLOG.md`, TOOL-2 (ruff pin skew) is closed as
  accepted-as-designed with evidence that Renovate manages both pinned
  locations (`renovate.json5` pre-commit manager + pip_requirements group;
  PRs #83/#84/#85), leaving no open in-repo deferral. Docs only.
- Tests: the four HTTP `/metrics` tests no longer use `starlette.testclient`
  (audit pass finding REL-1). That client warned `StarletteDeprecationWarning:
  ... install httpx2`; the tests now drive the in-process app through httpx's
  own `ASGITransport` (the already-pinned httpx, no httpx2 needed), which
  returns the identical response with no warning. The suite goes from one
  warning to zero, and `pytest -W error::DeprecationWarning` passes on that
  module. Test-only; no runtime or dependency change.
- Documentation: reconciled the `mcp` pin drift (the SDK moved
  1.27.1 → 1.27.2 in PR #66 but the living docs still named 1.27.1). The
  README status line + compatibility matrix and `docs/architecture.md` now
  read `mcp==1.27.2` (and `asyncssh` tested at 2.23.1); ADR 0001 gained a
  pin-movement Consequences line and ADR 0005 a 2026-06-12 validation
  outcome, closing the runbook §8.9 follow-through. Recorded as a full
  audit / validation pass under `audit/` (inventory, baseline, findings
  register, final report). No code, policy, redaction, or audit-record
  behavior changed.


- `server.py` admission-probe consolidation (closes runbook §5.2 R-002 and
  R-003, no behavior change): every tool with a non-empty policy surface
  now builds its `policy_text` through exactly one module-level
  `_policy_text_<tool>` function, so the "everything the executor sees,
  the policy sees" contract is greppable per tool and pinned by
  `tests/test_tool_wrappers.py`; `shell_spawn` / `ssh_spawn` register
  their transports through one shared `Relay.register_session` path
  (which also closes the spawn-leak fixed below).
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

- A `shell_spawn` / `ssh_spawn` whose registry admission failed (most
  commonly the `RELAY_SHELL_MAX_SESSIONS` limit) leaked the already-spawned
  child: the tool returned its bounded error string while the local PTY
  process or remote SSH process kept running unsupervised, invisible to
  `session_list` and exempt from idle reaping. The shared
  `Relay.register_session` path now closes the transport (reaping the
  child and releasing any adopted seccomp monitor) before the error
  propagates. Regression test in `tests/test_sessions.py`.
- A failed local PTY spawn (e.g. a nonexistent binary) leaked the PTY
  master file descriptor: `LocalPtyTransport.spawn` closed only the slave
  end when `create_subprocess_exec` raised. Both ends are now released on
  the failure path; pinned by an fd-count regression test.
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

- IP-encoding deny bypass closed on the transfer/forward tools too (SSRF-2,
  2026-06-21 backlog) — the follow-up to SSRF-1. A shared
  `_with_canonical_ips` helper (SSRF-1's `ssh_keyscan` path now delegates to it)
  is applied to the `ssh_upload`/`ssh_download` destination `host` and the
  `ssh_forward` `L:/R:` destination host, so an IP-based `RELAY_SHELL_POLICY_DENY`
  catches a decimal/hex/octal/IPv4-mapped destination on those tools, not only
  on `ssh_keyscan`. Still no DNS in the policy path (hostname/rebinding targets
  need an egress firewall). Additive to the probe; tests in
  `tests/test_tool_wrappers.py`.
- SBOM build-provenance attestation (CI-3, 2026-06-21 backlog). The `sbom`
  workflow now emits a Sigstore-signed in-toto build-provenance attestation for
  each generated SBOM (`.cdx.json` / `.cdx.xml`) via SHA-pinned
  `actions/attest-build-provenance` (`id-token: write` + `attestations: write`),
  mirroring `release.yml`'s wheel attestation. A consumer can verify an SBOM is
  the genuine output of this repo's CI — `gh attestation verify <file> --repo
  rmednitzer/relay-shell` — rather than a swapped artifact. actionlint clean; no
  change to the SBOM contents.
- Deploy / edge hardening follow-ups (2026-06-21 backlog):
  - **DEP-1**: `install-edge.sh` no longer trusts the Caddy apt repo signing
    key trust-on-first-use. It dearmors the fetched key to a temp file, logs
    the fingerprint, and — if `RELAY_SHELL_EDGE_CADDY_GPG_FPR` is set — fails
    closed unless it matches before apt trusts the key. No default fingerprint
    is shipped (Caddy/cloudsmith publish no canonical one to verify against), so
    the operator pins the value confirmed at caddyserver.com/docs/install;
    unset keeps the prior behavior but warns. (`deployment.md` env-var table
    updated.)
  - **DEP-2**: both installers create `/etc/relay-shell` as `0750
    root:relay-shell` instead of a world-listable `0755`; the edge installer
    falls back to `0750 root:root` on an edge-only host. systemd reads the
    EnvironmentFiles as root, so the service is unaffected.
  - **EDGE-1**: documented (in the Caddyfile) why `/authorize` and
    `/.well-known/*` are reachable before the CIDR `@blocked` rule — the browser
    OAuth redirect + RFC 8414 discovery need it, `/authorize` still requires a
    client + PKCE, and tool traffic / `/token` stay CIDR-gated — plus how to
    CIDR-gate them for a machine-only deployment.
  - **EDGE-2**: the edge Caddyfile now sets
    `Content-Security-Policy "default-src 'self'; frame-ancestors 'none';
    base-uri 'none'"` on its only HTML surface (the `/authorize` page); inert
    for JSON tool/token responses.

  Shell changes are shellcheck-clean; drift guards added in
  `tests/test_verifier.py` (CSP present, `/etc/relay-shell` not `0755`, the
  fingerprint-pin mechanism present).
- Config + audit hardening follow-ups (2026-06-21 backlog; no behavior change
  for valid configs):
  - **CFG-1**: every resource limit now carries an explicit `le=` upper cap —
    `max_output` (16 MiB), `max_output_hard` (128 MiB), `default_timeout` /
    `max_timeout` / `session_idle_timeout` (24 h), `session_buffer_bytes`
    (16 MiB). An absurd env value (e.g. a 1 TB output cap) is now rejected at
    load instead of producing a clamp that never bites — a self-inflicted
    memory/DoS footgun. The caps are far above any real config.
  - **OBS-1**: `AuditLogger` flags `degraded=True` (with a reason) when the
    audit sink is not a regular file (`RELAY_SHELL_AUDIT_PATH=/dev/null`, a
    device, a FIFO). Such a sink opens and accepts writes but stores nothing
    durable; the `relay_shell_audit_degraded` gauge and `server_info.audit` now
    surface "audit goes nowhere" instead of reporting a healthy trail. The sink
    still points where the operator configured it.
  - **FMT-2**: the CEF formatter's header fields now pass through a dedicated
    `_cef_header_escape` (escapes `\` and the `|` separator, not `=`). The
    fields are constants, so the output is byte-identical (pinned by
    `test_audit_cef_format`); the escape is structural insurance against a
    future dynamic header field splitting a record.

  Tests: `test_limit_upper_bounds_reject_absurd_values` (`tests/test_config.py`),
  `test_audit_degrades_on_non_regular_sink` +
  `test_cef_header_escape_neutralizes_pipe_and_backslash` (`tests/test_audit.py`).
- Redaction coverage + robustness follow-ups to the 2026-06-21 adversarial pass
  (`BACKLOG.md`; `PATTERNS_VERSION` 6→7; additive — audit-record shape
  unchanged):
  - **RED-3**: new secret shapes the prior set missed. Structure-preserving
    prefixes for AWS `*_SECRET_ACCESS_KEY=` (the `secret` keyword is mid-name so
    the generic `secret=` rule never fired — anchored on the full
    `secret_access_key` phrase for false-positive control), Azure
    connection-string `AccountKey=` / `SharedAccessKey=`, and Azure SAS
    `?…&sig=` (anchored on a `?`/`&` boundary + 20-char floor so `design=` /
    short `sig=` are left alone); plus a whole-match for Slack incoming-webhook
    URLs (`https://hooks.slack.com/services/…`, distinct from the `xox*` token
    rule). GCP service-account creds needed no new rule — their only secret is
    the `private_key` PEM block, already collapsed by the PEM rule (it matches a
    JSON-embedded block with escaped `\n` too).
  - **RED-4**: a `bytes` audit argument used to fall through `_scrub`
    unredacted; it is now decoded (utf-8, `errors="replace"`, never raises) and
    scrubbed like a string, so a future caller cannot smuggle a secret past
    redaction as raw bytes.
  - **RED-5**: `_scrub` now redacts dict **keys** as well as values — a nested,
    caller-supplied dict (e.g. a parsed JSON body) could carry a secret in a
    key, not only a value.

  `redaction.py` docstring and `SECURITY.md` updated to list the new shapes.
  Paired over/under-scrub tests in `tests/test_redaction.py` (each new shape
  has a negative that must NOT redact); the `redact` idempotency / no-leak fuzz
  invariants still pass.
- OAuth single-client lockdown can no longer be bypassed by re-registering the
  existing client (AUTH-2, adversarial pass). The lockdown guard previously
  refused only a *new* `client_id` (`cid not in clients`), so an attacker who
  learned the existing `client_id` and reached the (CIDR-allowed) registration
  endpoint could re-register it and overwrite its `redirect_uri`, steering the
  next authorization code to an attacker URL. `register_client` now refuses any
  registration that would create *or modify* a client while locked down
  (`clients.get(cid) != incoming`); a byte-identical re-registration stays a
  harmless no-op, so a client that re-runs DCR with the same metadata is not
  broken. With lockdown off, client updates still work. Tests in
  `tests/test_oauth.py` (`..._refuses_redirect_uri_overwrite`,
  `..._allows_identical_reregistration`, `test_non_lockdown_still_allows_client_update`).
- `ssh_keyscan` deny gate no longer dodged by IP-encoding (SSRF-1, adversarial
  pass). `RELAY_SHELL_POLICY_DENY` matches probe *text*, so a caller could spell
  a denied address another way the OS resolver still accepts — decimal
  (`2130706433`), hex (`0x7f000001`), octal (`0177.0.0.1`), dotted-short
  (`127.1`), or IPv4-mapped IPv6 (`::ffff:127.0.0.1`). The keyscan policy probe
  now appends the canonical dotted/colon form of any **literal** IP in the
  target list (`_canonical_ips` / `_augment_probe_with_ips`, via `inet_aton` +
  `ipaddress`), so an IP-based deny catches every spelling of the same address.
  No DNS is resolved in the policy path (it would block the event loop and a
  rebinding answer can differ from the dialled one), so hostname/DNS targets
  still need an egress firewall — documented in `docs/deployment.md`. The change
  is purely additive to the probe (a canonical form is appended only when it
  differs from what the caller wrote); plain literals and hostnames are
  untouched. Tests in `tests/test_ssh_keyscan_tool.py`. The same normalization
  for the other host-bearing probes (`ssh_upload`/`ssh_download`/`ssh_forward`)
  is tracked as SSRF-2 in `BACKLOG.md`.
- SSH-surface hardening — bounds + auditability follow-ups to the 2026-06-21
  adversarial pass (`BACKLOG.md`; no posture change, capability preserved):
  - **SSH-1**: the five SSH tools (`ssh_exec` / `ssh_spawn` / `ssh_upload` /
    `ssh_download` / `ssh_forward`) now record the effective per-call host-key
    verification mode in their audit args (`known_hosts` =
    the call's value, else the server default), so a per-call `known_hosts=
    "ignore"` MITM downgrade is visible in the audit trail instead of silent.
  - **SSH-2**: `ssh_check` gained a per-call host cap (100, bounded error like
    `ssh_fanout`) and runs its probes with bounded concurrency (8) instead of
    strictly sequentially, so a large/inventory-wide list cannot turn one call
    into a long-blocking sweep. Output order is unchanged.
  - **SSH-3**: active SSH port forwards are now capped by
    `RELAY_SHELL_MAX_FORWARDS` (default 64, mirroring `RELAY_SHELL_MAX_SESSIONS`).
    `SshPool.add_forward` pre-checks before dialling and re-checks under the lock
    — closing the just-opened listener on a lost race — so the cap is never
    exceeded and a refused forward leaks nothing. A new `ForwardError` returns a
    bounded message; `server_info.config` reports `max_forwards`.

  Tests: `test_ssh_tools_record_known_hosts_in_audit`,
  `test_ssh_check_caps_host_count` (`tests/test_tool_wrappers.py`), and
  `test_add_forward_enforces_cap` (`tests/test_sshpool_unit.py`). Audit-record
  shape is otherwise unchanged (the new `known_hosts` arg is additive).
- Adversarial (red-team) audit pass (2026-06-21) —
  `audit/2026-06-21-adversarial-engagement.md`; full register in `BACKLOG.md`
  (2026-06-21 adversarial section). A systemic Python `\b` word-boundary bug (it
  fires only at a word↔non-word boundary, so it never matched when the adjacent
  token char was preceded by another word char incl. `_`) independently broke
  **two** trust-boundary controls and was fixed in both:
  - **RED-1 (HIGH)**: compound `*_PASSWORD=` / `*_SECRET=` / `*_TOKEN=` secret
    values were written to the audit log verbatim because the `key=value`
    redaction prefix led with `\b` and the keyword was preceded by `_`. Dropped
    the `\b`; the trailing `\s*[:=]\s*\S+` still gates it to assignment shapes
    (no over-match on plain words). No FP on `description=` / `--color=auto` /
    `count=`.
  - **POL-1 (MED)**: `TIER2_PATTERN` / `TIER3_PATTERN` opened with `\b(`, so
    every alternative starting with a non-word char was dead code — `> /dev/sda`
    (disk wipe via redirect), the fork bomb `:(){ :|:& };:`, and `> /etc/passwd`
    classified **Tier 1** and were admitted in `guarded` mode. Anchor switched
    to `(?<![\w])(` so they fire at shell-token starts; the existing controls
    (`rm -rf`, `dd of=/dev/sda`) are unchanged and there are no new false
    denials (`> /dev/null`, `charm`).

  `PATTERNS_VERSION` 5→6. Also fixed **AUTH-1 (HIGH)** — OAuth token-type
  confusion: a refresh token presented as `Authorization: Bearer refresh:<tok>`
  authenticated as a full access token for the refresh TTL; `load_access_token`
  now rejects any bearer string carrying the `refresh:` key prefix before the
  store lookup. And **RED-2 (MED)** — the PEM private-key matcher's `.*?` drove
  O(n²) backtracking on an argument carrying many unterminated `BEGIN` markers
  (ReDoS on the synchronous audit path); the body is now length-bounded
  (`[\s\S]{0,8192}?`) and still matches a real key block (6400-marker input
  7.6s → ~1.0s). Two doc overclaims corrected: **DOC-1** (`SECURITY.md` —
  state the hash chain is keyless and the off-host copy, not `--verify-audit`,
  defends against a write-capable attacker) and **DOC-2** (`docs/deployment.md`
  — the deny list is defence-in-depth over a `"<tool> <command>"` probe, not an
  absolute prohibition, and a regex over that text is shell-obfuscation /
  encoding-evadable). Paired regression tests in `tests/test_patterns.py` and
  `tests/test_oauth.py`; the `redact` idempotency / no-leak fuzz still passes.
  No P0/critical, no remote-unauthenticated RCE, no auth-bypass-without-a-secret;
  the remaining MEDIUM/LOW hardening, auditability, DoS-footgun, and deploy
  items are deferred in `BACKLOG.md`. Additive — the audit-record shape is
  unchanged.
- OAuth token-store directory is now created `0o700` and the provider **fails
  closed** if its state dir remains group/other-accessible, rather than relying
  on a best-effort `chmod` (audit finding SEC-8). The secret files were already
  `0o600`; this closes the directory-exposure residual without rejecting a
  correctly-`0o700` dir owned by another uid (which we cannot `chmod`). Test
  `test_state_dir_permission_enforcement`.
- 2026-06-21 audit-pass P2/P3 follow-ups (`BACKLOG.md` 2026-06-21 section; no
  P0/P1). OAuth: **SEC-6** `load_refresh_token` now holds the per-provider lock
  so a concurrent revoke cannot surface a spurious `invalid_grant`; **SEC-7**
  the RFC 8707 `resource` indicator is forwarded into the SDK `AuthorizationCode`
  (was stored at authorize() then dropped). CI / supply chain: **CI-1**
  `release.yml` drops an unused `persist-credentials: true`; **CI-2** `sbom.yml`
  passes event/tag values through env vars instead of `${{ }}` shell
  interpolation and defaults its token to `contents: read` with a job-level
  `contents: write` escalation. Audit format & ergonomics: **FMT-1** the LEEF
  formatter emits the mandatory LEEF 2.0 delimiter field; **QUAL-2**
  `ssh_forward` raises a bounded error on a malformed spec instead of leaking a
  raw `ValueError`; **DOC-4** consolidated the duplicate `[Unreleased]` category
  blocks. SEC-5 (`/metrics` auth) and SEC-8 (token-dir fail-closed chmod) remain
  open with rationale in `BACKLOG.md`.
- Redaction now covers Anthropic API keys (`sk-ant-…`) and HuggingFace user
  access tokens (`hf_…`) — high-likelihood secrets in an AI-infrastructure
  tool's command arguments that the prior pattern set missed (audit pass
  finding SEC-4). Added as whole-match collapses in `patterns.py`
  (`PATTERNS_VERSION` 4→5) with paired over/under-scrub tests in
  `tests/test_patterns.py`; `redaction.py` docstring and `SECURITY.md` updated.
  Additive — the audit-record shape is unchanged and the `redact` idempotency
  fuzz still passes.
- Full validation + security audit pass (2026-06-21) —
  [ADR 0005](docs/adr/0005-codebase-validation.md) +
  `audit/2026-06-21-engagement.md`. Scanner battery (pip-audit, trivy, bandit,
  semgrep, actionlint, shellcheck, gitleaks) clean; steps 1-4 green; no pinned
  dependency carries a known CVE at its pinned version. **SEC-3**: raised
  `pyproject.toml` minimum-safe dependency floors — `asyncssh>=2.23.0`
  (GHSA-g794-3fmp-753h), `starlette>=1.3.0` (BadHost), `PyJWT>=2.13.0` (HMAC
  confusion), `cryptography>=48.0.1` (GHSA-537c-gmf6-5ccf) — so a cold
  `pip install` resolver cannot select a transitive version with a known
  advisory (the pinned/tested set was already safe; mirrors PR #97). **TOOL-4**:
  CODEOWNERS now references `renovate.json5` (the repo uses Renovate, not
  Dependabot). Remaining findings are P2/P3/info hardening + format-conformance,
  with no P0/P1; deferred to `BACKLOG.md`.
- Repository governance (GitHub-side, recorded here for the audit trail): the
  `main-protection` ruleset on `main` now additionally enforces
  `required_status_checks` — `check (py3.12)` / `check (py3.13)` /
  `check (py3.14)` / `gitleaks (secret scan)`, bound to GitHub Actions,
  strict=false — and `required_signatures`, alongside the existing
  pull_request / non_fast_forward / deletion / required_linear_history rules.
  Applied 2026-06-12 with explicit operator confirmation and verified
  effective via the rules API; closes the F-G2 residual and the 2026-06-01
  pack's deferred P2-3. pip-audit / dependency-review / CodeQL remain
  advisory by operator choice.
- The `dependency-review` CI job no longer persists the workflow token (audit
  pass finding SEC-2). The checkout step (which carried
  `persist-credentials: true`) was removed entirely: at the pinned action SHA
  (v5.0.0) dependency-review-action is API-only for `pull_request` events —
  base/head SHAs come from the event payload and the comparison runs through
  the Dependency Graph API — so the job needs neither the repository contents
  nor a credential helper. Verified against the action source at the pinned
  SHA; the change validates itself on every PR's `dependency-review` check.
- `ssh_keyscan` now feeds its caller-chosen target hosts to the policy layer,
  so `RELAY_SHELL_POLICY_DENY` can refuse a scan target (audit pass finding
  SEC-1). Previously the tool's policy probe text was empty, so the deny list
  never saw the hosts — a gap on the SSRF-shaped surface most worth gating by
  host, and inconsistent with `ssh_upload` / `ssh_download` / `ssh_forward`,
  which already name their host. A denied call short-circuits before any
  subprocess and is audited `denied=True`. Tradeoff: the same text feeds the
  tier classifier, so a host whose name embeds a `\b`-bounded destructive word
  (`reboot`, `sudo`, ...) over-classifies above Tier 1 and is refused in
  `guarded` mode — a conservative false-deny (`open` is advisory, `readonly`
  already refuses Tier 1, `RELAY_SHELL_POLICY_ALLOW` is the escape hatch),
  matching the transfer tools. No change to `open` mode's admission of a
  normally-named host. Tests in `tests/test_ssh_keyscan_tool.py`.


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
