# Phase 2 + 3: Findings register (2026-06-12 full pass)

Findings from the security audit (Phase 2, `S-`/`D-` ids) and the code-quality
audit (Phase 3, `Q-` ids). Every row is backed by a command run in this
session; unverifiable claims are marked `[UNVERIFIED]`.

## Headline

This is a mature codebase with two prior assurance engagements
(`audit/2026-05-27`, `audit/2026-06-01`). Automated SAST/secret/dependency
scanning is **clean**, the trust-boundary behavior holds empirically, and
the test suite is green at 93% coverage. The actionable findings are
**documentation drift** (a dependency pin moved without the documented
follow-through) plus low/informational hardening and tooling notes. No
critical, high, or medium security findings.

## Scanner results (Phase 2 tooling)

| Tool | Scope | Result | Command |
|---|---|---|---|
| semgrep | `src/` with `p/python` | **0 findings**, 19 files, 0 errors | `uvx semgrep scan --config p/python --json src` |
| bandit | `src/`, medium+ | **0 findings** | `uvx bandit -r src -ll -q` |
| pip-audit | `requirements.txt` | **No known vulnerabilities** | `uvx pip-audit -r requirements.txt --strict` |
| trivy | repo (vuln+misconfig+secret, skip `.venv`) | **0 / 0 / 0** | `trivy fs --scanners vuln,misconfig,secret --skip-dirs .venv .` |
| gitleaks | working tree + git history | only test fixtures + vendored `.venv` (see S-004) | `gitleaks detect --no-git -s .` / `gitleaks detect -s .` |

Manual SAST pass (OWASP-relevant categories for this codebase):

- Command injection: `create_subprocess_shell` is used **by design** (ADR
  0002 — this is a shell tool). `use_shell=false` paths use
  `create_subprocess_exec` with `shlex.split`. `ssh_keyscan` validates every
  host against `_HOSTNAME_RE` and `shlex.quote`s each token with a `--`
  option terminator. No `eval`/`exec`/`os.system`/`pickle`/`yaml.load`
  anywhere (`grep` over `src/`).
- Deserialization: only `json.loads` on env overlay / inventory / OAuth
  state, each wrapped to ignore malformed input. No `pickle`/`marshal`.
- SSRF: `ssh_keyscan` opens caller-chosen outbound TCP — a deliberate,
  documented Tier-1 surface (see S-001).
- Path traversal: the templated resource `{host}` flows to
  `inventory.resolve()` (dict lookup / `@` split), never to the filesystem.
- AuthZ: tiered policy + deny list enforced first in every mode (verified
  §2.4). OAuth provider has per-coroutine lock, single-use codes/refresh
  tokens, lazy expiry, `0o600`/`0o700` file modes.
- Crypto: SHA-256 for the audit hash chain (integrity, not secrecy —
  appropriate); `secrets.token_urlsafe` / `secrets.token_hex` for ids and
  tokens. No home-rolled crypto.

## Behavioral verification (runbook §2, this session)

| Check | Result |
|---|---|
| §2.2 capability surface | 21 tools, equal to `tests/test_server.py::_EXPECTED` |
| §2.3 audit schema | keys `args, denied, exit_code, output_len, output_sha256, tier, tool, ts`; `request_id`/`client_id` absent without an MCP context (documented) |
| §2.3 output-body non-leak | a sentinel present only in command *output* (`OUTBODYSENTINEL`) does not appear in the audit log — PASS |
| §2.3 hash chain | `--verify-audit` on a freshly chained log: `ok=True records=2 anchored=True` |
| §2.4 policy posture | `ls`→T1, `rm -rf`→T3, `systemctl restart`→T2, `sudo …`→T2, `shutdown`→T3; `readonly` permits only T0; `guarded` refuses T2+ unless allowlisted; deny fires in `open` |
| §2.5 redaction | Bearer / mysql `-p` / GITHUB_TOKEN / `--password` / bare `AIza` / JWT all collapse to `[REDACTED]`; `ssh -p22` correctly NOT redacted |

## Security findings register

Schema: ID, title, severity, CWE, file:line, evidence, exploit-plausibility,
recommended fix, effort.

### S-001 — `ssh_keyscan` target hosts bypass `RELAY_SHELL_POLICY_DENY`

- Severity: **info** (low-impact, deliberate-design tradeoff)
- CWE: CWE-862 (Missing Authorization), adjacent
- Location: `src/relay_shell/server.py:1127` (`policy_text=""` in the
  `ssh_keyscan` wrapper)
- Evidence (this session): with `Policy('open', deny=r'169\.254\.169\.254')`,
  `p.check('ssh_keyscan', '')` returns `allowed=True` — the scanned host is
  never shown to the deny regex. By contrast `ssh_upload` / `ssh_download` /
  `ssh_forward` build a synthetic `policy_text` that *does* name the host
  (`_policy_text_ssh_upload` etc.), so the deny list gates their targets.
- Exploit plausibility: low. `ssh_keyscan` is Tier 1 (refused in `readonly`),
  caps at 32 hosts, validates each host against `_HOSTNAME_RE`, and only
  performs an SSH-handshake key fetch (the metadata service at
  169.254.169.254 is not an SSH server). The connection-oriented SSH tools
  (`ssh_exec`/`ssh_spawn`/`ssh_fanout`) also do not expose the host to the
  deny list (their `policy_text` is the command), so host-level deny is not a
  uniform guarantee today regardless.
- Recommended fix: feed the validated host list to `policy_text` via a
  `_policy_text_ssh_keyscan` builder, mirroring the transfer tools. **Tradeoff
  to decide first**: the same text is consumed by the tier classifier, so an
  adversarial hostname containing a `\b`-bounded heuristic word (e.g.
  `sudo.example.com` → `PRIV_ESC_PATTERN`) would over-classify the scan to
  Tier 2 and get it refused in `guarded`. Because this is a behavior change
  with a non-obvious tradeoff, it is filed as a backlog proposal
  (BACKLOG `SEC-1`), not fixed unilaterally in this pass.
- Effort: S

### S-002 — `/metrics` is unauthenticated by design (accepted risk)

- Severity: **info** (documented, accepted)
- Location: `src/relay_shell/server.py:1246` (`@mcp.custom_route("/metrics")`)
- Evidence: the route is registered only for the HTTP transport, binds the
  loopback `http_host`/`http_port`, bypasses the OAuth layer (FastMCP
  `custom_route` is documented as health-check style), and is firewalled by
  the Caddy CIDR matcher in the supported deployment. The exposition carries
  only bounded counters/gauges (no command output). Verified the metric
  label set is fixed (`metrics.py` `_HELP`/`_TYPES`).
- Recommended fix: none. Recorded for completeness so a future reviewer does
  not re-discover it as a finding. The trust boundary is the transport
  (SECURITY.md); `/metrics` exposes no sensitive data.
- Effort: n/a

### S-003 — `dependency-review.yml` restores `persist-credentials`

- Severity: **low**
- CWE: CWE-522 (Insufficiently Protected Credentials), minor
- Location: `.github/workflows/dependency-review.yml:18` (`persist-credentials: true`)
- Evidence: `actions/checkout@v6` defaults `persist-credentials` to off; this
  workflow re-enables it so `dependency-review-action` can `git fetch` the
  base/head refs (the inline comment explains this). The effect is the
  `GITHUB_TOKEN` is written to `.git/config` for the job's duration.
- Exploit plausibility: very low. The job runs only the pinned
  dependency-review action (no third-party steps that could read the config),
  on PR events, with a read-only top-level `permissions: contents: read`.
- Recommended fix: optionally pass the refs to the action explicitly (its
  `base-ref`/`head-ref` inputs) to avoid the credential helper, or accept as
  documented. Backlog `TOOL-2`.
- Effort: S

### S-004 — gitleaks hits are test fixtures + vendored venv (no leak)

- Severity: **info** (false positives; no real secret)
- Evidence (this session): `gitleaks detect` flagged 19 working-tree / 13
  history matches. Every history match is in `tests/test_patterns.py`,
  `tests/test_redaction.py`, `tests/test_audit.py`, or `docs/runbook.md` —
  these are **synthetic** redaction fixtures (the runbook even assembles
  token samples from `prefix + body` at runtime to avoid shipping a
  contiguous secret literal; the test files use deliberately fake values like
  `ghp_abc…` / `AKIAIOSFODNN7EXAMPLE`, the documented AWS example key). The
  remaining working-tree-only hits are inside `.venv/` (vendored asyncssh /
  cryptography / jwt), which is not tracked. No credential requires rotation.
- Recommended fix: none required. Optionally add a `.gitleaks.toml`
  allowlist for `tests/` + `docs/runbook.md` so CI secret-scanning (if added,
  backlog `TOOL-1`) is not noisy. Backlog `TOOL-1`.
- Effort: S

## Documentation-drift findings

### D-001 — `mcp` pin moved to 1.27.2 but living docs + ADRs say 1.27.1

- Severity: **low** (docs accuracy; no runtime effect)
- Location: `README.md:6`, `README.md:151`, `docs/architecture.md:15`;
  ADR 0005 Consequences "current `mcp==1.27.1` pin remains validated"
  (`docs/adr/0005-codebase-validation.md:185`)
- Evidence (this session): `pyproject.toml:26` and `requirements.txt:7` pin
  `mcp==1.27.2`; the installed/validated runtime is 1.27.2; the bump landed in
  PR #66 (`07cf5b9 Build(deps): Bump mcp from 1.27.1 to 1.27.2`). The README
  status line, the README compatibility matrix, and `docs/architecture.md`
  still say `1.27.1`. Per `docs/runbook.md` §8.9 an `mcp` bump should add an
  ADR 0001 Consequences entry and trigger a fresh ADR 0005 validation
  outcome; neither was recorded. Upstream symbols still resolve on 1.27.2
  (FastMCP/Context, all 9 OAuth provider methods — verified this session).
- Note on frozen records: the `mcp==1.27.1` strings inside ADR 0005's *dated*
  outcome paragraphs (2026-05-24/05-31/06-01) and ADR 0001/0008's bodies are
  **historical** and correct-as-of-date (runbook §8.12a/§8.20). They are NOT
  edited. Only the living docs and the "current pin" claim are corrected, and
  a new dated ADR 0005 outcome carries the current truth.
- Recommended fix: update README status line + compat matrix and
  architecture.md to `1.27.2`; add an ADR 0001 Consequences entry for the
  bump; add an ADR 0005 2026-06-12 outcome paragraph; refresh the ADR index
  subject. Fixed in Phase 5/6 of this pass.
- Effort: S

### D-002 — README "last validated" date predates this pass

- Severity: **info**
- Location: `README.md:5-8` ("last validated … on 2026-06-01")
- Evidence: runbook §8.1 requires the status-line date to match the most
  recent ADR 0005 outcome paragraph. This pass adds a 2026-06-12 outcome, so
  the README date is updated to match. Fixed in Phase 5/6.
- Effort: S

### D-003 — README compat matrix says asyncssh "tested at 2.23.0"

- Severity: **info**
- Location: `README.md:152`
- Evidence: `requirements.txt:10` pins `asyncssh==2.23.1` and the suite was
  validated against 2.23.1 this session (24/24 SSH integration tests pass).
  The matrix note lags one patch version.
- Recommended fix: bump the parenthetical to 2.23.1. Fixed in Phase 5.
- Effort: S

## Quality findings register (Phase 3, `Q-`)

### Q-001 — ruff version skew across three pin sources

- Severity: **low**
- Location: `requirements.txt:20` (`ruff==0.15.16`),
  `.pre-commit-config.yaml:18` (`rev: v0.15.16`), `pyproject.toml:41`
  (`ruff>=0.8` dev floor)
- Evidence: a fresh `pip install -e ".[dev]"` in this session resolved
  `ruff 0.15.17`, while the two pinned sources say `0.15.16`. CI installs the
  unpinned dev extra, so CI runs whatever ruff is latest at job time, which
  can drift from the pinned pre-commit/requirements. No behavioral difference
  observed (both pass clean). This is Renovate-managed and self-correcting.
- Recommended fix: none in this pass (changing the mirror fights Renovate).
  Optionally pin the CI ruff to the pre-commit `rev` for reproducibility.
  Backlog `TOOL-3`.
- Effort: S

### Q-002 — `requirements.txt` mirror drifts from a fresh resolve

- Severity: **info**
- Location: `requirements.txt` (header claims it mirrors the resolved dev set)
- Evidence: same root cause as Q-001 — the file is a hand-maintained mirror,
  refreshed by Renovate, so between Renovate runs a fresh resolve can pull
  newer patch versions (ruff 0.15.16 → 0.15.17). Working as designed; noted
  so a reader does not mistake the mirror for a hash-locked lockfile.
- Recommended fix: none. Documented as expected behavior.
- Effort: n/a

### Q-003 — Starlette TestClient deprecation warning in the suite

- Severity: **low**
- Location: `tests/test_metrics.py:15`
- Evidence: `pytest` emits one
  `StarletteDeprecationWarning: Using httpx with starlette.testclient is
  deprecated; install httpx2 instead`. Upstream Starlette deprecation; the
  test still passes. `pyproject.toml` filters `DeprecationWarning` but this is
  a `StarletteDeprecationWarning` subclass surfaced at import.
- Recommended fix: track the Starlette/httpx2 migration; no action until the
  pinned Starlette removes the shim. Backlog `REL-1`.
- Effort: M (depends on upstream)

### Q-004 — a few seccomp tests assert via "does not hang"

- Severity: **info**
- Location: `tests/test_seccomp.py` (`test_drain_breaks_on_stop_signal`,
  `…_on_listener_hangup`, `…_on_recv_error`,
  `test_respond_continue_swallows_ioctl_error`,
  `test_dispatch_callback_exception_is_isolated`)
- Evidence: these exercise termination/exception-isolation paths whose
  success criterion is "returns without raising/hanging" rather than an
  explicit `assert`. This is a legitimate pattern for control-flow tests (a
  regression would hang and time out), but it is worth a comment so a future
  reader does not mistake them for stubs. No assertion-free *behavioral* test
  was found (the redaction/policy/audit suites all assert concretely).
- Recommended fix: optional — add a trailing `assert` on an observable
  (e.g. the dispatch counter) where cheap. Backlog `QUAL-1`.
- Effort: S

### Q-005 — no dead code, unused deps, or missing timeouts found

- Severity: **info** (negative result, recorded for the register)
- Evidence: every runtime dependency in `pyproject.toml` is imported
  (`mcp`, `pydantic`/`pydantic-settings`, `asyncssh`, `uvicorn`/`starlette`
  via FastMCP HTTP, `anyio` transitively). Network calls carry timeouts:
  `asyncssh.connect(connect_timeout=…)`, `ssh.run` via `asyncio.wait_for`,
  SFTP optional `timeout=`, local exec via `asyncio.wait_for` +
  `_kill_tree`. Resource teardown is explicit (`SshPool.close_all`,
  `SessionRegistry.shutdown`, `_kill_tree`, `aclose`). No leaked task or fd
  pattern found beyond the documented best-effort suppressions.

## Severity roll-up

| Severity | Security | Docs | Quality |
|---|---|---|---|
| critical | 0 | – | – |
| high | 0 | – | – |
| medium | 0 | 0 | 0 |
| low | 1 (S-003) | 1 (D-001) | 2 (Q-001, Q-003) |
| info | 3 (S-001, S-002, S-004) | 2 (D-002, D-003) | 3 (Q-002, Q-004, Q-005) |
