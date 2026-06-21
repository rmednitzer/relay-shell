# ADR 0005: Codebase validation against known-good sources

- Status: Accepted
- Date: 2026-05-24

## Context

ADR 0002 makes the trust boundary the **service account**, not an internal
sandbox; ADRs 0003 and 0004 add the compensating controls (tiered authority,
audited execution, edge TLS). All three rest on a contract with upstream
sources: the `mcp` SDK (FastMCP, the OAuth provider interface, the resource
+ tool decorators), `asyncssh` (the SSH semantics we expose), and
`pydantic-settings` (the configuration layer). If any of those drifts
silently — a renamed kwarg, a removed method, a relaxed default — the
documented guarantees stop being load-bearing.

The runbook §2 codifies the audit pass, but it had not been executed
end-to-end against the *actual upstream surfaces* on the pinned versions
since the original release. This ADR records the methodology, the result,
and the small drift the pass surfaced.

## Decision

Treat a periodic, repeatable validation pass against the upstream APIs
as a first-class operating procedure, owned by the runbook §2 (Audit) and
referenced from this ADR. The pass produces, in this order:

1. **Code index.** `git ls-files`, line counts for every package and test
   file, the registered tool set (from `FastMCP.list_tools()`), and the
   registered resource URIs.
2. **Quality gates.** `ruff check`, `ruff format --check`, `mypy --strict`,
   `pytest -q`, and `coverage report` with subprocess collection wired
   (runbook §4.3) so the stdio e2e contributes.
3. **Upstream surface validation.** Import every dependency the code
   touches and assert that the symbols and signatures we rely on still
   exist on the pinned version:
   - `mcp.server.fastmcp.FastMCP.__init__` accepts the kwargs `build_server`
     passes (`instructions`, `host`, `port`, `stateless_http`,
     `json_response`, `auth`, `auth_server_provider`).
   - `mcp.server.fastmcp.Context` exposes `request_id` and `client_id`
     (the audit pipeline reads both best-effort).
   - `mcp.server.auth.provider.OAuthAuthorizationServerProvider` advertises
     the nine methods `FileOAuthProvider` implements (`authorize`,
     `exchange_authorization_code`, `exchange_refresh_token`, `get_client`,
     `load_access_token`, `load_authorization_code`, `load_refresh_token`,
     `register_client`, `revoke_token`).
   - `mcp.server.auth.provider.AuthorizationParams` exposes the fields the
     provider reads (`code_challenge`, `redirect_uri`,
     `redirect_uri_provided_explicitly`, `scopes`, `state`, `resource`).
   - `mcp.shared.auth.OAuthClientInformationFull` /
     `mcp.shared.auth.OAuthToken` carry the fields the provider sets.
   - `asyncssh.connect` accepts `known_hosts`, `username`, `port`,
     `client_keys`, `connect_timeout`, `config`, `tunnel`,
     `keepalive_interval` — the surface the pool relies on.
4. **Behavior validation.** Drive at least one real tool through
   `build_server(...).call_tool(...)`, then inspect the resulting audit
   record on disk and confirm:
   - the record schema (`ts`, `tool`, `tier`, `denied`, `args`,
     `output_sha256`, `output_len`, `exit_code`) is intact;
   - the output body is *not* present in the record (only its hash);
   - a sample of tier classifications matches the table in ADR 0003;
   - canonical redaction inputs (Bearer, AWS SigV4, MySQL `-p`, URL
     creds, PEM block, GitHub token, `--password "two words"`) all
     produce the documented redacted output and `ssh -p22` is *not*
     redacted (the well-known under-scrub regression).
5. **Findings**: any code/doc mismatch surfaced by steps 1-4 becomes a
   line item with a severity (P0 release-blocker through P3 nice-to-fix)
   and a resolution plan that lands in the same PR.

## Validation outcome (2026-05-24)

All four steps passed without code-level regressions:

- 21 MCP tools registered, matching `tests/test_server.py::_EXPECTED` and
  `docs/tools.md`.
- 3 MCP resources registered, matching `docs/tools.md` §Resources.
- `ruff check`, `ruff format --check`, `mypy --strict` clean.
- `pytest -q` — 195 passed, 13 deselected (the `fuzz` marker is nightly-
  only by design; see `pyproject.toml`).
- `coverage` — 89% with subprocess collection enabled (floor is 85%).
- Every upstream symbol in step 3 resolved on the pinned versions.
- The audit record schema and the redaction / tier samples in step 4
  match the documented behavior verbatim.

Three documentation-drift findings were surfaced and **fixed in the same
PR that lands this ADR**, so they do not survive past 0005:

| ID    | Severity | Subject                                                                                   | Resolution |
|-------|----------|-------------------------------------------------------------------------------------------|------------|
| F-001 | P2       | `requirements.txt` pinned `starlette==1.0.0` / `PyJWT==2.12.1` / `ruff==0.15.13` while `pip install -e ".[dev]"` resolved `1.1.0` / `2.13.0` / `0.15.14` — the file header claimed "validated build set" but the pins did not match reality. | Pins refreshed to the actually-tested set; header reworded to "validated against the current development matrix". |
| F-002 | P2       | `docs/runbook.md` §4.3 still said "CI floor: 75%, current ~78%". The floor moved to 85% in B-022 and measured coverage is 89%.                                                                | Header and body of §4.3 updated to "CI floor: 85%, current ~89%". |
| F-003 | P3       | `docs/runbook.md` §3.4 referenced the obsolete tool-count assertion `len(names) == 18`. Actual: `tests/test_server.py:36` asserts `21`.                                                       | Reference updated to `21`. |

No security findings. No capability regressions. The trust boundary
described in ADR 0002 and the admission semantics described in ADR 0003
still hold byte-for-byte against the current code.

## Validation outcome (2026-05-31)

Re-ran steps 1-4 against the same pinned surfaces. The gates and the
upstream contract are still green:

- 21 MCP tools registered, matching `tests/test_server.py::_EXPECTED`
  and `docs/tools.md`; 3 MCP resources registered.
- `ruff check`, `ruff format --check`, `mypy --strict` clean.
- `pytest -q` — 250 passed, 13 deselected (up from 195/244 as the
  redaction-coverage tests below landed; the `fuzz` marker is
  nightly-only by design). `pytest -m fuzz` — 13 property invariants
  pass, including `redact` idempotency on the new shapes.
- `coverage` — 92% with subprocess collection (floor 90%);
  `patterns.py` and `redaction.py` at 100%.
- Every upstream symbol in step 3 still resolves on `mcp==1.27.1` /
  `asyncssh` 2.23.0 (FastMCP kwargs, `Context` ids, the nine OAuth
  provider methods, `AuthorizationParams` fields, the eight
  `asyncssh.connect` option kwargs, `OAuthToken` fields).

Step 4 surfaced one security finding against the *redaction* sample
set, fixed in the same PR:

| ID    | Severity | Subject                                                                                                                                                                                                                                  | Resolution |
|-------|----------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|------------|
| F-004 | P2       | The whole-match `REDACTION_PATTERNS` set covered GitHub / OpenAI(`sk-`) / AWS(`AKIA`) / Slack(`xox*`) but missed several of the most common structurally-anchored secret shapes when they arrive *bare* in an audited argument (a JSON body, a log line, a flag the CLI-flag prefix list does not name): Google API key (`AIza`), Google OAuth token (`ya29.`), Stripe `sk_`/`rk_` keys, GitLab `glpat-`, npm `npm_`, PyPI `pypi-`, and JWTs. The OpenAI `sk-` shape also missed the `sk-proj-`/`sk-svcacct-`/`sk-admin-` prefixes (an internal hyphen broke the run). Secret leakage into the audit log is in `SECURITY.md` §Scope. | Added the seven shapes and widened the OpenAI prefix in `src/relay_shell/patterns.py`; anchors and length floors track the canonical secret-scanning rulesets (gitleaks / GitHub secret scanning). `PATTERNS_VERSION` bumped `"3"` → `"4"`. Paired over-scrub / under-scrub tests in `tests/test_patterns.py` (lines under `test_openai_project_and_service_keys` through `test_registry_and_jwt_shapes_positive_and_negative`) and a bare-in-args scenario in `tests/test_redaction.py`. `redaction.py` docstring and `SECURITY.md` redaction bullet updated. |

PR review (Copilot + Codex) further hardened the F-004 fix before merge:
the provider-token bodies were made to run unbounded from their length
floor and to admit each token's full alphabet (Google OAuth `ya29.` dots,
OpenAI `sk-proj-`/`sk-svcacct-`/`sk-admin-` URL-safe separators), and the
JWT rule's payload/signature floor was lowered so a compact JWT with a
small claim set is still redacted. The intent in every case is the same:
a match must collapse the *whole* token, never leave a tail, and never
miss a valid-but-compact credential. Regression fixtures pinning each
edge live in `tests/test_patterns.py`.

No capability regressions; no change to policy admission, the audit
record schema, or any tool's response shape. The trust boundary
(ADR 0002) and tier semantics (ADR 0003) are unchanged — this pass
hardened a compensating control, it did not move the boundary.

## Validation outcome (2026-06-01)

Re-ran steps 1-4. This pass also landed [ADR 0007](0007-audit-hash-chain.md)
(tamper-evident audit hash chain) in the same PR, so the behavior
validation in step 4 was extended to cover the new chain surface. The
broader engagement is recorded in
[`audit/2026-06-01-engagement.md`](../../audit/2026-06-01-engagement.md).

- 21 MCP tools and 3 resources registered, matching
  `tests/test_server.py::_EXPECTED` and `docs/tools.md`. ADR 0007 adds a
  **CLI verb** (`--verify-audit`), not a tool, so the tool contract is
  unchanged.
- `ruff check`, `ruff format --check`, `mypy --strict` clean.
- `pytest -q` — 277 passed, 13 deselected (up from 250; +27 tests for the
  chain emit/resume, the `verify_chain` tamper / head-truncation /
  tail-truncation cases, the config cross-field validator, and the
  fail-closed `--verify-audit` CLI incl. `--segment`). `pytest -m fuzz`
  — 13 invariants pass.
- `coverage` — 92% with subprocess collection (floor 90%); `config.py`
  99%, `audit.py` 95%, `patterns.py` / `redaction.py` / `policy.py` 100%.
- Every upstream symbol in step 3 still resolves on `mcp==1.27.1` /
  `asyncssh` 2.23.0; `pydantic` `model_validator(mode="after")` (the new
  cross-field `audit_chain`→`jsonl` guard) resolves on the pinned
  `pydantic>=2.11`.
- Step 4 audit-record schema: the default-off record is byte-identical to
  the 2026-05-31 pass; with `RELAY_SHELL_AUDIT_CHAIN=true` it gains exactly
  `seq`/`prev`/`chain` and `verify_chain` confirms a clean chain and flags
  edit / forgery / deletion / reorder / garbage-line / non-genesis-anchor.

| ID    | Severity | Subject                                                                                                                                                                                                 | Resolution |
|-------|----------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|------------|
| F-005 | P3       | `docs/runbook.md` §5.1 still listed **C-005** (`Inventory` field naming) as an open consolidation candidate. It was closed in PR #57 (`Inventory(ssh_config=...)` ctor + `ssh_config_file` resolved-iff-exists property), as recorded in `audit/2026-05-27-engagement.md` §2.2/§3 and `CHANGELOG.md`. The code carries no `ssh_config_path`; the runbook entry was the last stale reference. | Moved C-005 to the §5.1 "Closed (do not re-add)" block with the resolution note. |
| G-1   | (gap)    | The audit log — ADR 0002's first compensating control — had no in-record tamper-evidence; integrity rested solely on `chattr +a` + off-host shipping, both defeatable by the documented residual-risk attacker in the pre-ship window. Not a regression against the docs (the docs never claimed in-record integrity), recorded as a hardening gap. | Closed by [ADR 0007](0007-audit-hash-chain.md): opt-in, additive per-record hash chain + `relay-shell --verify-audit`. Default-off keeps every existing deployment byte-identical. |

No security regressions. No capability regressions. The trust boundary
(ADR 0002) and tier semantics (ADR 0003) are unchanged. The audit-record
schema change is additive and opt-in (default off), so off-host parsers
built against the prior shape keep working.

## Validation outcome (2026-06-12)

Re-ran steps 1-4 as part of a full audit / validation / hardening pass
(evidence pack under `audit/00-inventory.md`, `audit/01-baseline.md`,
`audit/02-security-findings.md`, `audit/03-final-report.md`). This pass also
reconciled the `mcp` pin drift surfaced as D-001 below. All gates green; the
upstream contract holds on the bumped pin.

- 21 MCP tools registered, equal to `tests/test_server.py::_EXPECTED` and
  `docs/tools.md`; 3 MCP resources; 1 prompt (`operating_guide`, ADR 0008).
- `ruff check`, `ruff format --check`, `mypy --strict` clean (19 source
  files).
- `pytest` — **339 passed, 13 deselected** (the `fuzz` marker is
  nightly-only by design); `pytest -m fuzz` — **13** property invariants
  pass. Runtime ~36 s.
- `coverage` — **93%** with subprocess collection (floor 90%);
  `patterns.py` / `redaction.py` / `policy.py` / `metrics.py` 100%,
  `audit.py` 94%, `server.py` 95%, `seccomp.py` 97%.
- Step 3 upstream surface now resolves on **`mcp==1.27.2`** (the pin moved
  1.27.1 → 1.27.2 in PR #66, 2026-06-04) / `asyncssh` **2.23.1**: FastMCP
  kwargs, `Context` ids, the nine OAuth provider methods,
  `AuthorizationParams` / `OAuthToken` fields, and the `asyncssh.connect`
  option kwargs all resolve unchanged; `pydantic` `model_validator` resolves
  on the pinned `pydantic>=2.11`.
- Step 4 behavior: audit-record schema intact (`ts, tool, tier, denied,
  args, output_sha256, output_len, exit_code`); a sentinel present only in
  command *output* does not reach the audit log; `--verify-audit` confirms a
  freshly chained log (`anchored=True`); tier classification and the
  redaction sample set match ADR 0003 / `SECURITY.md`. External scanners
  (semgrep, bandit, pip-audit, trivy) reported zero findings.

| ID    | Severity | Subject                                                                                                                                                                                                                          | Resolution |
|-------|----------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|------------|
| D-001 | low (docs) | The `mcp` pin moved 1.27.1 → 1.27.2 in PR #66 (2026-06-04), but the README status line (`README.md:6`) + compatibility matrix (`README.md:151`) and `docs/architecture.md:15` still named 1.27.1, and no ADR 0001 Consequences entry / ADR 0005 outcome had recorded the bump (the runbook §8.9 trigger was missed). | Synced the living docs to 1.27.2 + asyncssh 2.23.1 (this pass); added the ADR 0001 Consequences pin-movement line; recorded this outcome paragraph. Frozen ADR bodies and prior dated outcomes left intact. |

No security regressions. No capability regressions. The trust boundary
(ADR 0002) and tier semantics (ADR 0003) are unchanged; this pass corrected
documentation drift and did not touch executor, policy, redaction, or audit
behavior.

## Validation outcome (2026-06-21)

Re-ran steps 1-4 on the pinned upstream surfaces. No dependency change since
the 2026-06-12 pass; this is a documentation-drift reconciliation pass whose
single finding (DOC-1) is a stale cross-reference, fixed in the same PR that
records this outcome. All gates green; the upstream contract holds.

- 21 MCP tools registered, equal to `tests/test_server.py::_EXPECTED` and
  `docs/tools.md`; 3 MCP resources (2 static + the `inventory/{host}`
  template); 1 prompt (`operating_guide`, ADR 0008).
- `ruff check`, `ruff format --check`, `mypy --strict` clean (19 source
  files).
- `pytest` — **342 passed, 13 deselected** (the `fuzz` marker is nightly-only
  by design); `pytest -m fuzz` — **13** property invariants pass.
- `coverage` — **93%** with subprocess collection (floor 90%);
  `patterns.py` / `redaction.py` / `policy.py` / `metrics.py` 100%,
  `config.py` 99%, `seccomp.py` 97%, `server.py` / `sshpool.py` 95%,
  `audit.py` 94%.
- Step 3 upstream surface resolves on **`mcp==1.27.2`** / `asyncssh`
  **2.23.1**: `FastMCP.__init__` kwargs, `Context` ids, the nine OAuth
  provider methods, `AuthorizationParams` / `OAuthToken` fields, and the
  `asyncssh.connect` option kwargs all resolve unchanged; `pydantic`
  `model_validator` resolves on the pinned `pydantic>=2.11`.
- Step 4 behavior: a real `shell_exec` call writes an audit record carrying
  the intact schema (`ts, tool, tier, denied, args, output_sha256,
  output_len, exit_code`) with the command output referenced by SHA-256 +
  length only — no raw output-body field on the record. Tier classification
  and the redaction sample set are exercised green by the suite.

| ID    | Severity | Subject | Resolution |
|-------|----------|---------|------------|
| DOC-1 | info (docs) | `docs/runbook.md` §8.18 described the ADR next-free-number marker as "currently **0008**", but `docs/adr/README.md` (the authoritative marker) has read **0009** since ADR 0008 landed (2026-06-08); the runbook's maintenance note for the README was one number behind. | Corrected the §8.18 parenthetical to **0009** to match `docs/adr/README.md`, and appended this pass to the ADR 0005 index subject. Frozen ADR bodies and prior dated outcomes were left intact — the "next free ... 0006" line in this ADR's own Consequences is the 2026-05-24 record, not a live marker. |

No security findings. No capability regressions. The trust boundary
(ADR 0002) and tier semantics (ADR 0003) are unchanged; this pass corrected
documentation drift and did not touch executor, policy, redaction, or audit
behavior.

## Validation outcome (2026-06-21, full audit pass)

A full validation + security audit, run the same day as the doc-drift pass above;
evidence pack:
[`audit/2026-06-21-engagement.md`](../../audit/2026-06-21-engagement.md). Steps
1-4 were re-run on a clean venv at the pinned `mcp==1.27.2` / `asyncssh==2.23.1`
(a `semgrep`-into-the-project-venv `mcp` downgrade to 1.23.3 was caught and the
venv rebuilt clean, with `semgrep` thereafter run isolated via `uvx`), plus an
external scanner battery and reviews of the trust boundary, the CI supply chain,
and structure-vs-spec conformance against trusted external sources.

- Gates green: `ruff` / `ruff format` / `mypy --strict` clean (19 files);
  `pytest` **342 passed, 13 deselected**; `pytest -m fuzz` **13**; `coverage`
  **93%** (floor 90%). 21 tools / 3 resources / 1 prompt; upstream surface
  resolves; the audit-record output-hash-only invariant holds.
- Scanner battery all clean: pip-audit (OSV/PyPA), trivy fs
  (vuln/secret/misconfig), bandit (0 medium+; 12 benign Low), semgrep (0
  findings, 183 rules), actionlint, shellcheck, gitleaks. No pinned dependency
  carries a known CVE at its pinned version.

| ID | Severity | Subject | Resolution |
|----|----------|---------|------------|
| SEC-3 | P2 | `pyproject.toml` lower bounds sat below the patched minimum for `asyncssh` (GHSA-g794-3fmp-753h), `starlette` (BadHost GHSA-86qp-5c8j-p5mr / GHSA-jp82-jpqv-5vv3), `PyJWT` (HMAC confusion GHSA-xgmm-8j9v-c9wx), and `cryptography` (GHSA-537c-gmf6-5ccf) — a cold `pip install` resolver could pick a vulnerable transitive version, though the *pinned* set was already safe. | Floors raised to `asyncssh>=2.23.0`, `starlette>=1.3.0`, `PyJWT>=2.13.0`, `cryptography>=48.0.1` (mirrors PR #97's `pydantic-settings` floor bump). Installed/tested set unchanged; gate green. |
| TOOL-4 | info | `.github/CODEOWNERS` required review on a non-existent `/.github/dependabot.yml`; the repo uses Renovate. | Reference corrected to `/renovate.json5`. |

The remaining findings are incremental hardening / format-conformance with no
P0/P1 (SEC-4 Anthropic `sk-ant-` / HuggingFace `hf_` redaction shapes is the
recommended next item); they are registered in the engagement pack §7 and
deferred to `BACKLOG.md` / runbook §7. No security regression; the ADR 0002
trust boundary and ADR 0003 tier semantics are unchanged.

## Consequences

- The runbook §2 audit pass is now grounded in a concrete, repeatable
  procedure rather than a free-form review. Reproducing the pass is a
  matter of re-running steps 1-4; deviations become a finding row in this
  table format.
- Each `mcp` SDK bump triggers a fresh §2 pass (the step-3 symbol set is
  the diff target). The latest validated pin is the one named in the most
  recent dated outcome paragraph above (currently `mcp==1.27.2`, validated
  2026-06-21), not a hardcoded version here — so this bullet does not drift
  as the pin moves.
- Each subsequent ADR landing should record its own validation outcome
  using the same format — terse findings table, severity, resolution —
  so the audit trail of *decisions* and the audit trail of *executions*
  stay symmetrical.
- The next free ADR number is **0006**.

## Rejected alternatives

- **Annual-only audit.** A yearly pass surfaces drift too late; the SDK
  ships minor versions in weeks and the policy/redaction modules drift
  fastest. The pass belongs in the runbook (always available) and is
  triggered on event, not date.
- **Continuous validation via a check-everything CI job.** Some of the
  step-3 introspection (importing the SDK, listing tool registration) is
  already covered by `tests/test_server.py` and `tests/test_oauth.py`.
  Duplicating those into a separate "validation" job would double the
  surface and the upkeep without buying anything `pytest` does not
  already give us. Coverage subprocess collection in CI catches the
  remaining cases (the e2e contributes the wrapper bodies).
- **Auto-generated findings file.** A standalone `docs/audit/2026-05-24.md`
  would split the audit trail across files. Recording each pass inline in
  the closing ADR keeps the consequences and the resolution co-located.
