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
- `pytest -q` — 275 passed, 13 deselected (up from 250; +25 tests for the
  chain emit/resume, the `verify_chain` tamper / head-truncation /
  tail-truncation cases, the config cross-field validator, and the
  `--verify-audit` CLI incl. `--require-genesis`). `pytest -m fuzz`
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

## Consequences

- The runbook §2 audit pass is now grounded in a concrete, repeatable
  procedure rather than a free-form review. Reproducing the pass is a
  matter of re-running steps 1-4; deviations become a finding row in this
  table format.
- Each `mcp` SDK bump triggers a fresh §2 pass (the step-3 symbol set is
  the diff target). The current `mcp==1.27.1` pin remains validated.
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
