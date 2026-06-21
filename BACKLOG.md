# Backlog — 2026-06-12 audit pass deferrals

This file is the deferral register for the 2026-06-12 full audit pass. Each
item is a finding from `audit/02-security-findings.md` that was **not** fixed
in the pass, with the schema the audit charter requires.

The project's **canonical, living backlog** is [`docs/runbook.md`](docs/runbook.md)
§7 (and the §8 per-file docs plan). This file does not replace it; it records
the audit-pass-specific deferrals and points into §7 where an item belongs in
the ongoing queue. When an item here is actioned, close it in the same place
its kind is tracked (runbook §7 for capability/quality/ops/security-hardening,
§8 for docs).

Severity order within each section: low before info; smaller effort first.

## Closed (follow-up work after the audit pass)

Resolved in the backlog-work PRs that followed the 2026-06-12 audit pass.
Do not re-add.

| ID | Title | Resolution |
|---|---|---|
| SEC-1 | `ssh_keyscan` target hosts bypass `RELAY_SHELL_POLICY_DENY` | **Closed** (PR #89). Added `_policy_text_ssh_keyscan(hosts)` and wired it into the wrapper so the deny list gates scan targets; the call is audited `denied=True` on a match. The tier-over-classification tradeoff was accepted (only bites `guarded` mode; `open` is advisory, `readonly` already refuses Tier 1; `POLICY_ALLOW` is the escape hatch; consistent with the transfer tools) and is documented in the builder docstring. Tests: deny-gates-host, non-denied-host-runs, classifier-tradeoff pin, and the R-002 builder-contract line. |
| QUAL-1 | A few `seccomp` termination tests assert via "does not hang" | **Closed** (PR #89). Added explicit observable asserts to the five control-flow tests (`m._count == 0` after a drain break, `== 1` after isolated dispatch, `is None` for the suppressed-ioctl `_respond_continue`). Test-only. |
| TOOL-1 | gitleaks flags synthetic redaction fixtures as secrets | **Closed** (PR #89). Added a tightly-scoped `.gitleaks.toml` (extends the default ruleset) allowlisting only `tests/*.py`, `docs/runbook.md`, and `audit/*.md`. Validated: history scan drops from 13 leaks to 0, while a canary key planted under `src/` is still caught. The CI job that consumes it landed as TOOL-3. |
| TOOL-3 | A CI secret-scan job (gitleaks) | **Closed** (PR #90). Added `.github/workflows/gitleaks.yml` (push to main, PRs, daily, `workflow_dispatch`). Self-contained, supply-chain careful: pinned gitleaks 8.30.1 installed by discovering the exact asset name from the release's own checksums file and verifying the tarball before extracting (no hardcoded checksum, no third-party action / license endpoint); `permissions: contents: read`; `gitleaks detect -c .gitleaks.toml` fails the job on any finding. Validated: YAML parses, the detect command runs clean on the tree, the install asset-discovery + checksum-verify pipeline was dry-run (match OK, tamper FAILS), and both first live runs (PR #90 and the post-merge push to `main`) concluded `success`. The required-check decision was made and applied on 2026-06-12: `gitleaks (secret scan)` is now a required status check on `main` via the `main-protection` ruleset (see the F-G2 row below). |
| SEC-2 | `dependency-review.yml` re-enables `persist-credentials` | **Closed** (PR #91). Removed the checkout step from the job entirely. Source-verified at the pinned action SHA (`a1d282b`, v5.0.0): for `pull_request` events the action takes base/head SHAs from the event payload (`src/git-refs.ts`) and calls the Dependency Graph compare API (`src/main.ts`); it spawns no git process and never reads the working tree unless a local `config-file` input is used (none is). The recorded "shells out to `git fetch`" rationale does not match this version's source. No checkout means no persisted token and no repo bytes on disk. Self-validated: the change runs on its own PR's `dependency-review` check. |
| REL-1 | Starlette `TestClient` deprecation in `tests/test_metrics.py` | **Closed** (PR #92). The "install httpx2" warning came from `starlette.testclient`, not from needing httpx 2 — re-checked this session: driving `/metrics` through httpx's own `ASGITransport` (already pinned, httpx 0.28.1) returns the identical response with **zero** warnings, and the `/metrics` custom route needs no lifespan context. Migrated the four HTTP `/metrics` tests off `starlette.testclient.TestClient` to a small `_http_get` ASGITransport helper. Suite now reports 0 warnings (was 1); `pytest -W error::DeprecationWarning tests/test_metrics.py` passes. No httpx2 bump, no dependency change. The earlier "blocked on upstream" disposition was wrong. |
| TOOL-2 | ruff pin skew across `requirements.txt` / `.pre-commit-config.yaml` / the `dev` extra resolve | **Closed** (PR #93; accepted as designed, evidence-verified — a disposition, no code change). `renovate.json5` enables the `pre-commit` manager and groups `pip_requirements` updates on the weekly schedule, and the history shows it updating both pinned locations in practice (#83 pre-commit ruff `v0.15.16`, #84 python dependencies, #85 pre-commit `v6`). The skew window is therefore bounded by the weekly Renovate cadence, both versions lint the tree identically, and a manual pin would only fight the bot. No change needed; re-open only if a ruff release ever splits lint behavior inside one cadence window. |

## 2026-06-21 full audit pass

Findings from the 2026-06-21 full validation + security audit
([`audit/2026-06-21-engagement.md`](audit/2026-06-21-engagement.md)). The scanner
battery (pip-audit, trivy, bandit, semgrep, actionlint, shellcheck, gitleaks) was
clean and no pinned dependency carries a known CVE; there were no P0/P1 findings.

Closed (engagement PR + 2026-06-21 follow-up PRs):

| ID | Title | Resolution |
|---|---|---|
| SEC-3 | `pyproject.toml` dependency lower bounds below patched minimums | **Closed** (this PR). Floors raised: `asyncssh>=2.23.0` (GHSA-g794-3fmp-753h), `starlette>=1.3.0` (BadHost GHSA-86qp-5c8j-p5mr / GHSA-jp82-jpqv-5vv3), `PyJWT>=2.13.0` (HMAC confusion GHSA-xgmm-8j9v-c9wx), `cryptography>=48.0.1` (GHSA-537c-gmf6-5ccf). The pinned set was already safe; this codifies minimum-safe transitive versions, mirroring PR #97's `pydantic-settings` floor. Installed/tested set unchanged; gate green. |
| TOOL-4 | CODEOWNERS required review on a non-existent `/.github/dependabot.yml` | **Closed** (this PR). The repo uses Renovate; reference corrected to `/renovate.json5`. |
| SEC-4 | Add Anthropic `sk-ant-` + HuggingFace `hf_` redaction shapes | **Closed** (follow-up PR to the 2026-06-21 audit pass). Added whole-match patterns to `patterns.py` (`sk-ant-[A-Za-z0-9_-]{20,}`, `hf_[A-Za-z0-9]{34,}`), bumped `PATTERNS_VERSION` 4→5, added paired over/under-scrub tests in `tests/test_patterns.py`, and updated the `redaction.py` docstring + `SECURITY.md`. Gate green incl. the `redact` idempotency fuzz. |
| CI-1 | `release.yml` verify job persisted the workflow token unnecessarily | **Closed** (P2/P3 follow-up PR). `persist-credentials: true` → `false`; no git-auth step runs after checkout (the tag signature is verified via the REST API with an explicit `GH_TOKEN`). actionlint clean. |
| CI-2 | `sbom.yml` shell interpolation + workflow-wide `contents: write` | **Closed** (P2/P3 follow-up PR). Event/tag values now pass through env vars instead of `${{ }}` in `run:`; the workflow token defaults to `contents: read` with a job-level `contents: write` escalation. actionlint clean. |
| SEC-6 | `oauth.load_refresh_token` read without the per-provider lock | **Closed** (P2/P3 follow-up PR). Wrapped the read in `async with self._lock` like every other store access; verified no lock-holding path calls it (no nested-acquire deadlock). |
| SEC-7 | OAuth RFC 8707 `resource` not forwarded to the SDK `AuthorizationCode` | **Closed** (P2/P3 follow-up PR). `_build_auth_code` now forwards `resource` (the field exists in mcp 1.27.2); `.get` keeps back-compat. Test `test_authorization_code_forwards_resource`. |
| FMT-1 | LEEF formatter omitted the mandatory LEEF 2.0 delimiter field | **Closed** (P2/P3 follow-up PR). `_format_leef` now emits `…\|audit\|x09\|<ext>`; `tests/test_audit.py` updated. |
| QUAL-2 | `ssh_forward` spec parse leaked a raw `ValueError` | **Closed** (P2/P3 follow-up PR). Extracted `SshPool._parse_forward_spec` (validated before connecting) raising a bounded message; paired unit test. |
| DOC-4 | `CHANGELOG.md` `[Unreleased]` duplicate `### Security` / `### Changed` blocks | **Closed** (P2/P3 follow-up PR). Consolidated to one block per category (Added/Changed/Fixed/Security) via a content-preserving regroup; Keep a Changelog 1.1.0. |
| SEC-8 | OAuth token-dir `chmod(0o700)` was best-effort | **Closed** (SEC-8 follow-up PR). `_Store` now creates the dir with `mode=0o700` (private at creation; umask can only tighten 0o700), still tightens a pre-existing dir best-effort, and then **fails closed only if the dir remains group/other-accessible**. An exposed token store is refused, while a correctly-`0o700` dir owned by another uid (which we cannot chmod) still passes — so the earlier deferral's false-break concern does not arise. Test `test_state_dir_permission_enforcement` covers both the refuse and accept paths; `test_state_dir_and_files_are_private` still green. |

Open deferrals (severity order; smaller effort first):

| ID | Item | Sev | Effort | Rationale / approach | Owner role |
|---|---|---|---|---|---|
| FMT-2 | CEF header field values not passed through `_cef_escape` | info | XS | No runtime defect (header fields are pipe/backslash-free constants); defensive only. | maintainer |
| CI-3 | `sbom.yml` artifacts not SLSA-attested | info | S | Add `attest-build-provenance` (release.yml precedent). | maintainer |
| DOC-5 | `CHANGELOG.md` lacks Keep-a-Changelog version-compare links | info | XS | Deferred until a second release is tagged ("omit rather than fake"). | maintainer |

Accepted as-designed / operator discretion (no action): **SEC-5** (`/metrics`
OAuth bypass) — operator decision (2026-06-21): keep the documented design
(default `http_host=127.0.0.1` bind + Caddy-edge firewall), not gated in-app, so
the standard unauthenticated Prometheus-scrape model is preserved; pre-commit
hooks pinned
to tags (Renovate-managed; TOOL-2 rationale); hygiene bumps `cryptography` 49 /
`anyio` 4.14 / `mcp` 1.28 (Renovate); `RestrictSUIDSGID` absent from the systemd
hardening drop-in (ADR 0002 full-capability posture; operator call); the ADR 0006
hybrid status string and ADR 0005's frozen "next free 0006" line
(no-retro-edit-of-decision-records).

## Security

(Empty — SEC-1 and SEC-2 closed in the follow-up work above.)

## Reliability

(Empty — REL-1 closed in the follow-up work above.)

## Quality

(Empty — QUAL-1 closed in the follow-up work above.)

## Documentation

(Closed in this pass — D-001/D-002/D-003 are reconciled. No open docs
deferrals. The frozen ADR 0008 incidental `mcp==1.27.1` mention is
deliberately left as-authored per the project's no-retro-edit-of-decision-
records convention; see `audit/03-final-report.md`.)

## Tooling

(Empty — TOOL-1/TOOL-3 closed by the follow-up work and TOOL-2 closed as
accepted-as-designed with Renovate evidence; see the Closed table above.)

## Carried forward from prior engagement packs (operator action)

| ID | Item | Severity | Effort | Rationale | Owner role |
|---|---|---|---|---|---|
| F-G2 | Branch protection on `main` — **fully resolved** (rules enumerated and hardened) | high (governance), now closed | S (done) | Prior packs (`audit/2026-06-01-engagement.md` §7.1) carried this as an open HIGH item ("`main` accepts direct pushes"). Resolved in two steps. 2026-06-12 (audit pass): the branches API reports `protected: true` [V]. 2026-06-12 (follow-up, via the Vertex-held `gh` credential): protection comes from ruleset `main-protection` (id 17307996; classic protection is unset), which enforced pull_request (0 approvals), non_fast_forward, deletion, and required_linear_history [V]. With operator confirmation (a T3 change per the operator's `github-vertex.md` contract), the ruleset gained `required_status_checks` — `check (py3.12)` / `check (py3.13)` / `check (py3.14)` / `gitleaks (secret scan)`, all bound to GitHub Actions, strict=false — and `required_signatures` (closing the prior pack's deferred **P2-3**). Verified effective post-change via `GET /repos/rmednitzer/relay-shell/rules/branches/main` [V]. pip-audit / dependency-review / CodeQL stay advisory by operator choice. | repo owner (executed with operator confirmation) |

## Notes on items NOT added here

- No critical / high / medium **code** security findings were produced by
  this pass, so there is no remediation backlog of that kind.
- The structural refactor candidates (`R-001` table-driven tool registration,
  `R-004` OAuth store `Protocol`) already live in runbook §5.2 and are not
  duplicated here.
- No destructive or irreversible operation was proposed by this pass
  (no history rewrite, no dependency major bump, no schema change), so the
  charter's "proposals, not executed" bucket is empty.
