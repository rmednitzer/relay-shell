# Assurance engagement — 2026-06-21 (full validation + security audit)

- **Baseline**: `rmednitzer/relay-shell` at `823bbab` (`main` HEAD at engagement
  start: PR #98 + PR #97 merged).
- **Branch**: `claude/audit-2026-06-21`.
- **Scope**: full repeatable validation pass (runbook §2 / ADR 0005 steps 1–4),
  a dependency + static + secret scanner battery, a defensive review of the
  trust-boundary modules, a CI / supply-chain hardening review, and a
  structure-vs-spec conformance review. Every structural claim is grounded in a
  trusted external source (see §9), tagged `[V]` verified / `[I]` inferred.
- **Posture note**: `relay-shell` is, by design (ADR 0002), an unsandboxed,
  full-access shell/SSH server whose safety story is *compensating controls*
  (audit, tiered policy, redaction, resource bounds), not capability removal.
  Preserved capability is not a finding; the audit verifies the compensating
  controls hold.
- **This is a frozen, point-in-time record** (per runbook §8.20). Findings fixed
  in the engagement PR name that PR; deferred findings are tracked in
  `BACKLOG.md` and runbook §7.

---

## 1. Validation run (ADR 0005 steps 1–4)

Run on a clean Python 3.12 venv built from `pip install -e ".[dev]"`, after a
contamination catch: installing `semgrep` into the project venv had silently
downgraded `mcp` 1.27.2 → 1.23.3 (semgrep depends on an older `mcp`); the venv
was rebuilt clean and `semgrep` thereafter run isolated via `uvx`, so the
recorded surface is the pinned `mcp==1.27.2`. [V]

- **Step 1 (index)**: 21 MCP tools (== `tests/test_server.py::_EXPECTED` ==
  `docs/tools.md`), 3 resources (2 static + the `inventory/{host}` template),
  1 prompt (`operating_guide`). [V]
- **Step 2 (gates)**: `ruff check` ✓, `ruff format --check` ✓ (46 files),
  `mypy --strict` ✓ (19 source files), `pytest` **342 passed / 13 deselected**,
  `pytest -m fuzz` **13 passed**, `coverage` **93 %** (floor 90 %;
  `patterns`/`redaction`/`policy`/`metrics` 100 %, `audit` 94 %,
  `server`/`sshpool` 95 %, `seccomp` 97 %). [V]
- **Step 3 (upstream surface)**: on `mcp==1.27.2` / `asyncssh==2.23.1` —
  `FastMCP.__init__` kwargs, `Context` ids, the nine OAuth provider methods,
  `AuthorizationParams` / `OAuthToken` fields, and the `asyncssh.connect` option
  kwargs all resolve unchanged. [V]
- **Step 4 (behavior)**: a real `shell_exec` call produced an audit record with
  the intact schema (`ts, tool, tier, denied, args, output_sha256, output_len,
  exit_code`) and the command output referenced by SHA-256 + length only — no
  raw output-body field on the record. [V]

## 2. Security scanner battery — all clean [V]

| Scanner | Target | Result |
|---|---|---|
| **pip-audit** (OSV / PyPA) | `requirements.txt` + installed env | No known vulnerabilities |
| **trivy fs** (vuln + secret + misconfig, MEDIUM+) | whole tree | 0 vulns, 0 secrets, 0 misconfigs |
| **bandit** (`-ll -ii`) | `src/` (4 624 LoC) | 0 High, 0 Medium; 12 Low (all benign — see §4) |
| **semgrep** (`p/python` + `p/secrets`, isolated via `uvx`) | 20 git-tracked files | 0 findings (183 rules) |
| **actionlint** | 8 workflows | 0 issues |
| **shellcheck** (`-S style`) | `deploy/install.sh`, `install-edge.sh` | 0 issues |
| **gitleaks** | full history (CI, merged-PR run) | 0 leaks |

No deployed or pinned dependency carries a known CVE at its pinned version (§3).

## 3. Dependency & supply-chain review

Per-advisory verification against OSV (`osv.dev`) and the GitHub Advisory
Database corroborates the clean pip-audit result; every **pinned** runtime
version is at or past its advisory's fix. [V] The gap is in the **lower bounds**
declared in `pyproject.toml`, which were below the patched minimum and would let
a cold `pip install relay-shell` resolver pick a vulnerable transitive version:

| Package | Pinned (safe) | Old floor | Advisory below floor | Fix |
|---|---|---|---|---|
| asyncssh | 2.23.1 | `>=2.18` | GHSA-g794-3fmp-753h (AuthorizedKeysFile `%u` path traversal, fixed 2.23.0) | floor → `>=2.23.0` |
| starlette | 1.3.1 | `>=0.47` | GHSA-86qp-5c8j-p5mr / GHSA-jp82-jpqv-5vv3 (BadHost host-header, fixed 1.0.1 / 1.3.0) | floor → `>=1.3.0` |
| PyJWT | 2.13.0 | `>=2.10` | GHSA-xgmm-8j9v-c9wx (HMAC confusion) / GHSA-fhv5-28vv-h8m8 / GHSA-752w-5fwx-jx9f (all fixed ≤2.13.0) | floor → `>=2.13.0` |
| cryptography | 48.0.1 / 49.0.0 | `>=44` | GHSA-537c-gmf6-5ccf (bundled OpenSSL) / GHSA-r6ph-v2qm-q3c2 (subgroup) | floor → `>=48.0.1` |
| pydantic-settings | 2.14.2 | `>=2.14.2` (PR #97) | GHSA-4xgf-cpjx-pc3j — **unreachable**: `NestedSecretsSettingsSource` / `secrets_dir` / `secrets_nested_subdir` unused in `src/` [V] | already fixed |

→ **SEC-3 fixed in the engagement PR**: floors raised to the patched minimums
(matching what PR #97 did for `pydantic-settings`). The installed/tested set is
unchanged, so the gate stays green.

Hygiene-only (no security relevance at pinned versions; left to Renovate, whose
`osvVulnerabilityAlerts:true` + weekly grouped PRs is the right channel —
consistent with the TOOL-2 disposition): `cryptography` 48→49, `anyio` 4.13→4.14,
`mcp` 1.27.2→1.28.0. Supply-chain workflows (`pip-audit`, `dependency-review`,
`gitleaks`, `codeql`, `sbom`) are SHA-pinned, least-privilege, and scheduled. [V]

## 4. Trust-boundary code review

**Controls verified sound** [V] (file evidence in the review notes):
1. Output bodies never reach the audit log — only `output_sha256` + `output_len`
   (traced every `audit.record()` caller).
2. Hash chain (ADR 0007) construction + fail-closed `--verify-audit`.
3. Redaction applied centrally in `Relay.run` before every audit write; no bypass
   path; recurses dicts/lists.
4. Policy denylist evaluated first in all three modes.
5. Exec paths: `shell_exec(use_shell=True)` is intentional; `shell_script` and
   argv paths avoid string-interpolation; `ssh_keyscan` uses `shlex.quote` + `--`.
6. Resource bounds clamped (output/timeout/sessions/fanout/keyscan/ring buffer).
7. SSH host verification default `accept-new`; `ignore` is an explicit operator
   choice.
8. Errors rendered via `fmt_exc` (bounded, no traceback).
9. OAuth: PKCE + redirect_uri exact-match (SDK-enforced), TTLs, refresh rotation
   under lock, revocation, `0o600` token files.
10. `ssh_keyscan` SSRF-shaped surface gated through the policy layer (SEC-1).

`bandit`'s 12 Low are benign: one B107 is a false positive on
`token_type="Bearer"` (`oauth.py:245`, the RFC 6750 literal); nine B101 are
type-narrowing/internal-invariant asserts (`assert callable(sink)`,
`assert _libc is not None`), none a security gate; two are deliberate
`try/except` control flow. [V]

Findings (deferred — see register §7):
- **SEC-4 (P2)** redaction lacks Anthropic `sk-ant-` and HuggingFace `hf_` token
  shapes — likely to appear in an AI-infra tool's command args; additive fix with
  the F-004 precedent (OWASP Secrets Management Cheat Sheet [V]).
- **SEC-5 (P3)** `/metrics` bypasses OAuth. Real exposure is low: `http_host`
  defaults to `127.0.0.1` and the edge-firewall posture is documented; an
  optional token gate or separate bind would close the residual.
- **SEC-6 (P3)** `oauth.load_refresh_token` reads without the per-provider lock
  (a concurrent `revoke` can cause a spurious `invalid_grant` — minor DoS, not a
  bypass; rotation invariant still holds at the locked exchange). Verify no
  nested-call deadlock before fixing.
- **SEC-7 (P3)** OAuth `resource` (RFC 8707) stored but not forwarded to the
  SDK's `AuthorizationCode`; SDK-version-specific, verify before changing.
- **SEC-8 (P3)** token-dir `chmod(0o700)` is best-effort; make it fail-closed
  when `auth_enabled` (systemd `UMask=0077` mitigates today).
- **QUAL-2 (P3)** `ssh_forward` spec parsing leaks a `ValueError` message
  (`no-raw-traceback` hygiene) — wrap as a structured `RelayError`.

## 5. CI / Actions hardening (vs GitHub hardening guide [V])

All 8 workflows: third-party actions SHA-pinned, top-level `permissions` present,
no `pull_request_target`/`workflow_run` misuse, no untrusted-payload
interpolation into `run:`. `release.yml` uses OIDC trusted-publishing + SLSA
provenance attestation + a `pypi` environment gate. Deferred findings:
- **TOOL-4 fixed in PR**: CODEOWNERS referenced a non-existent
  `/.github/dependabot.yml`; the repo uses Renovate — corrected to
  `/renovate.json5`.
- **CI-1 (P3)** `release.yml` `verify` job sets `persist-credentials: true`
  though it authenticates via an explicit `GH_TOKEN` and never pushes — drop it
  (consistent with the SEC-2 posture).
- **CI-2 (P3)** `sbom.yml` interpolates `${{ inputs.tag }}` / `github.ref_name`
  into `run:` without env-var indirection, and holds `contents: write` at the
  workflow level with no job-level narrowing.
- **CI-3 (info)** `sbom.yml` artifacts are not SLSA-attested as `release.yml`'s
  are (enhancement).
- Branch-protection requiring CODEOWNERS review is an operator/ruleset decision
  (the `main-protection` ruleset requires 0 approvals by choice).

## 6. Structure / convention conformance (vs external specs [V])

Conforms: all 8 ADRs to the Nygard template + index/next-free marker; SemVer
(`0.1.0`); CEF header structure (`CEF:0|…`, 7 fields) + extension escaping; the
MCP OAuth provider interface (all 9 methods, PKCE, DCR, metadata); Caddyfile v2;
systemd units (the omitted sandboxing directives are explicitly justified against
ADR 0002 in `hardening.conf`). Deferred findings:
- **DOC-4 (P2)** `CHANGELOG.md` `[Unreleased]` has duplicate `### Security`
  (lines 9, 339) and `### Changed` (43, 227) blocks — violates Keep a Changelog
  1.1.0 [V] and the runbook §8.3 one-block-per-category rule; consolidate.
- **FMT-1 (P3)** `audit.py` LEEF formatter advertises `LEEF:2.0` but omits the
  mandatory 6th header (delimiter) field; either add it or label `LEEF:1.0`.
- **FMT-2 (info)** CEF header *field* values aren't passed through `_cef_escape`
  (current values are pipe/backslash-free constants → no runtime defect).
- **DOC-5 (deferred)** no Keep-a-Changelog version-compare links — deferred until
  a second release is tagged (consistent with the SECURITY.md §"omit rather than
  fake" stance).
- Accepted (no-retro-edit convention): ADR 0006 hybrid `Accepted (Proposed …)`
  status string; the frozen `next free … 0006` line in ADR 0005's Consequences.

## 7. Findings register

| ID | Sev | Area | Disposition |
|---|---|---|---|
| SEC-3 | P2 | deps | **Fixed (this PR)** — pyproject floors → patched minimums |
| TOOL-4 | info | CI | **Fixed (this PR)** — CODEOWNERS → `renovate.json5` |
| SEC-4 | P2 | redaction | Deferred → BACKLOG / §7.5 (recommended next) |
| DOC-4 | P2 | changelog | Deferred → BACKLOG / §7.4 |
| SEC-5 | P3 | observability | Deferred → BACKLOG / §7.5 |
| SEC-6 | P3 | auth | Deferred → BACKLOG / §7.5 |
| SEC-7 | P3 | auth | Deferred → BACKLOG / §7.5 |
| SEC-8 | P3 | auth | Deferred → BACKLOG / §7.5 |
| QUAL-2 | P3 | errors | Deferred → BACKLOG / §7.2 |
| FMT-1 | P3 | audit fmt | Deferred → BACKLOG / §7.2 |
| CI-1 | P3 | CI | Deferred → BACKLOG / §7.5 |
| CI-2 | P3 | CI | Deferred → BACKLOG / §7.5 |
| FMT-2 | info | audit fmt | Deferred → BACKLOG / §7.2 |
| DOC-5 | info | changelog | Deferred (blocked on a release tag) |
| CI-3 | info | CI | Deferred → BACKLOG / §7.5 |

No P0/P1 (critical/high) findings. No code security vulnerability was found in
the deployed configuration; the open items are incremental hardening and
documentation/format conformance.

## 8. Changes landed in this engagement PR

- `pyproject.toml` — SEC-3 minimum-safe dependency floors.
- `.github/CODEOWNERS` — TOOL-4 Renovate-config reference.
- `docs/adr/0005-codebase-validation.md` — 2026-06-21 full-audit outcome.
- `BACKLOG.md` — 2026-06-21 deferral register.
- `docs/runbook.md` §7 — living-queue entries for the deferred findings.
- `CHANGELOG.md` — `[Unreleased]` entry.

Rollback: every change is reversible; the floor bump and doc edits carry no
runtime/state effect. Revert the merge to restore prior bounds and docs.

## 9. External sources consulted

- OSV — https://osv.dev ; GitHub Advisory Database — https://github.com/advisories
- GitHub Actions security hardening — https://docs.github.com/actions/security-guides/security-hardening-for-github-actions
- OWASP Logging Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html
- OWASP Secrets Management Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html
- Keep a Changelog 1.1.0 — https://keepachangelog.com/en/1.1.0/ ; SemVer 2.0.0 — https://semver.org
- MCP authorization spec — https://modelcontextprotocol.io/specification/2025-03-26/basic/authorization
- ArcSight CEF / IBM LEEF references (NXLog) — https://docs.nxlog.co/integrate/cef-logging.html , https://docs.nxlog.co/integrate/leef.html
- Caddy v2 Caddyfile — https://caddyserver.com/docs/caddyfile/concepts
