# 2026-06-01 — `relay-shell` engagement evidence pack

Focused audit + hardening engagement against `rmednitzer/relay-shell`,
starting from HEAD `1181a37` (`docs: fix stale coverage-floor comment +
inventory the audit engagement packs` (#63)).

Mode: ACTION-RB. Authorization: **Broad** (trust-boundary changes permitted
with runbook §2 evidence; stop-and-confirm for breaking changes, governance
artifacts, repo settings, history rewrites). The one trust-boundary change
this engagement (the audit-record shape) was confirmed with the maintainer
before code landed and shipped opt-in + default-off.

Working branch: `claude/trusting-curie-MRii3` (single PR).

Evidence tags: **[V]** verified against an authoritative source / tool result
this session, **[I]** reasoning from training knowledge, **[S]** suspected
pattern without confirmation.

Confidence: 50 | 70 | 80 | 90. Never 100.

---

## 1. Engagement metadata

| Field | Value |
|---|---|
| Repo | `rmednitzer/relay-shell` |
| Engagement date | 2026-06-01 |
| Project version | `0.1.0` |
| Default branch | `main` |
| Start HEAD | `1181a37` (#63) |
| Working branch | `claude/trusting-curie-MRii3` |
| Maintainer / single CODEOWNER | `@rmednitzer` |
| Trust-boundary modules (runbook §3.3) | `audit.py`, `redaction.py`, `policy.py`, `patterns.py`, `server.py::Relay.run`, `auth/oauth.py` |
| Phases executed | 0 (inventory), 1 (audit pass), 2 (findings), 3 (hardening), 4 (validation) |
| New ADR | [0007](../docs/adr/0007-audit-hash-chain.md) — tamper-evident audit hash chain (Accepted) |

This pack is a **frozen, point-in-time record** (per runbook §8.20). It is
the broader assurance counterpart to the ADR 0005 §"Validation outcome
(2026-06-01)" paragraph, which records the terse four-step upstream-surface
check.

---

## 2. Phase 0 — inventory snapshot

- Python `>=3.12`; CI matrix `3.12/3.13/3.14`; hatchling build; mypy
  `--strict`; ruff (lint + format); coverage floor 90% (CI gate). **[V]**
- 18 src `.py` files in `src/relay_shell/` (~4,528 LOC); 25 test files in
  `tests/` (~5,015 LOC); **7** ADRs in `docs/adr/` (0007 added this
  engagement). **[V]**
- 7 CI workflows: `ci.yml`, `codeql.yml`, `dependency-review.yml`,
  `nightly-fuzz.yml`, `pip-audit.yml`, `release.yml`, `sbom.yml`. **[V]**
- 21 MCP tools + 3 resources registered, matching
  `tests/test_server.py::_EXPECTED` and `docs/tools.md`. **[V]**
- 0 open issues; 0 open PRs at engagement start. **[V]**

---

## 3. Phase 1 — audit pass (ADR 0005 four-step)

Ran the repeatable validation pass end-to-end against the pinned upstream
surfaces. Full terse record in ADR 0005 §"Validation outcome (2026-06-01)".

| Step | Result | Tag |
|---|---|---|
| 1 Code index | 21 tools / 3 resources / 18 src / 25 test files, all cross-referenced sets equal | [V] |
| 2 Quality gates | `ruff check` + `ruff format --check` + `mypy --strict` clean; `pytest -q` 269 passed / 13 deselected; `pytest -m fuzz` 13 passed; `coverage` 92% (floor 90%) | [V] |
| 3 Upstream surface | `mcp==1.27.1` FastMCP kwargs, `Context` ids, 9 OAuth provider methods, `AuthorizationParams` / `OAuthToken` fields, 8 `asyncssh.connect` kwargs all resolve; `pydantic>=2.11` `model_validator` resolves | [V] |
| 4 Behavior | audit-record schema intact, hash-not-body holds, tier + redaction samples match ADR 0003 / docs | [V] |

No gate regressions. No capability regressions. The trust boundary
(ADR 0002) and tier semantics (ADR 0003) hold byte-for-byte.

---

## 4. Phase 2 — findings (2)

| ID | Sev | Module / location | Status | Resolution |
|---|---|---|---|---|
| F-005 | P3 (docs drift) | `docs/runbook.md` §5.1 | **fixed (this PR)** | C-005 (`Inventory` field naming) was still listed as an *open* consolidation candidate, but it landed in PR #57 (`Inventory(ssh_config=...)` ctor + `ssh_config_file` resolved-iff-exists property). Code carries no `ssh_config_path` **[V]**; CHANGELOG + `audit/2026-05-27-engagement.md` §2.2/§3 record the close. Moved the entry to §5.1 "Closed (do not re-add)". |
| G-1 | gap (not a regression) | `audit.py` integrity model | **closed (this PR)** | The audit log — ADR 0002's first compensating control — had no in-record tamper-evidence; integrity rested solely on `chattr +a` + off-host shipping, both defeatable by the documented `SECURITY.md` residual-risk attacker in the pre-ship flush window **[I]**. Closed by [ADR 0007](../docs/adr/0007-audit-hash-chain.md) (see §5). |

0 critical, 0 high, 0 medium. 1 P3 docs-drift (fixed), 1 hardening gap
(closed). The audit pass surfaced no security regression and no capability
regression against the documented behavior.

---

## 5. Phase 3 — hardening: ADR 0007 audit hash chain

**Decision** (confirmed with maintainer before code): add an opt-in,
additive per-record hash chain to the audit log so any edit / insertion /
deletion / reorder of the on-disk stream is detectable by recomputation.

| Aspect | Choice | Why |
|---|---|---|
| Default | **off** (`RELAY_SHELL_AUDIT_CHAIN=false`) | record byte-identical to v0.1; zero blast radius for existing deployments **[V]** |
| Shape | additive `seq` / `prev` / `chain` trailing fields | off-host parsers built on the prior shape keep working (same promise as ADR 0006) |
| Canonicalization | `SHA-256(prev ‖ json(record−chain, sort_keys))` | order- and formatter-independent; verifier reconstructs from a parsed line |
| Format gate | `jsonl` only; chain + `cef`/`leef` rejected at startup | chain resume re-parses the last record; SIEM formats own integrity their side |
| Restart / rotation | resume from last record's `seq+1` + `chain`; genesis seam on unreadable tail | rotation-safe; a reset is *visible*, never a silent gap |
| Concurrency | `seq`/`prev`/emit under one lock | ordering invariant holds if a future thread writes (ADR 0006 seccomp supervisor) |
| Verification | `relay-shell --verify-audit [--audit-path] [--json]` (CLI verb, **not** a tool) | forensic/operator action; keeps the 21-tool contract (`_EXPECTED`) unchanged |

**Surface touched** (18 files; +721/−24 before this pack):

- `src/relay_shell/config.py` — `audit_chain` setting + `model_validator`
  (`jsonl`-required). `src/relay_shell/audit.py` — chain emit/resume,
  `_chain_value`, `ChainResult`, `verify_chain`. `src/relay_shell/server.py`
  — pass `chain=`, additive `server_info.audit.{format,chain}`.
  `src/relay_shell/__main__.py` — `--verify-audit` / `--audit-path`.
- Tests (+19): `test_audit.py` (15 — emit/resume + 9 `verify_chain` tamper
  cases), `test_config.py` (3 — validator), `test_main.py` (2 — CLI),
  `test_tool_wrappers.py` (server_info field assertions).
- Docs: ADR 0007 (new), ADR 0005 outcome, `docs/adr/README.md` index +
  next-free `0008`, `.env.example`, `docs/deployment.md` §6a,
  `docs/architecture.md`, `SECURITY.md`, `docs/tools.md`, `docs/runbook.md`
  (§2.3, §3.2, §3.3, §5.1, §7.1, §7.5), `CHANGELOG.md`.

Closes runbook §7.5 **B-023**.

### 5.1 Threat model addressed

| Tamper | Detection | Tag |
|---|---|---|
| In-place edit of a record body | `chain` recompute mismatch at that line | [V] |
| Forged `chain` field | recompute mismatch | [V] |
| Deleted record | `seq` gap + `prev` linkage break at the next line | [V] |
| Reordered records | `seq` / linkage mismatch | [V] |
| Garbage line spliced into the region | JSON-decode break | [V] |
| Truncate-and-rewrite a clean chain from a host **holding no signing key** | NOT defended — out of scope; the off-host shipped prefix pins the hashes, and HMAC/Merkle anchoring is the recorded next step in ADR 0007 §"Rejected alternatives" | [I] |

---

## 6. Phase 4 — validation suite

| Gate | Result |
|---|---|
| `ruff check .` / `ruff format --check .` | clean **[V]** |
| `mypy` (`--strict`) | clean, 18 source files **[V]** |
| `pytest -q` | 269 passed, 13 deselected **[V]** |
| `pytest -m fuzz` | 13 passed **[V]** |
| `coverage` (subprocess collection) | 92% total (floor 90%); `config.py` 99%, `audit.py` 93%, `patterns/redaction/policy.py` 100% **[V]** |

Existing CI workflows unchanged this engagement; no new CI axis required
(the chain is exercised by `pytest`, not a new job).

---

## 7. Outstanding risks + recommended next steps

### 7.1 Outstanding (carried forward — operator action required)

| # | Priority | Action |
|---|---|---|
| F-G2 | **HIGH** | **Branch protection on `main`** is still not enabled (carried from the 2026-05-27 pack §8.1). Until it lands, CODEOWNERS is advisory, `main` accepts direct pushes, and signed-commits cannot be enforced. ~5 min GitHub Settings → Branches UI action. Recipe in the PR #57 description. **[S]** (not re-verified via API this session — reassert until closed). |

### 7.2 Deferred (tracked, low priority)

- **F-6** SFTP/connect explicit timeouts (`ssh_upload` / `ssh_download`):
  now tracked in runbook §7.1 (was only in the 2026-05-27 pack §8.2).
  Surgical follow-up PR.
- **B-021** seccomp-notify audit channel ([ADR 0006](../docs/adr/0006-seccomp-notify-audit-channel.md), Proposed).
- Phase-4 CI gates from the prior pack: P1-2 gitleaks, P1-5 commitlint,
  P2-1 pip-licenses, P2-3 require-signed-commits (blocked on F-G2).

### 7.3 Recommended next steps

1. Apply F-G2 branch protection (UI, ~5 min).
2. If a deployment ships audit off-host, enable `RELAY_SHELL_AUDIT_CHAIN`
   on a freshly rotated log and add a periodic `--verify-audit` of the
   shipped copy to the SIEM-side runbook.
3. Consider promoting ADR 0007 §"Rejected alternatives" HMAC/Merkle-anchor
   note to a backlog item if a key-holding-off-host integrity model is
   wanted (defends truncate-and-rewrite, which the plain chain does not).

---

## 8. Confidence statement

| Claim | Confidence |
|---|---|
| Audit pass gates green at HEAD + this PR | 90 |
| F-005 disposition (C-005 closed in #57, runbook stale) | 90 (verified against code + CHANGELOG + prior pack) |
| ADR 0007 chain correctness (emit/resume/verify/tamper) | 90 (each path has a passing test) |
| ADR 0007 default-off byte-identical claim | 90 (test asserts no `seq`/`prev`/`chain` keys when off) |
| F-G2 still open | 70 ([S] — not re-queried via API this session) |
| Engagement complete absent F-G2 application | 85 |

---

## 9. Sign-off

This engagement is complete. The repository's audit posture is materially
stronger:

- Full ADR 0005 validation pass re-run — all gates green, no regressions.
- 1 docs-drift finding fixed (F-005 / runbook §5.1 C-005).
- 1 hardening gap closed (G-1) via [ADR 0007](../docs/adr/0007-audit-hash-chain.md):
  opt-in tamper-evident audit hash chain + `relay-shell --verify-audit`,
  default-off and additive (no posture change, trust boundary unmoved).
- 19 new regression tests anchoring the chain and the config validator.
- Backlog reconciled: B-023 closed; F-6 promoted into runbook §7.1.

No further work is queued without an explicit follow-up request. The single
outstanding operator action (F-G2 branch protection) is carried forward
from the prior pack and reasserted here until it is closed.
