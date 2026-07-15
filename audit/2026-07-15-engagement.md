# Assurance engagement — 2026-07-15 (full audit + Vertex/Axiom comparison)

- **Baseline**: `rmednitzer/relay-shell` at `4256f73` (`main` HEAD at engagement
  start: PR #127 merged).
- **Branch**: `claude/relay-shell-audit-comparison-6j7y69`.
- **Scope**: a full repeatable validation pass (runbook §2 / ADR 0005 steps
  1–4), the dependency + static + secret scanner battery, a defensive review of
  the trust-boundary modules, **and** a comparative analysis of `relay-shell`
  against two sibling MCP control planes (referred to here as the *control
  plane* and the *data plane*) to identify concrete, in-scope lessons — the
  highest-value of which (a Tier-3 confirmation broker) is **implemented in this
  pass** under [ADR 0009](../docs/adr/0009-tier3-confirmation-broker.md).
- **Posture note**: `relay-shell` is, by design (ADR 0002), an unsandboxed,
  full-access shell/SSH server whose safety story is *compensating controls*
  (audit, tiered policy, redaction, resource bounds), not capability removal.
  Preserved capability is not a finding. The confirmation broker added this pass
  is a new compensating control layered on ADR 0003's classification; it removes
  no capability and is default-off (byte-identical when disabled).
- **This is a frozen, point-in-time record** (per runbook §8.20). Findings fixed
  in the engagement PR name that PR; deferred findings are tracked in
  `BACKLOG.md` and runbook §7. Frozen ADRs and prior engagement records are not
  retro-edited; only *living* docs (README status line + compatibility matrix,
  `docs/architecture.md` diagram) are reconciled for pin drift.

Every structural claim is tagged `[V]` verified in this session, `[I]` inferred,
or `[CI]` covered by CI but not reproduced locally.

---

## 1. Validation run (ADR 0005 steps 1–4)

Run on a clean Python **3.12.3** venv built from `pip install -e ".[dev]"`. The
container's default interpreter is 3.11, below the `>=3.12` floor; the venv was
rebuilt on 3.12 (a CI matrix leg) so the recorded surface is the supported one.
The **3.13 / 3.14** legs are `[CI]` (not reproduced locally). [V]

- **Step 1 (index)**: **22** MCP tools (== `tests/test_server.py::_EXPECTED` ==
  `docs/tools.md` == README), 3 resources (2 static + the `inventory/{host}`
  template), 1 prompt (`operating_guide`). The count moved 21 → 22 this pass:
  `operation_confirm` was added with the confirmation broker (ADR 0009). [V]
- **Step 2 (gates)**: `ruff check` ✓, `ruff format --check` ✓ (48 files),
  `mypy --strict` ✓ (20 source files), `pytest` **391 passed / 13 deselected**
  (up from 374; +17 broker/wiring tests), `pytest -m fuzz` **13 passed**,
  `coverage` **94 %** (floor 90 %; `broker` **100 %**, `metrics`/`policy`/
  `redaction` 100 %, `audit` 95 %, `server` 96 %). [V]
- **Step 3 (upstream surface)**: on the pinned `mcp==1.28.1` /
  `asyncssh==2.24.0` — the full OAuth token lifecycle, FastMCP tool/resource/
  prompt wiring, `Context` ids, and the `asyncssh` exec/SFTP/forward paths all
  resolve and pass their suites (the 391-test run exercises them). [V] The pin
  has moved since the last engagement (`mcp` 1.27.2 → 1.28.1, `asyncssh` 2.23.1
  → 2.24.0) via Renovate; the *living* docs still named the old pin — see
  finding **DOC-1** below. [V]
- **Step 4 (behavior)**: a real `shell_exec` call produced an audit record with
  the intact schema (`ts, tool, tier, denied, args, output_sha256, output_len,
  exit_code`) and the output referenced by SHA-256 + length only — no raw
  output-body field. With the broker **off** (default) a Tier-3 command
  (`rm -rf …`) runs and its record carries **no** `action` field
  (byte-identical); with the broker **on** the same command is challenged
  (`action=confirm_plan`, no side effect), and after `operation_confirm` +
  re-issue it executes (`action=confirm_execute`). [V]

## 2. Security scanner battery — all clean [V]

| Scanner | Target | Result |
|---|---|---|
| **pip-audit** (OSV / PyPA, `--no-deps` on pinned reqs) | `requirements.txt` | No known vulnerabilities |
| **trivy fs** (vuln) | whole tree | 0 vulnerabilities |
| **trivy fs** (secret) | whole tree | 0 secrets |
| **bandit** (`-ll`) | `src/` | 0 High, 0 Medium, 12 Low (all benign, unchanged class from prior passes) |
| **semgrep** (`p/python`, isolated via `uvx`) | 20 git-tracked src files | 0 findings (151 rules) |
| **actionlint** | 8 workflows | 0 issues |
| **shellcheck** (`-S style`) | `deploy/install.sh`, `install-edge.sh`, `scripts/healthcheck.sh` | 0 issues |
| **gitleaks** | full history | `[CI]` — the pinned `gitleaks` job (`.github/workflows/gitleaks.yml`) covers this; the Go binary is not present in this container, so not reproduced locally |

No pinned dependency carries a known CVE at its pinned version. `pip-audit`'s
default resolver path failed operationally (isolated-build pip upgrade blocked
in this container); `--no-deps` on the fully-pinned `requirements.txt` and the
independent `trivy` vuln scan both corroborate the clean result. [V]

## 3. Dependency & supply-chain review

The pinned runtime set: `mcp==1.28.1`, `pydantic==2.13.4`,
`pydantic-settings==2.14.2`, `asyncssh==2.24.0`, `uvicorn==0.49.0`,
`starlette==1.3.1`, `anyio==4.14.1`, `httpx==0.28.1`, `PyJWT==2.13.0`,
`cryptography==48.0.1`. Every pin is at or past its advisory-fixed minimum, and
the `pyproject.toml` floors (`asyncssh>=2.23.0`, `starlette>=1.3.0`,
`PyJWT>=2.13.0`, `cryptography>=48.0.1`) still bound a cold resolve to the safe
range (SEC-3, closed 2026-06-21). No new floor regression this pass. [V]

## 4. Trust-boundary review

Walked the runbook §3.3 security-sensitive surface. The one behavioral change
this pass is the confirmation broker; it is reviewed against its own ADR 0009
invariants and found to hold:

- **Deny/mode-first, never a bypass** — the gate is consulted only *after*
  `policy.check` admits the call, and only for `Tier.IRREVERSIBLE`. A denied or
  `readonly`/`guarded`-refused call never reaches the broker. [V]
- **Default-off byte-identical** — `Relay.broker is None` unless
  `RELAY_SHELL_CONFIRM_TIER3=true`; the new optional `action` field is written
  only when non-empty (like `request_id`/`client_id`), so the default record and
  the ADR 0007 hash chain are unchanged. Verified: a default-off Tier-3 record
  has no `action` key. [V]
- **Single-use + TTL + exact-operation binding** — tokens are bound to
  `sha256(tool \0 policy_text)` (every executor-visible byte), single-use
  (burned on consume), and TTL-bounded; a mismatched/expired/bad token
  re-challenges. Verified by `tests/test_broker.py`. [V]
- **Raw token never logged** — `operation_confirm` audits only a token
  fingerprint; the raw token appears nowhere in the audit file. Verified. [V]
- **Label cardinality bounded** — the new `confirm_required` metric outcome is a
  fixed constant, not user-controlled; the `/metrics` cardinality invariant
  holds. [V]

The remaining trust-boundary modules (`patterns`, `redaction`, `audit` chain,
`auth/oauth`, `seccomp`) are unchanged by this pass; their prior `[V]` status
stands and the scanner battery + full suite re-confirm no regression. [V]

## 5. Findings & dispositions

| ID | Severity | Finding | Disposition |
|---|---|---|---|
| **DOC-1** | low (doc) | Living docs named the superseded pin (`mcp==1.27.2`, `asyncssh` "tested at 2.23.1", floor `>=2.18`) after Renovate moved the pins to `mcp==1.28.1` / `asyncssh==2.24.0` (floor `>=2.23.0`). | **Fixed this PR.** Reconciled the README status line + compatibility matrix and the `docs/architecture.md` diagram; "last validated" date → 2026-07-15. Frozen ADRs / prior engagement records left intact per convention. |
| **ENV-1** | info | `.env.example` should gain `RELAY_SHELL_CONFIRM_TIER3` / `RELAY_SHELL_CONFIRM_TTL` to mirror `Settings` and `docs/deployment.md` §8a (runbook §3.1 checklist). | **Deferred (env constraint).** The audit environment blocks all access to `.env*` paths, so the file could not be edited in this session. The settings carry safe defaults, so nothing breaks; tracked as a one-line follow-up in `BACKLOG.md`. |

No P0/P1, no critical/high/medium security finding; the scanner battery and
steps 1–4 are clean.

## 6. Comparative analysis — lessons from the control/data planes

The two sibling MCP servers in the operating environment implement a materially
different safety and observability model. Each candidate lesson is tagged
**adopt** / **adapt** / **defer** / **reject** with rationale, so scope stays
honest and capability is preserved (CLAUDE.md "when uncertain").

| # | Lesson (origin) | `relay-shell` gap | Disposition |
|---|---|---|---|
| **L1** | **plan → authorize → execute broker** — a privileged/irreversible op returns a single-use, TTL token; a distinct authorize step must intervene before execution. | Single-pass allow/deny in `Relay.run`; a Tier-3 op is either run with no friction (`open`) or refused wholesale (`guarded`) — no per-call confirmation middle ground. | **ADOPT — implemented this pass** (ADR 0009; §1/§4 above). Adapted to `relay-shell`'s idiom: opt-in, default-off, centrally gated, bound to the operation hash. |
| **L2** | **in-band `audit` tool** — chain-verify + correlate-by-input-hash exposed as a live tool (query, verify, correlate actions). | `relay-shell --verify-audit` is CLI-only and `audit_tail` only lists; there is no in-band verify or correlate-by-input-`sha256`. | **ADAPT → backlog `AUD-1` (P2).** A read-only `audit_verify`/correlate tool mirroring `audit_tail`'s wiring (Tier 0, stable audit `tool` name). Kept off this PR to bound scope; the CLI verify already covers the operator/forensic path (deliberately off the tool surface per ADR 0007 — the tradeoff must be weighed in the ADR the new tool would need). |
| **L3** | **deploy-host HIDS** — file-integrity + config-drift monitoring (etckeeper / AIDE / fail2ban / lynis) around the service. | `deploy/` hardens systemd + Caddy CIDR + logrotate but the docs do not cover host-integrity / config-drift monitoring for the deployment host. | **ADOPT (docs-only) → backlog `DOC-6` (P2).** A `docs/deployment.md` hardening subsection; in scope per the CLAUDE.md GitHub checklist ("docs clearly explain secure deployment"). No code. |
| **L4** | **KEV/EPSS dependency intel** — a CVE store carrying Known-Exploited + exploit-probability signal for prioritization. | `pip-audit` gates on CVE *presence* with no exploit-in-the-wild prioritization. | **DEFER → backlog `OPS-2` (P3).** Advisory enrichment only: `pip-audit` already fails closed, so this is prioritization, not a gate. Low value for a small, tightly-pinned dependency set; revisit if the set grows. |
| — | Semantic search over docs/audit, scheduled briefings, multi-host fleet orchestration, local-inference data plane. | Out of scope for a focused single-purpose shell/SSH server (ADR 0001's single-process architecture). | **REJECT** (recorded so the comparison is complete, not silently dropped). |

The through-line: the sibling planes treat **consequential actions as
multi-step, independently-verified events** rather than single admissions.
`relay-shell` already embodies this for *observability* (hash-chained audit,
seccomp-notify); L1 extends it to *admission* for the irreversible tier, which
is the single most valuable transfer. L2/L3 extend the *observability* and
*deployment* stories incrementally.

## 7. Commits in this pass

Kept in two commits per the charter (implementation vs audit evidence):

1. **Feature (ADR 0009 confirmation broker)** — `src/relay_shell/broker.py`
   (new), wiring in `config`/`audit`/`policy`/`metrics`/`server`, the
   `operation_confirm` tool, `tests/test_broker.py` (new), the tool-contract
   bumps (`_EXPECTED`, stdio-e2e count), and the doc set (ADR 0009 + index,
   `docs/tools.md`, README, `architecture.md`, `deployment.md` §8a,
   `CHANGELOG.md`, `_INSTRUCTIONS` / `_OPERATING_GUIDE`). Plus the DOC-1
   living-doc pin reconciliation.
2. **Audit evidence** — this document + the `BACKLOG.md` / runbook §7 entries
   for AUD-1 / DOC-6 / OPS-2 / ENV-1.

## 8. Residual risk statement

- The **unsandboxed full-access posture** (ADR 0002) is unchanged and remains
  the defining risk. The confirmation broker adds friction to the irreversible
  tier but does not reduce capability: a client fully in control can call
  `operation_confirm` itself. Its value is deliberate, audited friction against
  single-turn persuasion, not a sandbox.
- Tier classification is heuristic (ADR 0003); the broker is only as precise as
  the tier, so it is an *additional* guardrail on top of the deny list, never a
  replacement. This is stated in ADR 0009 and `docs/deployment.md` §8a.
- The **3.13 / 3.14** CI legs and the **gitleaks** job were not reproduced
  locally (`[CI]`); they remain covered by CI per the workflows.
- `.env.example` could not be updated in this environment (ENV-1); the two new
  vars have safe defaults, so the omission is cosmetic pending the follow-up.

## 9. Methodology

Every metric and finding above is backed by a command run in this session. No
destructive or irreversible operation was performed on the repository; no
dependency was bumped; no history was rewritten; no frozen record was edited.
The audit evidence (this doc + backlog) is committed separately from the
implementation, per the charter.
