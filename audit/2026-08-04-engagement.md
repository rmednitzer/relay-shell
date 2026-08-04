# Adversarial engagement — 2026-08-04 (audit + gap analysis)

- **Baseline**: `rmednitzer/relay-shell` at `edf72ae` (`main` after PR #158,
  cryptography v50).
- **Branch**: `claude/vertex-relay-audit-gaps-fb6e2k`.
- **Scope**: a fresh in-depth repo audit and adversarial review across the
  trust-boundary core (policy/patterns/redaction/audit/broker + the `Relay.run`
  dispatch), the SSH/session/seccomp runtime, the OAuth/edge surface, and the
  newest deploy tooling (the 2026-07 evidence + host-monitoring additions from
  PRs #155–#157, the least-audited code in the tree). Gap analysis against the
  CLAUDE.md trusted references (GitHub Actions hardening, OWASP logging, MCP).
- **Posture note**: `relay-shell` is, by design (ADR 0002), unsandboxed — the
  service account is the trust boundary and the safety story is *compensating
  controls* (audit, tiered policy, redaction, resource bounds). Every finding
  here is a gap **in those controls**, not a break of the intentional posture.
  No P0/P1: no remote-unauthenticated RCE, no auth-bypass-without-a-secret, no
  secret-leak to the audit log. Four MEDIUM defence-in-depth / correctness gaps,
  three fixed in this PR and one deferred with a design.
- **Frozen record** (runbook §8). Fixed findings name this PR; the frozen ADRs
  and prior engagement records are not retro-edited.

`[V]` = verified in this session (code-traced / test-run); `[I]` = inferred.

---

## 1. Findings & resolutions

| ID | Sev | Finding | Fix |
|----|-----|---------|-----|
| **CONN-1** | MED | **`SshPool._conns` had no hard ceiling.** `max_sessions` (registry) and `max_forwards` (`SshPool._forwards`, closed as SSH-3) both check-under-lock before admitting a new entry; the connection cache *underneath* them had no equivalent cap. Eviction was purely idle-timeout-based (`ssh_idle_timeout`) and only opportunistic — `_sweep_conns()` runs at the top of the *next* `connect()`, so nothing bounded how many distinct live SSH sessions could accumulate. A caller varying the target (or per-call `user`/`port`/`key_path`) across many real reachable hosts grows the cache (fds/memory) unbounded between sweeps. Same resource-growth class SSH-3 closed for forwards, left open for the cache beneath it. `[V]` | `config.py`: new `RELAY_SHELL_MAX_CONNS` (default 256, `ge=1, le=4096`), mirroring `max_forwards`. `sshpool.py`: `connect()` evicts the least-recently-used **unpinned** entry before caching (new `_select_conn_evictions`); a pinned (in-use) connection is never evicted, so the cap is transiently exceeded rather than dropping a live connection. Surfaced in `server_info.config.max_conns`. Tests: cap-enforced-and-LRU-closed, pinned-never-evicted, upper-bound rejected. |
| **CONN-2** | MED | **`SshPool.run()` output cap was applied per-stream, not combined.** The bounded drain budgeted stdout and stderr against **independent** `out_kept`/`err_kept` counters, so peak transient memory per call was up to **2× `max_output_bytes`** before the post-drain `truncate` trimmed the returned string. The final response was still correctly bounded, but `ssh_fanout`'s careful per-host sizing math (server.py) assumes a footprint of `cap`, not 2×cap, across up to 32 concurrent hosts. `[V]` | `sshpool.py`: one shared `kept` budget passed to both `_drain` calls, so combined buffered bytes stay within `cap`. The read/write of `kept[0]` has no `await` between them, so the two concurrent drains never interleave in that window. Test: both streams over cap → combined kept ≤ cap. |
| **EDGE-3** | MED | **Edge omitted `/revoke` from the pre-CIDR allowlist.** The OAuth provider enables revocation (`RevocationOptions(enabled=True)`, `oauth.py:404`), so the SDK mounts `POST /revoke` and advertises `revocation_endpoint` in the discovery metadata. The Caddyfile handled `/authorize`, `/register`, `/token`, `/mcp`, and the two `.well-known` paths before the CIDR block — but **not** `/revoke`. A remote MCP client that registered, authorized, and obtained a token through the public edge (the ChatGPT use case EDGE-1 exists for) gets a flat `403` when it tries to self-revoke a leaked bearer token — the operator would have to hand-edit `tokens.json`. A security-control-reachability gap that undermines client-side incident response. `[V]` | `deploy/Caddyfile`: a `handle /revoke` block before the `@blocked` CIDR gate, mirroring `/token`. RFC 7009 requires presenting the token being revoked, so public reachability is safe. Drift test: `/revoke` handled before `@blocked`. |
| **EVID-1** | MED | **Audit-evidence segment ordering + torn-write (deferred, design below).** `deploy/evidence/relay-audit-evidence.py` sorts retained segments by filesystem **mtime** (`st_mtime_ns`), which the shipped logrotate config (`compress` + `delaycompress`) can invert — a rotated segment's mtime is rewritten when it is later gzipped, which can land after the current segment's mtime, so the cross-segment seam check compares the wrong adjacent pair and reports a spurious `"broken rotation seam"`. Separately, the glob matches the **live** `audit.jsonl` and `lines()` opens it `errors="strict"`, so a read landing mid-write on the final record marks the whole run `valid: false`. Because `relay-audit-evidence-sync` gates the off-host publish on `verify_status == 0`, either failure **silently suppresses the off-host copy** — the exact anti-tail-truncation control this tooling exists to provide (ADR 0007). `[V]` | **Deferred** to a focused follow-up (see §3 and `BACKLOG.md`): the correct fix is a two-phase restructure (verify each segment independently, then order by `first_seq` for the seam checks) plus tolerating a single torn *final* line on the active segment. It needs dedicated multi-segment tests and is out of scope for this pass's surgical fixes. |

Ruled out (checked, not exploitable / by-design, `[V]`):

- **Redaction `_WHOLE_MATCH_HINTS` gate completeness** (PR #156). The substring
  gate that skips the whole-match provider-token table when no anchor is present
  was cross-checked against every pattern in `REDACTION_PATTERNS`: each pattern's
  mandatory literal anchor (`-----BEGIN `, `ghp_`/`gho_`/`ghu_`/`ghs_`/`ghr_`,
  `gith_pat_`/`github_pat_`, `sk-`, `hf_`, `AKIA`, `xox`, `hooks.slack.com/…`,
  `AIza`, `ya29.`, `sk_`/`rk_`, `glpat-`, `npm_`, `pypi-`, JWT `ey`) is present in
  the hint tuple. No pattern can match hint-free text, so the gate cannot skip a
  real secret. Correct.
- **Audit chain vs non-JSONL format.** `verify_chain` parses each line as JSON;
  a CEF/LEEF chained log would verify zero records. Already guarded — the
  `config.py` model validator `_v_chain_requires_jsonl` rejects
  `audit_chain=true` with a non-`jsonl` format at startup, and the
  `--verify-audit` CLI fails closed on `records == 0`. Triple-defended.
- **Unbounded single-host output buffering** (`shell_exec`/`shell_script` via
  `communicate()`, and `ssh_exec` calling `SshPool.run` with `max_output_bytes`
  unset → `cap is None`). Real unbounded-memory property, but symmetric between
  the local and SSH single-host paths and consistent with the no-sandbox posture
  (the interactive/PTY paths *are* bounded by `session_buffer_bytes`, and
  `ssh_fanout` passes a cap). Left as an existing documented design property, not
  a regression; noted in `BACKLOG.md` as a hardening opportunity.
- **`Relay.run` dispatch, broker, policy/tier, OAuth (PKCE/redirect/refresh),
  metrics, seccomp BPF, sessions, inventory** — re-verified against the installed
  `mcp` SDK and existing regression tests; no new issue. AUTH-1/2/3, SEC-6/7/8,
  SSH-1/2/3/4, SSRF-1/2, EDGE-1/2, RED-1..8, POL-1/2 all present and unregressed.
- **CI/GitHub Actions posture** — every workflow pins actions by full SHA with a
  version comment and runs least-privilege (`permissions: contents: read` at the
  workflow level, job-level escalation only where a step needs it). Matches the
  GitHub Actions hardening reference; no gap.

## 2. Fixes landed in this PR

- **CONN-1** — `RELAY_SHELL_MAX_CONNS` connection-cache ceiling with LRU-unpinned
  eviction (`config.py`, `sshpool.py`, `server_info`); tests in
  `tests/test_sshpool_unit.py` + `tests/test_config.py`.
- **CONN-2** — shared stdout+stderr output budget in `SshPool.run`
  (`sshpool.py`); test in `tests/test_sshpool_unit.py`.
- **EDGE-3** — `/revoke` handled before the CIDR gate (`deploy/Caddyfile`); drift
  test in `tests/test_verifier.py`.
- **Docs** — CHANGELOG `[Unreleased]`; runbook §7 backlog reconciled (FMT-2 was
  closed in PR #111 but still listed open) and the new items registered.

Gate: `ruff check`, `ruff format --check`, `mypy`, and `pytest` all clean;
coverage unchanged vs baseline in this environment (integration/seccomp-live
tests need a full host; CI floor 90%).

## 3. Deferred — EVID-1 design (for a focused follow-up)

The evidence verifier conflates *file discovery order* with *chain order*. The
fix:

1. **Read + intra-segment verify each file independently** (order-independent):
   collect `(first, last, count, per-file errors)` per segment. Intra-segment
   checks (`seq` monotonic, `prev == prior chain`, body-hash recompute) do not
   depend on cross-file ordering.
2. **Order the segments by `first_seq`** (self-describing from the chain), not by
   mtime, before running the cross-segment seam continuity + genesis-anchor +
   approved-reset logic. This removes the logrotate `delaycompress` mtime-inversion
   failure entirely.
3. **Tolerate a single torn final line on the active (non-`.gz`) segment**: a
   JSON/Unicode error on the *last* line of the currently-appended file is the
   expected torn-write, not corruption — skip it rather than failing the run. A
   malformed line anywhere else stays fatal.

New tests: multi-segment out-of-mtime-order (must verify clean), a torn final
line on the active segment (must stay valid), and a genuinely broken interior
line (must fail). Because `relay-audit-evidence-sync` gates the off-host publish
on the verifier's exit status, this directly restores the availability of the
anti-tail-truncation control.
