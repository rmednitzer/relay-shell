# Backlog follow-up — 2026-08-04 (EVID-1, PERF-4)

- **Baseline**: `rmednitzer/relay-shell` at `e5da318` (`main` after PR #159, the
  2026-08-04 audit pass).
- **Branch**: `claude/vertex-relay-audit-gaps-fb6e2k` (restarted from `main`
  after #159 merged).
- **Scope**: close the two items the 2026-08-04 audit pass
  (`audit/2026-08-04-engagement.md`) deferred — **EVID-1** (audit-evidence
  verifier ordering + torn-write) and **PERF-4** (single-host unbounded output
  buffering). Both are gaps in the compensating controls (audit integrity and
  resource bounds), not a break of the intentional unsandboxed posture
  (ADR 0002).
- **Posture note**: no returned-output or protocol behaviour changes. PERF-4
  bounds only relay-internal memory (output stays byte-identical after the
  existing truncation, exit codes preserved, commands run to completion); EVID-1
  changes only the deploy-side verifier's ordering + torn-tolerance.
- **Frozen record** (runbook §8). The prior engagement record is not
  retro-edited; this is its follow-up.

`[V]` = verified in this session (test-run); `[I]` = inferred.

---

## 1. EVID-1 — audit-evidence verifier ordering + torn-write (MED)

**Gap** (from the 2026-08-04 pass). `deploy/evidence/relay-audit-evidence.py`
sorted retained segments by filesystem `st_mtime_ns`. logrotate `compress` +
`delaycompress` (the shipped `deploy/logrotate/relay-shell`) rewrites a rotated
segment's mtime when it is gzipped on a *later* cycle, which can push an older
segment's mtime past the live segment's and invert the order — the cross-segment
seam check then compares the wrong adjacent pair and reports a spurious
`"broken rotation seam"`. Separately, the glob matches the live, concurrently-
appended `audit.jsonl` and `lines()` opened it `errors="strict"`, so a read
racing an in-progress append (a torn final record, or a torn multibyte) failed
the run as `"invalid JSON"` / a read error. Either false failure makes
`relay-audit-evidence-sync` — which gates the off-host publish on the verifier's
exit status — silently skip the off-host copy, defeating the anti-tail-
truncation control (ADR 0007) the tooling exists to provide.

**Fix** `[V]`.

- **Two-phase verification.** New `verify_segment(path)` verifies each segment in
  isolation (chain-hash recompute, `seq` monotonicity, `prev` linkage — all
  order-independent), returning `(first, last, count, torn_tail, errors)`.
  `main()` runs phase 1 over all segments, then **phase 2 orders them by the
  first record's `ts`** — the chain-authoritative chronological key, which
  logrotate cannot corrupt — before the cross-segment seam / genesis-anchor /
  approved-reset logic. `ts` ordering is correct within an epoch (records are
  written in time order, so `first_ts` rises with `seq`) *and* across an approved
  genesis reset (where `first_seq` returns to 0 and cannot order epochs);
  `first_seq` then the file name are stable tiebreakers.
- **Torn-tail tolerance.** A JSON parse failure on the **last** non-empty line of
  the **live** segment (`audit.jsonl`) is deferred and, if nothing follows it,
  tolerated as an in-progress append (counted in a new `torn_tails` evidence
  field for visibility). A parse failure anywhere else — or on any rotated
  segment — stays a hard error. The live segment is read `errors="replace"` so a
  torn multibyte in that tail cannot abort the whole segment; rotated segments
  stay `errors="strict"` so genuine corruption still surfaces.

**Tests** (`tests/test_evidence_deploy.py`, driving the verifier as a subprocess
against constructed chained logs, reusing the script's own `canonical_chain` for
byte-exact hashes):

- `test_verifier_orders_segments_by_record_ts_not_mtime` — rotated segment given
  a *newer* mtime than the live one (the delaycompress inversion): verifies clean
  and in chain order. Pre-fix this reported a broken seam. `[V]`
- `test_verifier_tolerates_torn_final_line_on_active_segment` — a torn trailing
  record on `audit.jsonl`: `valid=true`, `torn_tails=1`, only complete records
  counted. `[V]`
- `test_verifier_flags_malformed_line_that_is_not_the_tail` — garbage between two
  valid records: `valid=false`, `torn_tails=0`. `[V]`
- `test_verifier_does_not_tolerate_torn_tail_on_rotated_segment` — a partial
  final line on a rotated segment is genuine truncation: `valid=false`. `[V]`

## 2. PERF-4 — single-host unbounded output buffering (info → MED)

**Gap.** `shell_exec` / `shell_script` drained the local child with
`proc.communicate()` (buffers the entire output), and `ssh_exec` called
`SshPool.run` without `max_output_bytes` (`cap is None`, the unbounded path).
`max_output` truncation ran only *after* the full body was in memory, so a
single high-volume producer (`cat /dev/zero`, a runaway build log) grows the
long-lived relay process without bound — a memory DoS. It is reachable by a
Tier-1 command that even `guarded` mode permits (guarded refuses Tier ≥ 2), so
it crosses a mode boundary; upgraded from the info rating the audit pass gave it.
The interactive/PTY paths were already bounded (`session_buffer_bytes`) and
`ssh_fanout` already passed a cap — this was the one-shot asymmetry.

**Fix** `[V]`. `shelltools._drive` now:

- Drains stdout (and stderr, when not merged) to EOF keeping at most
  `output_cap` bytes across a **shared** budget, discarding the rest — the same
  bounded-drain discipline `SshPool.run` already used, so relay memory is bounded
  while the child still runs to completion (exit code and true length preserved).
- Feeds stdin **concurrently** with the drain (one `asyncio.gather`, so a
  `wait_for` timeout cancels every child task together), so a large stdin cannot
  deadlock against a bounded output drain.

The server passes `output_cap = max_output_hard` (the existing absolute ceiling)
to `run_command` / `run_script`, and `max_output_bytes = max_output_hard` to
`SshPool.run` via `ssh_exec`. The returned output is **byte-identical**: the
server already truncates to `clamp_output(max_output) ≤ max_output_hard`, so the
discarded bytes were never returned. The only observable change is that the
truncation marker's "total bytes" count is capped at `max_output_hard` when the
true output exceeds it (an advisory count on an already-truncated response).
Timeout semantics unchanged. `output_cap=None` preserves the historical
unbounded path (default for direct `run_command`/`run_script` callers/tests).

**Tests** (`tests/test_shell.py`):

- bounded buffer under a small cap with a large producer (`head -c … /dev/zero`);
- exit code preserved when a nonzero exit follows large output;
- stdin still delivered under a cap; a 500 KB stdin does **not** deadlock;
- shared stdout+stderr budget (`merge_stderr=false`, combined ≤ cap);
- `output_cap=None` unbounded (byte-for-byte historical behaviour);
- `run_script` bounded too. `[V]`

## 3. Gate

`ruff check .`, `ruff format --check .`, `mypy src/relay_shell`, and `pytest -q`
all clean. Coverage unchanged vs baseline in this environment (integration /
seccomp-live tests need a full host; CI floor 90%).

## 4. Remaining open backlog (correctly deferred, not actioned)

- **BRK-2** (P3) — rollback/verify broker: ADR 0010 **decides to defer** until a
  concrete trigger (an autonomous/unattended deployment, or an operator ask for
  operation-bound remediation that survives the turn). No such trigger exists;
  implementing it now would contradict the accepted ADR.
- **B-025** (P3) — `aarch64` seccomp-notify: requires validating the notify
  round-trip on a live `aarch64` host, unavailable here.
- **OPS-2** (info) — KEV/EPSS layering on `pip-audit`: explicitly declined as low
  value for the small pinned set; `pip-audit` already fails closed.
- **PERF-1/2/3** (P3) — audit write offload, `_sweep_conns` O(n)-under-lock,
  `Session.buffer` front-deletion: the project's disposition is "measure before
  acting — none on a hot path." No measurement shows a hot path, so unchanged.
- **DOC-5** (info) — Keep-a-Changelog version-compare links: deferred until a
  second release is tagged ("omit rather than fake"); only v0.3.0 exists.
- **`.env.example` `RELAY_SHELL_MAX_CONNS` mirror** — the `.env*` path is denied
  to this session (the same restriction ENV-1 hit); `Settings` +
  `docs/deployment.md` carry it. A trivial follow-up when the path is writable.
