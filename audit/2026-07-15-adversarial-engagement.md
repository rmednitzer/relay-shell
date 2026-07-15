# Adversarial engagement — 2026-07-15 (red-team + performance)

- **Baseline**: `rmednitzer/relay-shell` at `d623ca8` (`main` after PR #128 +
  #129 merged).
- **Branch**: `claude/relay-shell-audit-comparison-6j7y69`.
- **Scope**: a fresh adversarial pass over the trust-boundary modules
  (redaction/audit, policy/tier/broker, SSH/OAuth/edge) **plus** a performance
  profiling pass, prompted by the question "is everything lean, secure,
  performant?". Every finding was reproduced with a runnable PoC or a measured
  benchmark before the fix and re-checked after; PoC scripts are under the
  session scratchpad, and the before/after evidence is inlined below.
- **Posture note**: `relay-shell` is, by design (ADR 0002), unsandboxed — the
  service account is the trust boundary and the safety story is *compensating
  controls* (audit, tiered policy, redaction, bounds). Every finding here is a
  gap **in those controls**, not a break of the intentional posture. One is
  HIGH (a redaction bypass leaking secrets to the audit log); the rest are
  MEDIUM defence-in-depth gaps and one performance defect.
- **Frozen record** (runbook §8.20). Fixed findings name this PR; the frozen
  ADRs and prior engagement records are not retro-edited.

`[V]` = verified in this session (PoC/benchmark run); `[I]` = inferred.

---

## 1. Findings & resolutions

| ID | Sev | Finding | Fix |
|----|-----|---------|-----|
| **RED-6** | **HIGH** | **JSON-quoted-key secret leak.** The generic keyword redaction rule and the AWS `secret_access_key` rule required `keyword\s*[:=]`, so a JSON-quoted key (`"password": "x"`, `"AWS_SECRET_ACCESS_KEY": "x"`) never anchored and the value was written **verbatim** to the audit log. Only the `Authorization` rule was quote-tolerant. `env_json` (a JSON env map) and JSON in `command`/`stdin` are the common delivery shapes; the AWS secret has no whole-match fallback. Defeats the "safe to ship off-host" promise (`redaction.py` module docstring). | `patterns.py`: quote-tolerant separator (`["']?` each side) + a non-space/non-quote value run (`[^\s"'\r\n]+`) on the generic + AWS rules. Redacts the JSON shape, preserves the closing quote, and is **linear** (see RED-6a). `PATTERNS_VERSION` 7→8. |
| **RED-6a** | **HIGH (introduced-and-fixed in this PR)** | The first RED-6 draft used a quoted-value lookahead (`[^"'\r\n]+(?=["'])`); on an **unquoted** value it backtracked char-by-char, and because the keyword prefix recurs O(n) times in a large quote-free argument this was **O(n²) — a ReDoS on the synchronous audit path**. Caught by the performance pass, not by unit tests. | Replaced with the linear char-class value run above. Measured: `redact()` on 1 MB of `DB_PASSWORD=…` went **165 s (lookahead) → 196 ms (shipped, linear)**; scaling is now 4×-in→4×-out. |
| **SSH-4 (F2)** | MED | **Deny-list blind to host for the RCE tools.** `RELAY_SHELL_POLICY_DENY` is the documented way to block an SSH tool from a host (e.g. the cloud-metadata IP); the transfer/scan tools fold the host into the deny probe (SEC-1/SSRF-2) but `ssh_exec`/`ssh_spawn`/`ssh_fanout` used command-only text and `ssh_check` sent none — so the block silently failed for exactly the tools that grant remote execution. | `server.py`: `_policy_text_ssh_exec/_ssh_spawn/_ssh_fanout` fold the destination host (canonical-IP-widened, SSRF-1/2) into the probe; new `_policy_text_ssh_check`. Same accepted SEC-1 tier-over-classification tradeoff, documented in the builders. |
| **BRK-3 (F3)** | MED | **Broker confused-deputy via SSH identity.** The ADR-0009 op-key binds `policy_text + audit_args`, but `ssh_exec`/`ssh_spawn` audit_args omitted `user`/`port`/`key_path` — so a confirmed token could be re-issued with a swapped credential (readonly→root) against the same host+command, and the `confirm_plan` record hid which credential would run. Same class as SR-1, not previously extended to the identity trio. | `server.py`: added `user`/`port`/`key_path` to the ssh_exec/ssh_spawn audit_args — closing the op-key gap **and** surfacing the credential in the audit record. |
| **POL-2 (F4)** | MED | **Tier heuristic missed non-obfuscated long options.** `TIER3_PATTERN` matched `rm -rf` but not `rm --recursive --force` (both alternatives required a single dash right after `rm `). Under-classified a legitimate destructive command → permitted in `guarded`, skipped the broker gate. (Pure shell obfuscation like `r''m`/`${IFS}` is separately by-design/documented — out of scope.) | `patterns.py`: a **bounded** long-option `rm` alternative (`rm\s+(?:\S+\s+){0,16}?--(?:recursive\|force\|no-preserve-root)`). The `{0,16}` bound avoids an O(n²) rescan of `rm rm rm …`. `PATTERNS_VERSION` 7→8 (RED-7). |
| **P1** | MED | **Redaction scanned the full untruncated argument on the event loop**, before the `max_len` truncation, synchronously — so a multi-MB `command`/`stdin`/`env_json` cost real wall-clock on the async loop, per call. | `redaction.py`: `_scrub_str` bounds the scan to `max_len + 16 KiB` (> the 8 KB PEM bound), since only the first `max_len` chars survive truncation. **No** change to what is redacted (the dropped tail is truncated out of the record regardless). Measured: `redact_args` on a 1–4 MB arg is now **constant ~12 ms** (was superlinear). |

Ruled out (checked, not exploitable, `[V]`): ReDoS in the CLI-flag / PEM / MySQL
patterns (measured linear to 5 MB; PEM already length-bounded, RED-2); audit
hash-chain forgery (needs filesystem write the service account holds by design);
confirmation-token exposure (the raw token is never logged — the record stores
only `sha256(output)`; `operation_confirm` logs a one-way 12-hex fingerprint);
OAuth token-type confusion / SSRF-1/2 / EDGE-1/2 / SSH-1/2/3 / AUTH-2 (all
previously closed — re-verified no regression). Lower-priority perf items
observed but deferred (see `BACKLOG.md`): the synchronous audit write on the
loop (vs the offloaded read), `SshPool._sweep_conns` O(n) under lock, and the
`Session.buffer` front-deletion — all small and not on any measured hot path.

## 2. Before/after evidence [V]

```
RED-6  redact('{"AWS_SECRET_ACCESS_KEY":"wJalr…","DB_PASSWORD":"Sup3r$ecretPW!"}')
   before:  …"wJalr…", …"Sup3r$ecretPW!"   (verbatim — LEAK)
   after :  …"[REDACTED]", …"[REDACTED]"    (compact multi-field preserves "host":"db")
RED-6a redact() on 1 MB recurring `DB_PASSWORD=`:   165 s → 196 ms (linear)
P1     redact_args() on 1 MB / 4 MB arg:            superlinear → ~12 ms (constant)
POL-2  classify('rm --recursive --force /data'):    REVERSIBLE(1) → IRREVERSIBLE(3)
       classify('rm rm rm …' 600 KB, no --force):   bounded, ~0.5 s (was O(n²))
SSH-4  Policy(deny=metadata).check('ssh_exec', …):  allowed → DENIED (+ decimal-IP spelling)
BRK-3  _confirm_op_key(user=readonly) vs (user=root): equal → differ
```

## 3. Validation

`ruff check` ✓, `ruff format --check` ✓ (48 files), `mypy --strict` ✓ (20
files), `pytest` **401 passed / 13 deselected** (+9 regression tests),
`pytest -m fuzz` 13 passed, `coverage` **94 %** (floor 90; `patterns`,
`redaction`, `policy`, `broker` all **100 %**). Scanner battery
(pip-audit / trivy / bandit / semgrep / actionlint / shellcheck) re-run clean.

No change to the no-sandbox posture, tier semantics, or any tool's response
shape. The fixes harden compensating controls and remove one secret-leak and
two ReDoS surfaces (one of them introduced-and-fixed within the pass). Every
new pattern carries paired positive/negative + ReDoS-ceiling tests.
