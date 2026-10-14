# Full audit and streamlining pass, 2026-10-14

- **Baseline**: `rmednitzer/relay-shell` at `feeb266` (`main` after PR #210). Branch
  `claude/beautiful-edison-5qs47t`, PR #211.
- **Scope**: the whole repository: trust-boundary core (`policy`, `patterns`, `redaction`,
  `audit`, `broker`, `config`, `Relay.run`), the SSH/session/seccomp runtime, OAuth and the
  edge, deploy tooling, CI and supply chain, documentation, and the test suite.
- **Method**: four read-only reviewers (one per slice) each reproduced their findings by
  running code; every claim below marked fixed was re-reproduced by the author before the fix
  and has a regression test that fails against the previous source (checked against a
  `git archive` copy of `HEAD`). Posture is unchanged: no sandbox was introduced and no
  capability was removed (ADR 0002), except as called out under "Behaviour changes".
- **Frozen record** (runbook §8). Not retro-edited; later state lands in `BACKLOG.md`.
- **Gates**: baseline `ruff check`, `ruff format --check`, `mypy` clean and the default
  `pytest` run green with 2 skips (Caddy absent). Final: the same three clean, `pytest`
  810 passed / 2 skipped, and the 12 `-m fuzz` tests pass separately.

`[V]` verified by running code in this session; `[R]` verified by reading only.

## 1. Fixed in this pass

### Trust-boundary core

| ID | Sev | Finding | Fix and evidence |
|----|-----|---------|------------------|
| A14-C1 | HIGH | Tier classifier ReDoS ahead of the deny list: 400 newlines took 3.5 s (cubic), `dd ` x30000 quadratic. `max_input` does not help `[V]` | `_CMD` whitespace gaps made unambiguous, `dd ... of=/dev/` bounded to 256 chars. `PATTERNS_VERSION` 14. 200k-sample differential test: 0 classification diffs. `tests/test_patterns.py::test_classifier_is_linear_*` |
| A14-C2 | MED | CLI-flag redaction rule quadratic on `-1-1-1...` (4000 pairs 1.4 s), runs on every audit record `[V]` | hyphen-word repetition bounded to 6. `test_cli_flag_redaction_is_not_quadratic_*` |
| A14-C3 | MED | Bare `Authorization:` value swallowed the rest of the line, hiding a following `rm -rf` from the audit record `[V]` | value now stops at `;` + whitespace (a plain `;` is needed by SigV4 `SignedHeaders`). `test_authorization_redaction_does_not_swallow_following_commands` |
| A14-C4 | MED | A runtime audit write failure left `degraded=False` (gauge and `server_info` healthy while records were lost) `[V]` | handler `handleError` sets `degraded` and a reason. `test_runtime_write_failure_marks_the_audit_sink_degraded` |
| A14-C5 | LOW | U+2028/U+2029/U+0085 in a record fragmented `audit_tail` and reset the chain `seq` to 0 on restart `[V]` | `split("\n")` instead of `splitlines()`; lone surrogates written as `\udXXX` instead of dropping the record |
| A14-C6 | MED | `jump=` was dialled first but absent from the policy probe, so a `RELAY_SHELL_POLICY_DENY` on an address was bypassable `[V]` | jump chain (and the `ssh_forward` host) added to the five SSH builders; probe unchanged without a jump. `test_deny_list_sees_the_jump_host` |
| A14-C7 | MED | `_with_canonical_ips` quadratic, run before the host caps (30000 hex tokens) `[V]` | first 128 tokens canonicalized |
| A14-C8 | MED-LOW | `SECRET_KEY=`, `DJANGO_SECRET_KEY=`, `ENCRYPTION_KEY=`, `PRIVATE_KEY=`, `ACCESS_KEY=`, `*_KEY_BASE=` and PGP private-key blocks not redacted `[V]` | keyword group and PEM rule extended |
| A14-C10 | LOW | Broker overflow eviction dropped the soonest-expiring entry, which could be an armed token `[V]` | un-armed entries evicted first. `test_overflow_evicts_unarmed_plans_before_an_armed_token` |
| A14-S1 | LOW | `AUDIT_SESSION_INPUT=hash` recorded an unsalted SHA-256 of a typed password at a secret prompt `[R]` | digest withheld at a recognised prompt. `test_hash_mode_withholds_the_digest_at_a_secret_prompt` |

### Runtime (SSH, sessions, inventory)

| ID | Sev | Finding | Fix and evidence |
|----|-----|---------|------------------|
| A14-R1 | HIGH | `ssh_forward` `L:`/`D:` bound every interface (`""`): an unauthenticated forward / SOCKS proxy for anything that can reach the relay `[V]` | bind `127.0.0.1`. `test_local_and_dynamic_forwards_listen_on_loopback_only` (reads `/proc/net/tcp`) |
| A14-R2 | MED | An error or cancel between claiming the connect slot and `asyncssh.connect` left the future unresolved; every later connect to that key hung `[V]` | option building moved inside the `try`. `test_failed_option_building_does_not_poison_the_connect_slot` |
| A14-R5 | MED | Cancelling the connect owner cancelled every waiter (including a whole `ssh_fanout`) `[V]` | waiters retry on `_OwnerCancelled`. `test_cancelled_connect_owner_does_not_cancel_waiters` |
| A14-R6 | MED-LOW | cols/rows > 65535 raised `struct.error` and leaked the pty fds `[V]` | clamped to 1..65535 |
| A14-R7 | MED-LOW | `ssh_spawn` stdin never drained: unbounded local buffer `[V]` | 1 MiB pending cap, bounded drain. `test_ssh_process_transport_refuses_unbounded_input_buffering` |
| A14-R8 | MED-LOW | SSH timeout sent SIGTERM only and left the channel open `[V]` | channel closed too (outcome-unknown wording deferred, see BACKLOG) |
| A14-R9 | LOW-MED | Shutdown ran `aclose` in a fresh loop; `RuntimeError` skipped SIGKILL `[V]` | `RuntimeError` handled, SIGKILL still sent |
| A14-R11 | LOW-MED | `known_hosts` append fused with an unterminated last line, corrupting both entries `[V]` | newline repaired. `test_append_known_host_repairs_a_missing_final_newline` |
| A14-R12 | LOW-MED | `ssh_config` `Match` block keywords merged into the previous `Host` `[V]` | `Match` ends the Host block. `test_match_block_is_not_merged_into_the_preceding_host` |
| A14-R14 | LOW | `shell_script(interpreter="sh")` strict mode always failed on dash (`pipefail`); `verify-deploy` raised on a non-UTF-8 file; `session_recv(timeout=NaN)` wrote bare `NaN` to the audit log; non-ASCII-digit `Port` crashed inventory load `[V]` | `set -eu` for sh; drift finding; clamped audited value; ASCII-only port |

### OAuth, deploy

| ID | Sev | Finding | Fix and evidence |
|----|-----|---------|------------------|
| A14-A1 | MED | `/register` returned HTTP 500 + traceback on every refusal under lockdown (bare `ValueError`) `[V]`; the "identical re-registration is a no-op" claim can never hold over HTTP because the SDK mints a fresh `client_id` | `RegistrationError` (RFC 7591 400). `docs/auth.md` corrected. `test_register_refusal_is_a_registration_error_not_a_500` |
| A14-A4 | MED | Admin CLI run as root wrote root-owned state files that the service then cannot read (fails closed for every client) `[V]` | ownership of the state directory preserved. `test_store_save_as_root_keeps_state_dir_ownership` |
| A14-A11 | LOW | `clients.json` written before the approval record: a crash in between made the legacy migration auto-approve the client; fixed temp name, no fsync `[R]` | approval first; unique same-directory temp, fsync, rename |
| A14-A6 | MED | `install-edge.sh` replaced the live Caddyfile before validating it, no backup (contradicted ADR 0004) `[R]` | validate the candidate first; keep `Caddyfile.bak` |

### Documentation and tests

Doc drift corrected (17 items verified, see PR #211 and the CHANGELOG): README layout, SDK pin
and validation claims; architecture module table and CLI flags; `approvals.json` in the state
and backup lists; the `cancelled` metric outcome; `release-trust` in the docs nav; the pre-commit
and CI claims in CONTRIBUTING; stale `B-007` references; the `release.yml` header. Streamlining:
runbook §5/§7 closed lists collapsed, the obsolete per-file `.md` plan (§8) replaced by the
conventions that still apply, BACKLOG placeholders removed, the OAuth migration section numbered
(§10). Tests: about 19 tautological assertions in `tests/test_tool_wrappers.py` replaced by
exact outcomes (several calls passed arguments the tools do not have), duplicated helpers moved
to `tests/helpers.py`, one subsumed fuzz test dropped. Dead code: `errors.PolicyDenied`, three
identical branches in `policy.classify`.

## 2. Behaviour changes operators may notice

1. `ssh_forward` `L:`/`D:` listen on loopback only (A14-R1). There is no non-loopback bind option.
2. `/register` refusals are 400, not 500 (A14-A1).
3. `ssh_forward` and the jump chain now reach `RELAY_SHELL_POLICY_DENY` (A14-C6); a deny that
   matched only a jump hop now fires where it silently did not.
4. `PATTERNS_VERSION` 14: more values redacted; a bare `Authorization:` value ends at `;`.
5. `ssh_spawn` `session_send` fails with a bounded error once 1 MiB is pending (A14-R7).

## 3. Open items

All deferrals, with severity, effort and the reason each was not fixed here, are in
`BACKLOG.md` under "2026-10-14 audit pass". The two with the largest operational weight:

- **A14-D3 (MED)**: the evidence verifier requires the oldest retained segment to start at
  genesis. With `rotate 90` the off-host sync stops after about 90 days `[V]` (reproduced by the
  reviewer on a copy). Needs a design for the anchor.
- **A14-A2 (MED)**: an approved *public* OAuth client needs only its `client_id` to obtain
  tokens, because `/authorize` is outside the CIDR gate and has no login step `[V]`. The fix is a
  deployment decision (move `/authorize` behind the gate, or refuse `none` clients).

## 4. Not findings (checked)

All `uses:` are pinned to full SHAs; no `pull_request_target`/`workflow_run`; no untrusted
interpolation into `run:`; code/refresh single-use, client binding, expiry and token-type guards
behave as documented; Caddy `remote_ip` ignores `X-Forwarded-For`; SFTP recursion rejects `/` in
names; the jump hop is verified strictly; `accept-new` refuses a changed key; `actionlint`,
`shellcheck`, `systemd-analyze verify` clean.

## 5. Limits of this pass

- No live shell/SSH smoke, deployment or restart was performed; no running service was touched.
- Caddy is not installed in the sandbox: the Caddy routing tests stay skipped and the Caddyfile
  findings are by reading.
- Seccomp findings were reproduced as root with `CAP_SYS_ADMIN` in the sandbox only; the fix for
  A14-R4 needs a privileged host and its own change.
- `.env.example` is outside this session's permissions: its stale `--require-genesis` comment is
  not fixed (the genesis check is the default; `--segment` relaxes it).
- Repository-setting claims (ruleset required checks, CODEOWNERS enforcement, environment branch
  policy) are not visible in-tree and were not verified.
- Classification and redaction remain heuristics (ADR 0003); nothing here claims containment.
