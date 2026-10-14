# ADR 0003: Tiered authority

- Status: Accepted
- Date: 2026-05-19

## Context

With no internal sandbox (ADR 0002), the model sits inside the execution
loop. A bash script cannot assess "this restarts a service users depend on,
ask first"; a reasoning layer can. We want that judgement captured and, when
desired, *enforced* - without crippling the default single-owner workflow.

## Decision

Classify every call into a tier and admit it according to a configured mode.

| Tier | Meaning | Examples |
|------|---------|----------|
| 0 | Read-only / observe | `server_info`, `ssh_hosts`, `ssh_check`, `session_recv` |
| 1 | Reversible / low blast | `ls`, open a PTY, send keystrokes |
| 2 | Stateful / visible impact | service restart, package install, SFTP, forward |
| 3 | Irreversible / high blast | `rm -rf`, `mkfs`, `shutdown`, `drop database`, force-push |

Classification is conservative (ambiguity rounds **up**) and based on the tool
plus a scan of the command/script text.

Modes (`RELAY_SHELL_POLICY_MODE`):

- `open` - permit all, still classify and audit. Default; matches the
  documented single-owner posture.
- `guarded` - refuse Tier >= 2 unless `RELAY_SHELL_POLICY_ALLOW` matches; lower
  tiers pass.
- `readonly` - permit only Tier 0.

`RELAY_SHELL_POLICY_DENY` is evaluated **first in every mode**, including `open`, so
an absolute prohibition always holds. A refusal is audited (with the tier and
reason) and returned as a `[DENIED ...]` string, never an exception.

## Consequences

- The tier is always recorded, so the audit trail shows intent and blast
  radius even when nothing is enforced.
- An operator can tighten a deployment (observation-only client, change
  allowlist) without code changes.
- Classification is heuristic and advisory in `open` mode: defence in depth,
  not a sandbox. It complements, and never replaces, the deployment controls
  in ADR 0002. The regex sets are intentionally simple and auditable; extend
  them per deployment via the deny/allow lists rather than by widening the
  built-in heuristics silently.

## Rejected

- No classification (rely only on deployment controls): loses the intent
  record and the ability to tighten without a rebuild.
- A full capability/command allowlist as the primary control: unbounded for
  general administration; high friction for low risk reduction on a
  single-owner host. The deny list plus `guarded` allow list covers the cases
  that matter without that cost.

## 2026-10-14 update: classifier tuning (A14-C9, `PATTERNS_VERSION` 16)

The 2026-10-14 audit corpus showed the heuristics drifting in both directions, and the
reproduced cases are now fixed. Nothing here makes the classifier a boundary: a permitted
shell command is not contained by it, and `guarded`/`readonly` remain advisory for
anything the patterns do not name.

- **Under-classified, now escalated.** Tier 3: `rm \<newline>-rf` (line continuations are
  removed before matching, as the shell does), `sudo -u root reboot`, `nice -n 10 reboot`,
  `timeout 5 reboot` (wrappers with arguments), `redis-cli FLUSHALL|FLUSHDB`. Tier 2:
  `systemctl start|enable|reload|...` (including with `--user`/`-H host`), `service ...
  start`, `useradd`/`usermod`/`groupadd`/`chpasswd`/..., `iptables -A/-I/-D/...`, `nft add/
  delete/...`, `firewall-cmd --add/--permanent/...`, `kubectl exec|drain|cordon|patch|edit|
  create|...` after global flags, `redis-cli shutdown|config set`, `docker-compose`, and a
  `>`/`>>`/`tee` into `~/.ssh/`, `authorized_keys`, a shell rc file, `sudoers`, /root,
  /boot, /usr, /bin, /sbin, /lib*, /opt, /srv, /sys or /var/{spool,lib,www}. Account,
  firewall and cache commands match in command position only, so `man useradd` does not.
- **Over-classified, now lower.** `crontab -l`, `docker compose ps|logs|config|...`, and a
  privilege wrapper named by a read-only command (`grep sudo /var/log/auth.log`,
  `man sudo`, `echo sudo`). Other segments of the same line are still scanned, so
  `grep x f | sudo tee y` stays Tier 2, and a line that can evaluate text
  (`echo 'sudo id' | sh`, `eval`, `$(...)`) keeps the privilege tier.
- **Verification.** Every case has a positive and a near-miss test
  (`tests/test_classifier_v16.py`); a differential run over a realistic corpus and 60,000
  random commands against v15 showed no Tier 3 downgrade except where a line continuation
  joins the lines (`echo hi \<newline>reboot` is one command whose argument is `reboot`).
- **Still heuristic.** Quoting, `eval`, variable indirection, `sh -c` strings, scripts, and
  commands that are not named above remain Tier 1. Extend per deployment with the deny and
  allow lists rather than by widening the built-ins silently.

### STPA trace for the 2026-10-14 tuning (authority and automated decision)

The tier decides whether `guarded` and `readonly` refuse a call and whether the opt-in
Tier-3 broker (ADR 0009) demands a second step, so moving a command between tiers moves
authority. Boundary: `policy.classify`, the policy modes, and the audit record of the
decision; the shell and the remote host are outside it. Controller: the classifier (an
automated decision); human intervention: the operator's deny/allow lists and the audit
review.

- **Losses.** L-1 A destructive or persistent change runs without the refusal or the
  second step the operator configured. L-2 A harmless read is refused, so the operator
  loosens the mode (or stops using it) and the control weakens. L-3 The audit record
  hides what ran.
- **Hazards.** H-1 A command that changes state is admitted as Tier 1 (under-classified).
  H-2 A read-only command is refused as Tier 2/3 (over-classified). H-3 The text the
  classifier sees differs from what the shell executes (line continuations, wrappers).
- **Constraints.** SC-1 (H-1) A named state-changing command is Tier 2 or 3 wherever the
  shell would run it. SC-2 (H-2) The same word as an argument or text of a read-only
  command does not escalate. SC-3 (H-3) The classifier reads the command as the shell
  does for the cases it models: continuations outside single quotes are removed, and
  wrappers with arguments are skipped only at a command boundary. SC-4 Every pattern is
  linear, because classification runs before admission on the event loop.
- **Unsafe control actions.** UCA-1 (not provided) a state change is not escalated:
  `rm \<nl>-rf`, `sudo -u root reboot`, `nice -n 10 reboot`, `systemctl start`,
  `iptables -A`, `kubectl exec`, `redis-cli FLUSHALL`, a redirect into `authorized_keys`.
  UCA-2 (provided unsafely) a read is escalated: `crontab -l`, `docker compose ps`,
  `grep sudo auth.log`, `kubectl get pod delete`, `systemctl --user status stop`,
  `firewall-cmd --permanent --get-zones`, `echo timeout 5 reboot`, `grep redis-cli FLUSHDB`.
  UCA-3 (wrong order) a continuation is removed after matching, or inside single quotes
  where it is literal text. UCA-4 (too late) a quadratic pattern delays admission.
- **Causal scenarios.** CS-1 (UCA-1) a model or attacker splits or wraps the command so
  the token the pattern needs is not adjacent. CS-2 (UCA-2) a verb-shaped word is an option
  value or a resource name (`--profile logs`, `get pod delete`), so a pattern that scans
  for the verb anywhere misreads it; the patterns therefore model option arity for
  `systemctl`, `kubectl` and `docker compose` and treat a flag value as a value. CS-3
  (UCA-3) a literal `\<newline>` inside `printf '...'`; the scan keeps single-quoted spans.
  CS-4 (UCA-4) option runs repeated thousands of times; every repetition is bounded.
  CS-5 (UCA-1) a read-only command's output is executed: `echo 'sudo -n touch /x' | sh`,
  `$(echo sudo ...)`, `eval`. Naming `sudo` after `echo` is data only if nothing evaluates
  the text, so the reader exemption is switched off for any line with an interpreter or
  `xargs` after a pipe, `eval`/`source`/`exec`, a `sh -c` string, a backtick, `$(` or `<(`
  (`test_a_real_privilege_wrapper_still_escalates`).
- **Trace.** SC-1 and UCA-1: `test_wrapped_or_continued_destructive_commands_are_tier3`,
  `test_state_changes_that_were_tier1_are_now_tier2`, `test_wrappers_with_arguments_need_a_command_boundary`.
  SC-2 and UCA-2: `test_near_misses_stay_tier1`, `test_read_only_commands_no_longer_over_classify`,
  `test_a_real_privilege_wrapper_still_escalates`. SC-3: `test_line_continuation_is_removed_before_matching`.
  SC-4: `test_new_patterns_are_linear_on_adversarial_input` and `pytest -m fuzz`. All in
  `tests/test_classifier_v16.py`.
- **Assumptions and limits.** An unbalanced quote makes the continuation scan fall back to
  removing every continuation (the conservative direction). Here-document bodies are not
  tracked. Quoting, `eval`, variable indirection, `sh -c` strings, scripts and unnamed
  commands stay Tier 1; wrappers chained behind other wrappers (`sudo nice reboot`) are not
  followed. The deny-list probe reads the raw text. This is a heuristic with an operator
  override, not a boundary; the no-sandbox posture (ADR 0002) is unchanged.
