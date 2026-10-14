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
  `grep x f | sudo tee y` stays Tier 2.
- **Verification.** Every case has a positive and a near-miss test
  (`tests/test_classifier_v16.py`); a differential run over a realistic corpus and 60,000
  random commands against v15 showed no Tier 3 downgrade except where a line continuation
  joins the lines (`echo hi \<newline>reboot` is one command whose argument is `reboot`).
- **Still heuristic.** Quoting, `eval`, variable indirection, `sh -c` strings, scripts, and
  commands that are not named above remain Tier 1. Extend per deployment with the deny and
  allow lists rather than by widening the built-ins silently.
