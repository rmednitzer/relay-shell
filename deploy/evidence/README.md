# Audit evidence verifier and off-host sync

These deployment assets verify every retained Relay Shell audit segment,
validate cross-rotation seams, write a compact latest anchor, and copy the
evidence to an operator-selected off-host destination.

Genesis resets are fail-closed. A reset is accepted only when its exact first
record timestamp appears in a root-owned approval ledger. This avoids broad
date cutoffs and keeps each exception reviewable.

## Install

Install the scripts and units with root ownership:

```bash
install -m 0755 relay-audit-evidence.py /usr/local/libexec/relay-audit-evidence
install -m 0755 relay-audit-evidence-sync /usr/local/libexec/
install -m 0644 relay-audit-evidence.service relay-audit-evidence.timer \
  /etc/systemd/system/
install -m 0644 audit-evidence.env.example /etc/relay-shell/audit-evidence.env
install -m 0644 approved-resets.json.example \
  /etc/relay-shell/audit-approved-resets.json
systemctl daemon-reload
systemctl enable --now relay-audit-evidence.timer
```

Set `RELAY_AUDIT_RSYNC_DEST` in `audit-evidence.env` to an rsync destination
whose SSH identity is already constrained separately. The service deliberately
does not create or manage credentials.

## Approval ledger

The ledger is JSON:

```json
{
  "version": 1,
  "approved_resets": [
    {
      "first_ts": "2026-01-02T03:04:05.678901+00:00",
      "approved_at": "2026-01-02T04:00:00+00:00",
      "reason": "Reviewed service restart after rotation; retained seam and journal matched."
    }
  ]
}
```

The verifier requires:

- root ownership;
- no group or world write bit;
- version `1`;
- unique, timezone-aware `first_ts` values;
- non-empty `reason` and `approved_at` fields.

The timestamp identifies the first record of the new genesis segment exactly.
Do not approve a range, a date, or a host-wide bypass. Preserve incident
evidence outside this file and put a concise evidence reference in `reason`.

## Retention and pruning

`deploy/logrotate/relay-shell` keeps `rotate 90` segments, so after about 90 days the oldest
segment is deleted and the retained history no longer starts at sequence 0. The verifier
accepts that only when both hold:

1. the oldest retained record continues a record (`seq - 1`, `prev`) that an earlier valid
   run checkpointed in `retained-checkpoints.json`, and
2. at least `RELAY_AUDIT_RETAIN_SEGMENTS` rotated segments (default 90, set it to the
   logrotate `rotate` value) are still present.

Deleting a segment more than logrotate would have normally fails condition 2, and a history
that continues an unknown chain fails condition 1. This catches accidents and crude deletion.
It is **not** a defence against someone who can write the log directory: condition 2 counts
files, so such a writer can split a retained segment in two (every hash and seam still verify)
to restore the count, and the chain is keyless (ADR 0007). The off-host copy is the authority
for that case. `RELAY_AUDIT_RETAIN_SEGMENTS` must be an integer from 1 to 3660; anything else
fails the run instead of being coerced, and the checkpoint history is sized from it. The run
also fails (rather than publishing a valid anchor) if `retained-checkpoints.json` cannot be
written, since the next prune would then stall the pipeline. The anchor reports
`retention_pruned_head` (`checkpoint`, `approved` or `null`) and `first_retained_seq`.
Deleting whole segments at the retention boundary is, by design, indistinguishable from
rotation locally: the off-host copy (the sync never deletes) remains the authority.

**Hosts that already crossed the window** have no checkpoint, so the verifier fails with the
exact `seq` and `prev` of the oldest retained record. After reviewing the evidence (compare
with the off-host copy), approve exactly that record in the root-owned ledger:

```json
{
  "version": 1,
  "approved_resets": [],
  "approved_heads": [
    {
      "first_seq": 4321,
      "prev": "<64 lowercase hex chars from the error message>",
      "approved_at": "2026-10-14T12:00:00+00:00",
      "reason": "Oldest segment rotated out before checkpoints existed; off-host copy matches.",
      "epoch": "<optional: latest_epoch from the last good anchor / off-host evidence>"
    }
  ]
}
```

`approved_heads` entries are validated like resets (root-owned ledger, timezone-aware
`approved_at`, non-empty `reason`, unique, `first_seq >= 1`). The chain epoch cannot be
recomputed from a pruned history; if you supply the optional 64-hex `epoch` (the
`latest_epoch` of the last good anchor, kept in `chain-verification.jsonl` or off-host) the
anchor and the new checkpoints carry it, otherwise `latest_epoch` is `null` until a genesis
reset reappears. The next valid run records
checkpoints, and later rotations need no further approval.

## Validate

```bash
/usr/local/libexec/relay-audit-evidence
systemctl start relay-audit-evidence.service
systemctl status relay-audit-evidence.service
cat /var/log/relay-shell/latest-anchor.json
```

A valid anchor requires:

- every retained record hash to recompute;
- sequence and `prev` continuity inside every file;
- each cross-file seam to continue, or to match one exact approved reset;
- a beginning for the retained history that is either genesis-anchored or a verified
  continuation after logrotate pruned older segments (see "Retention and pruning").


The verifier writes:

- `chain-verification.jsonl`: append-only verification history;
- `latest-anchor.json`: atomic compact state for health and ingestion checks;
- `retained-checkpoints.json`: boundary records (`seq`, `chain`, chain epoch) seen by
  earlier valid runs, used to accept pruned history (written only after a valid run, shipped
  off-host with the payload).

The sync wrapper fails before publishing anything when verification fails. It
uses delayed replacements and publishes audit segments plus verification
history first, then publishes `latest-anchor.json` in a second rsync pass.
`RELAY_AUDIT_VERIFY_BIN` and `RELAY_AUDIT_RSYNC_BIN` can override the verifier
and rsync binaries (primarily for testing); defaults match the installed paths.
The anchor is therefore the commit marker for the off-host generation: consumers
must reject stale or invalid anchors and must not infer completeness from a
partially transferred payload.

The off-host copy remains authoritative for tail-truncation detection. This
verifier cannot prove that a locally removed newest record never existed.
