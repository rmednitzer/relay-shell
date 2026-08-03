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
- a genesis-anchored beginning for the retained history.

The verifier writes:

- `chain-verification.jsonl`: append-only verification history;
- `latest-anchor.json`: atomic compact state for health and ingestion checks.

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
