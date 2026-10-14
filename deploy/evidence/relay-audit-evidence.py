#!/usr/bin/env python3
"""Verify retained Relay Shell chains and emit an externally shippable anchor."""

from __future__ import annotations

import gzip
import hashlib
import json
import os
import stat
import sys
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

LOG_DIR = Path(os.environ.get("RELAY_AUDIT_LOG_DIR", "/var/log/relay-shell"))
APPROVALS = Path(
    os.environ.get("RELAY_AUDIT_APPROVALS", "/etc/relay-shell/audit-approved-resets.json")
)
EVIDENCE = LOG_DIR / "chain-verification.jsonl"
ANCHOR = LOG_DIR / "latest-anchor.json"
# Boundary records seen by earlier VALID runs. Once logrotate prunes the oldest
# segments the retained history no longer starts at genesis; it is still trustworthy
# when its first record continues a record this file proves was verified before.
CHECKPOINTS = LOG_DIR / "retained-checkpoints.json"
HEX64 = frozenset("0123456789abcdef")
MAX_RETAIN_SEGMENTS = 3660  # ten years of daily rotation


def _retain_segments() -> tuple[int, str | None]:
    """Rotated segments logrotate keeps (`rotate N`); head-pruning is only legitimate at N.

    A malformed or out-of-range value is an error (the run fails), never silently
    coerced: this setting decides whether a non-genesis history is trusted.
    """
    raw = os.environ.get("RELAY_AUDIT_RETAIN_SEGMENTS", "90").strip()
    try:
        value = int(raw)
    except ValueError:
        return 90, f"RELAY_AUDIT_RETAIN_SEGMENTS must be an integer, got {raw!r}"
    if not 1 <= value <= MAX_RETAIN_SEGMENTS:
        return 90, f"RELAY_AUDIT_RETAIN_SEGMENTS must be 1..{MAX_RETAIN_SEGMENTS}, got {value}"
    return value, None


RETAIN_SEGMENTS, RETAIN_ERROR = _retain_segments()
# Keep every endpoint a full retention window can still need (plus the active segment).
MAX_CHECKPOINTS = max(512, 2 * RETAIN_SEGMENTS + 16)
GENESIS = "0" * 64
# The live, actively-appended segment. Rotated segments carry a numeric/date
# suffix (optionally `.gz`); only this one is written concurrently with the
# verifier, so only it can present a torn trailing record (EVID-1).
ACTIVE_LOG = "audit.jsonl"


def canonical_chain(previous: str, row: dict[str, Any]) -> str:
    body = {key: value for key, value in row.items() if key != "chain"}
    canonical = json.dumps(
        body, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str
    )
    return hashlib.sha256((previous + canonical).encode()).hexdigest()


def timestamp(value: object) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            return None
        return parsed.astimezone(UTC)
    except (TypeError, ValueError):
        return None


def normalized_timestamp(value: object) -> str | None:
    parsed = timestamp(value)
    return parsed.isoformat() if parsed else None


def lines(path: Path) -> Iterator[str]:
    # Rotated segments are complete and read strictly, so genuine corruption
    # (incl. a truncated multibyte) surfaces as a read error. The live segment is
    # appended concurrently by the running server, so a read can race an
    # in-progress write and see a torn trailing record — decode it `replace` so a
    # torn multibyte in that tail cannot abort the whole segment; the torn line
    # then fails JSON parse and is tolerated as the last line (EVID-1). Complete
    # records are valid UTF-8 either way, so `replace` never masks a finished one.
    strict = not (path.name == ACTIVE_LOG and path.suffix != ".gz")
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rt", encoding="utf-8", errors="strict" if strict else "replace") as handle:
        yield from handle


def chain_epoch(first: dict[str, Any]) -> str:
    material = f"relay-shell-genesis\0{first.get('ts', '')}\0{first.get('chain', '')}"
    return hashlib.sha256(material.encode()).hexdigest()


def load_approvals() -> tuple[
    dict[str, dict[str, str]], dict[tuple[int, str], dict[str, str]], str | None, str | None
]:
    """Return ``(approved_resets, approved_heads, ledger_sha256, error)``.

    ``approved_heads`` is the root-reviewed bootstrap for a retained history that no
    longer starts at genesis: an exact ``(first_seq, prev)`` of the oldest retained
    record, for hosts that crossed the retention window before checkpoints existed.
    """
    if not APPROVALS.exists():
        return {}, {}, None, None

    try:
        metadata = APPROVALS.stat()
        if metadata.st_uid != 0:
            raise ValueError("approval ledger must be owned by root")
        if metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise ValueError("approval ledger must not be group- or world-writable")

        raw = APPROVALS.read_bytes()
        document = json.loads(raw)
        if not isinstance(document, dict) or document.get("version") != 1:
            raise ValueError("approval ledger must be an object with version 1")
        entries = document.get("approved_resets")
        if not isinstance(entries, list):
            raise ValueError("approved_resets must be a list")

        approvals: dict[str, dict[str, str]] = {}
        for index, entry in enumerate(entries):
            if not isinstance(entry, dict):
                raise ValueError(f"approved_resets[{index}] must be an object")
            first_ts = normalized_timestamp(entry.get("first_ts"))
            approved_at = normalized_timestamp(entry.get("approved_at"))
            reason = entry.get("reason")
            if first_ts is None:
                raise ValueError(f"approved_resets[{index}].first_ts must be timezone-aware")
            if approved_at is None:
                raise ValueError(f"approved_resets[{index}].approved_at must be timezone-aware")
            if not isinstance(reason, str) or not reason.strip():
                raise ValueError(f"approved_resets[{index}].reason must be non-empty")
            if first_ts in approvals:
                raise ValueError(f"duplicate approved reset timestamp: {first_ts}")
            approvals[first_ts] = {
                "first_ts": first_ts,
                "approved_at": approved_at,
                "reason": reason.strip(),
            }

        heads: dict[tuple[int, str], dict[str, str]] = {}
        head_entries = document.get("approved_heads", [])
        if not isinstance(head_entries, list):
            raise ValueError("approved_heads must be a list")
        for index, entry in enumerate(head_entries):
            if not isinstance(entry, dict):
                raise ValueError(f"approved_heads[{index}] must be an object")
            first_seq = entry.get("first_seq")
            prev = entry.get("prev")
            approved_at = normalized_timestamp(entry.get("approved_at"))
            reason = entry.get("reason")
            if not isinstance(first_seq, int) or isinstance(first_seq, bool) or first_seq < 1:
                raise ValueError(f"approved_heads[{index}].first_seq must be an integer >= 1")
            if not (isinstance(prev, str) and len(prev) == 64 and set(prev) <= HEX64):
                raise ValueError(f"approved_heads[{index}].prev must be 64 lowercase hex chars")
            if approved_at is None:
                raise ValueError(f"approved_heads[{index}].approved_at must be timezone-aware")
            if not isinstance(reason, str) or not reason.strip():
                raise ValueError(f"approved_heads[{index}].reason must be non-empty")
            if (first_seq, prev) in heads:
                raise ValueError(f"duplicate approved head: seq {first_seq} prev {prev}")
            epoch = entry.get("epoch")
            if epoch is not None and not (
                isinstance(epoch, str) and len(epoch) == 64 and set(epoch) <= HEX64
            ):
                raise ValueError(f"approved_heads[{index}].epoch must be 64 lowercase hex chars")
            heads[(first_seq, prev)] = {
                "approved_at": approved_at,
                "reason": reason.strip(),
                "epoch": epoch or "",
            }

        digest = hashlib.sha256(raw).hexdigest()
        return approvals, heads, digest, None
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        return {}, {}, None, f"invalid approval ledger {APPROVALS}: {exc}"


def load_checkpoints() -> tuple[dict[tuple[int, str], str | None], str | None]:
    """Read the checkpoint file. A missing file is empty; an unreadable one is empty
    too (head-pruned history then fails closed) and is reported as a warning."""
    if not CHECKPOINTS.exists():
        return {}, None
    try:
        document = json.loads(CHECKPOINTS.read_text(encoding="utf-8"))
        entries = document["checkpoints"]
        if document.get("version") != 1 or not isinstance(entries, list):
            raise ValueError("unsupported checkpoint file")
        found: dict[tuple[int, str], str | None] = {}
        for entry in entries:
            seq, chain, epoch = entry["seq"], entry["chain"], entry.get("epoch")
            if not isinstance(seq, int) or not isinstance(chain, str):
                raise ValueError("malformed checkpoint entry")
            found[(seq, chain)] = epoch if isinstance(epoch, str) else None
        return found, None
    except (OSError, UnicodeError, ValueError, KeyError, TypeError) as exc:
        return {}, f"ignoring unreadable checkpoint file {CHECKPOINTS}: {exc}"


def save_checkpoints(
    existing: dict[tuple[int, str], str | None], fresh: list[dict[str, Any]]
) -> None:
    merged: dict[tuple[int, str], dict[str, Any]] = {
        (seq, chain): {"seq": seq, "chain": chain, "epoch": epoch}
        for (seq, chain), epoch in existing.items()
    }
    for entry in fresh:
        merged[(entry["seq"], entry["chain"])] = entry
    entries = list(merged.values())[-MAX_CHECKPOINTS:]
    temporary = CHECKPOINTS.with_suffix(".tmp")
    temporary.write_text(
        json.dumps({"version": 1, "checkpoints": entries}, indent=1) + "\n", encoding="utf-8"
    )
    temporary.chmod(0o600)
    temporary.replace(CHECKPOINTS)


def verify_segment(
    path: Path,
) -> tuple[dict[str, Any] | None, dict[str, Any] | None, int, bool, list[str]]:
    """Verify one segment in isolation (order-independent).

    Returns ``(first, last, count, torn_tail, errors)``. Intra-segment checks
    (chain-hash recompute, ``seq`` monotonicity, ``prev`` linkage) do not depend
    on cross-segment ordering, so they run here per file. A parse failure on the
    LAST non-empty line of the live segment is the expected torn-write of an
    in-progress append (EVID-1): it is deferred and, if nothing follows it, is
    dropped (``torn_tail=True``) instead of failing the run. A parse failure
    anywhere else — or on any rotated segment — stays a hard error.
    """
    first: dict[str, Any] | None = None
    last: dict[str, Any] | None = None
    count = 0
    errors: list[str] = []
    is_active = path.name == ACTIVE_LOG
    # A parse error we have not yet decided is real: on the active segment the
    # final one may be a torn append. Flushed as real the moment another
    # non-empty line follows it.
    deferred: str | None = None
    try:
        for line_number, raw in enumerate(lines(path), 1):
            if not raw.strip():
                continue
            if deferred is not None:
                # A non-empty line followed the deferred parse error, so that
                # error was NOT the torn trailing record — it is real.
                errors.append(deferred)
                deferred = None
            try:
                row = json.loads(raw)
            except json.JSONDecodeError as exc:
                message = f"{path.name}:{line_number}: invalid JSON: {exc.msg}"
                if is_active:
                    deferred = message  # maybe the torn tail; decide at EOF
                else:
                    errors.append(message)
                continue
            if not (
                isinstance(row, dict)
                and isinstance(row.get("seq"), int)
                and isinstance(row.get("prev"), str)
                and isinstance(row.get("chain"), str)
            ):
                if first is not None:
                    errors.append(f"{path.name}:{line_number}: unchained record in chained region")
                continue
            if canonical_chain(row["prev"], row) != row["chain"]:
                errors.append(f"{path.name}:{line_number}: chain hash mismatch")
            if last is not None:
                if row["seq"] != last["seq"] + 1:
                    errors.append(
                        f"{path.name}:{line_number}: sequence {row['seq']} follows {last['seq']}"
                    )
                if row["prev"] != last["chain"]:
                    errors.append(f"{path.name}:{line_number}: previous hash mismatch")
            first = first or row
            last = row
            count += 1
    except (OSError, UnicodeError) as exc:
        errors.append(f"{path.name}: read error: {exc}")
    # A deferred error that survived to EOF was the last non-empty line of the
    # live segment: tolerate it as a torn in-progress append.
    torn_tail = deferred is not None
    return first, last, count, torn_tail, errors


def main() -> int:
    approvals, approved_heads, approval_digest, approval_error = load_approvals()
    checkpoints, checkpoint_warning = load_checkpoints()
    errors: list[str] = []
    if approval_error:
        errors.append(approval_error)
    if RETAIN_ERROR:
        errors.append(RETAIN_ERROR)
    if checkpoint_warning:
        print(checkpoint_warning, file=sys.stderr)

    paths = [path for path in LOG_DIR.glob("audit.jsonl*") if path.is_file()]

    # Phase 1: verify each segment independently. Ordering is deferred to phase 2
    # so that file-discovery order (and thus filesystem mtime) never affects the
    # cross-segment seam decisions.
    verified: list[dict[str, Any]] = []
    torn_tails = 0
    for path in paths:
        first, last, count, torn_tail, seg_errors = verify_segment(path)
        errors.extend(seg_errors)
        if torn_tail:
            torn_tails += 1
        if first is None or last is None:
            continue
        verified.append({"path": path, "first": first, "last": last, "count": count})

    # Phase 2: order segments by the first record's timestamp — the
    # chain-authoritative chronological order — NOT by filesystem mtime, which
    # logrotate `delaycompress` inverts when it rewrites a rotated segment's mtime
    # at compression time (EVID-1). Records are written in time order, so within
    # an epoch `first_ts` rises with `seq`; across an approved genesis reset it
    # keeps epochs in chronological order where `first_seq` alone (0 again) cannot.
    # `first_seq` then the file name are stable tiebreakers for determinism.
    def _order_key(segment: dict[str, Any]) -> tuple[str, int, str]:
        ts = normalized_timestamp(segment["first"].get("ts")) or ""
        return (ts, int(segment["first"]["seq"]), segment["path"].name)

    verified.sort(key=_order_key)

    segments: list[dict[str, Any]] = []
    total = 0
    previous_last: dict[str, Any] | None = None
    used_approvals: set[str] = set()
    latest_epoch: str | None = None
    rotated_count = sum(1 for segment in verified if segment["path"].name != ACTIVE_LOG)
    pruned_head: str | None = None
    fresh_checkpoints: list[dict[str, Any]] = []

    for segment in verified:
        path = segment["path"]
        first = segment["first"]
        last = segment["last"]
        count = segment["count"]

        if previous_last is None:
            if first["seq"] != 0 or first["prev"] != GENESIS:
                head = (first["seq"], first["prev"])
                before = (first["seq"] - 1, first["prev"])
                if head in approved_heads:
                    pruned_head = "approved"
                    # The chain epoch cannot be recomputed from a pruned history; the
                    # reviewed ledger entry may carry it (from the last anchor).
                    latest_epoch = approved_heads[head]["epoch"] or None
                elif before in checkpoints and rotated_count >= RETAIN_SEGMENTS:
                    # Logrotate pruned older segments: the oldest retained record
                    # continues one a previous valid run verified, and the full
                    # retention window is still present (deleting one more segment
                    # drops the count below it and fails here).
                    pruned_head = "checkpoint"
                    latest_epoch = checkpoints[before]
                else:
                    errors.append(
                        f"{path.name}: retained history is not genesis-anchored and does "
                        f"not continue a verified checkpoint (first seq {first['seq']}, "
                        f"prev {first['prev']}; {rotated_count} rotated segments retained, "
                        f"{RETAIN_SEGMENTS} required). If this host rotated before "
                        "checkpoints existed, review the evidence and add an approved_heads "
                        "entry for exactly this seq and prev"
                    )
        elif first["seq"] == previous_last["seq"] + 1 and first["prev"] == previous_last["chain"]:
            pass
        elif first["seq"] == 0 and first["prev"] == GENESIS:
            reset_time = normalized_timestamp(first.get("ts"))
            if reset_time in approvals and reset_time not in used_approvals:
                used_approvals.add(reset_time)
            else:
                errors.append(
                    f"{path.name}: unapproved genesis reset at {first.get('ts', 'unknown')}"
                )
        else:
            errors.append(f"{path.name}: broken rotation seam after seq {previous_last['seq']}")
        if first["seq"] == 0 and first["prev"] == GENESIS:
            latest_epoch = chain_epoch(first)

        segments.append(
            {
                "file": path.name,
                "records": count,
                "first_seq": first["seq"],
                "last_seq": last["seq"],
                "first_ts": first.get("ts"),
                "last_ts": last.get("ts"),
                "chain_epoch": latest_epoch,
            }
        )
        total += count
        previous_last = last
        fresh_checkpoints.append(
            {
                "seq": last["seq"],
                "chain": last["chain"],
                "epoch": latest_epoch,
                "ts": last.get("ts"),
            }
        )

    if not segments:
        errors.append("no chained audit records found")

    LOG_DIR.mkdir(mode=0o755, parents=True, exist_ok=True)
    if not errors:
        # Persist the boundary records BEFORE declaring the run valid: a run that cannot
        # record them would publish a valid anchor and then stall for good once logrotate
        # removes the genesis segment, so it must fail loudly now.
        try:
            save_checkpoints(checkpoints, fresh_checkpoints)
        except OSError as exc:
            errors.append(f"could not write {CHECKPOINTS}: {exc}")

    now = datetime.now(UTC).isoformat()
    valid = not errors
    anchor = {
        "evidence_type": "relay_shell_audit_anchor",
        "generated_at": now,
        "valid": valid,
        "records": total,
        "segments": len(segments),
        "approval_policy": "exact_timestamp",
        "approval_ledger_sha256": approval_digest,
        "approved_historic_resets": len(used_approvals),
        "retention_pruned_head": pruned_head,
        "first_retained_seq": segments[0]["first_seq"] if segments else None,
        "latest_seq": previous_last.get("seq") if previous_last else None,
        "latest_epoch": latest_epoch,
        "latest_chain": previous_last.get("chain") if previous_last else None,
        "latest_record_ts": previous_last.get("ts") if previous_last else None,
    }
    evidence = {
        **anchor,
        "evidence_type": "relay_shell_chain_verification",
        "errors": errors[:50],
        "torn_tails": torn_tails,
        "approved_reset_timestamps": sorted(used_approvals),
        "segment_summary": segments,
    }

    with EVIDENCE.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(evidence, separators=(",", ":")) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    EVIDENCE.chmod(0o600)
    temporary = ANCHOR.with_suffix(".tmp")
    temporary.write_text(json.dumps(anchor, indent=2) + "\n", encoding="utf-8")
    temporary.chmod(0o600)
    temporary.replace(ANCHOR)
    print(json.dumps(anchor, separators=(",", ":")))
    for error in errors[:50]:
        print(error, file=sys.stderr)
    return 0 if valid else 1


MAX_ANCHOR_BYTES = 65536  # an anchor is a few hundred bytes; bound what a remote can feed us


def compare_remote_anchor(remote_path: str) -> tuple[int, str]:
    """Refuse to publish an anchor that is older than, or has diverged from, the remote one.

    The sync is a mirror, so a locally rewritten chain that still verifies would overwrite
    the off-host copy and erase the evidence of the rewrite (A14-D9). Within one chain epoch
    the sequence only grows: a smaller ``latest_seq`` is a rollback, and the same
    ``latest_seq`` with a different ``latest_chain`` is a fork. A different epoch is a new
    chain (an approved genesis reset, checked against the approvals ledger by ``main``) and
    is not compared. Returns ``(exit_code, message)``: 0 ok, 4 regression or fork, 2 when
    either anchor cannot be read.
    """
    try:
        with Path(remote_path).open("rb") as handle:
            raw = handle.read(MAX_ANCHOR_BYTES + 1)
        if len(raw) > MAX_ANCHOR_BYTES:
            return 2, f"cannot compare anchors: remote anchor exceeds {MAX_ANCHOR_BYTES} bytes"
        remote = json.loads(raw.decode("utf-8"))
        local = json.loads(ANCHOR.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return 2, f"cannot compare anchors: {exc}"
    if not isinstance(remote, dict) or not isinstance(local, dict):
        return 2, "cannot compare anchors: not JSON objects"
    if remote.get("valid") is not True:
        return 0, "remote anchor is not marked valid; nothing to protect"
    r_seq, l_seq = remote.get("latest_seq"), local.get("latest_seq")
    if not isinstance(r_seq, int) or not isinstance(l_seq, int):
        return 0, "an anchor has no latest_seq; nothing to compare"
    if remote.get("latest_epoch") != local.get("latest_epoch"):
        return 0, "chain epoch differs from the remote anchor; not comparable"
    if l_seq < r_seq:
        return (
            4,
            f"local latest_seq {l_seq} is behind the remote anchor's {r_seq}: refusing to publish",
        )
    if l_seq == r_seq and remote.get("latest_chain") != local.get("latest_chain"):
        return 4, f"local and remote chains diverge at seq {l_seq}: refusing to publish"
    return 0, f"local anchor (seq {l_seq}) is not behind the remote anchor (seq {r_seq})"


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--check-remote-anchor":
        _code, _message = compare_remote_anchor(sys.argv[2])
        print(_message, file=sys.stderr if _code else sys.stdout)
        raise SystemExit(_code)
    raise SystemExit(main())
