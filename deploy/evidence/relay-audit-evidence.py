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


def load_approvals() -> tuple[dict[str, dict[str, str]], str | None, str | None]:
    if not APPROVALS.exists():
        return {}, None, None

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

        digest = hashlib.sha256(raw).hexdigest()
        return approvals, digest, None
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        return {}, None, f"invalid approval ledger {APPROVALS}: {exc}"


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
    approvals, approval_digest, approval_error = load_approvals()
    errors: list[str] = []
    if approval_error:
        errors.append(approval_error)

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

    for segment in verified:
        path = segment["path"]
        first = segment["first"]
        last = segment["last"]
        count = segment["count"]

        if previous_last is None:
            if first["seq"] != 0 or first["prev"] != GENESIS:
                errors.append(f"{path.name}: retained history is not genesis-anchored")
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

    if not segments:
        errors.append("no chained audit records found")

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

    LOG_DIR.mkdir(mode=0o755, parents=True, exist_ok=True)
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


if __name__ == "__main__":
    raise SystemExit(main())
