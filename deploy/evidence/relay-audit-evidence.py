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
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rt", encoding="utf-8", errors="strict") as handle:
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


def main() -> int:
    paths = sorted(
        (path for path in LOG_DIR.glob("audit.jsonl*") if path.is_file()),
        key=lambda path: (path.stat().st_mtime_ns, path.name),
    )
    approvals, approval_digest, approval_error = load_approvals()
    errors: list[str] = []
    if approval_error:
        errors.append(approval_error)
    segments: list[dict[str, Any]] = []
    total = 0
    previous_last: dict[str, Any] | None = None
    used_approvals: set[str] = set()
    latest_epoch: str | None = None

    for path in paths:
        first: dict[str, Any] | None = None
        last: dict[str, Any] | None = None
        count = 0
        try:
            for line_number, raw in enumerate(lines(path), 1):
                if not raw.strip():
                    continue
                try:
                    row = json.loads(raw)
                except json.JSONDecodeError as exc:
                    errors.append(f"{path.name}:{line_number}: invalid JSON: {exc.msg}")
                    continue
                if not (
                    isinstance(row, dict)
                    and isinstance(row.get("seq"), int)
                    and isinstance(row.get("prev"), str)
                    and isinstance(row.get("chain"), str)
                ):
                    if first is not None:
                        errors.append(
                            f"{path.name}:{line_number}: unchained record in chained region"
                        )
                    continue
                if canonical_chain(row["prev"], row) != row["chain"]:
                    errors.append(f"{path.name}:{line_number}: chain hash mismatch")
                if last is not None:
                    if row["seq"] != last["seq"] + 1:
                        errors.append(
                            f"{path.name}:{line_number}: sequence "
                            f"{row['seq']} follows {last['seq']}"
                        )
                    if row["prev"] != last["chain"]:
                        errors.append(f"{path.name}:{line_number}: previous hash mismatch")
                first = first or row
                last = row
                count += 1
        except (OSError, UnicodeError) as exc:
            errors.append(f"{path.name}: read error: {exc}")

        if first is None or last is None:
            continue

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
