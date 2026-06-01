"""Append-only, output-hashed audit trail.

One JSON object per line. The output *body* is never written - only its
SHA-256 and byte length - so the log is safe to ship off-host. Arguments are
redacted by the caller (see :mod:`relay_shell.redaction`) before they arrive here.

The handler is rotation-safe (:class:`logging.handlers.WatchedFileHandler`):
make ``audit.jsonl`` append-only on disk with ``chattr +a`` and rotate it with
the bundled logrotate config; the handler reopens the file after rotation.

Audit failures must never break a tool call: if the sink cannot be opened the
logger degrades to stderr (or silence) and records ``degraded=True``.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import sys
import threading
from dataclasses import dataclass
from logging.handlers import WatchedFileHandler
from pathlib import Path
from typing import Any

from .util import now_iso, sha256_hex

__all__ = ["AuditLogger", "ChainResult", "verify_chain"]


def _format_jsonl(entry: dict[str, Any]) -> str:
    return json.dumps(entry, default=str, ensure_ascii=False)


def _stringify(value: Any) -> str:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return str(value)
    return json.dumps(value, default=str, ensure_ascii=False, separators=(",", ":"))


def _cef_escape(value: str) -> str:
    # CEF extension escaping for separators and line breaks.
    return (
        value.replace("\\", "\\\\")
        .replace("=", "\\=")
        .replace("|", "\\|")
        .replace("\n", "\\n")
        .replace("\r", "\\r")
    )


def _leef_escape(value: str) -> str:
    # LEEF extension escaping with tab-separated key-value fields.
    return (
        value.replace("\\", "\\\\")
        .replace("=", "\\=")
        .replace("\t", "\\t")
        .replace("\n", "\\n")
        .replace("\r", "\\r")
    )


def _format_cef(entry: dict[str, Any]) -> str:
    ext = " ".join(f"{k}={_cef_escape(_stringify(v))}" for k, v in sorted(entry.items()))
    return f"CEF:0|relay-shell|relay-shell|1.0|audit|tool-call|5|{ext}"


def _format_leef(entry: dict[str, Any]) -> str:
    ext = "\t".join(f"{k}={_leef_escape(_stringify(v))}" for k, v in sorted(entry.items()))
    return f"LEEF:2.0|relay-shell|relay-shell|1.0|audit\t{ext}"


_FORMATTERS = {"jsonl": _format_jsonl, "cef": _format_cef, "leef": _format_leef}


# --- Tamper-evident hash chain (opt-in; see docs/adr/0007-audit-hash-chain.md) ---

# Anchor for the first record of a from-scratch chain (seq 0). A rotated
# file inherits its anchor from the last record of the prior file, carried
# forward in that record's `chain` and the next record's `prev`.
_CHAIN_GENESIS = "0" * 64


def _chain_value(prev: str, entry_without_chain: dict[str, Any]) -> str:
    """SHA-256 over the previous chain hash + the canonical record body.

    The body is serialized with sorted keys and compact separators so the
    value is independent of dict insertion order and of the on-disk
    formatter: a verifier reconstructs the exact same input from a parsed
    JSONL line by dropping the record's own ``chain`` field. Any edit,
    insertion, interior deletion, or reordering of records breaks the
    recomputation or the ``prev`` linkage downstream. (Head/tail truncation
    of the file is a separate concern handled by the genesis anchor and the
    off-host copy — see :func:`verify_chain` and ADR 0007.)
    """
    canonical = json.dumps(
        entry_without_chain,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
        ensure_ascii=False,
    )
    return sha256_hex(prev + canonical)


def _is_chained(rec: Any) -> bool:
    """True if ``rec`` is a JSONL record carrying the three chain fields."""
    return (
        isinstance(rec, dict)
        and isinstance(rec.get("seq"), int)
        and isinstance(rec.get("prev"), str)
        and isinstance(rec.get("chain"), str)
    )


@dataclass(frozen=True)
class ChainResult:
    """Outcome of :func:`verify_chain` over one on-disk audit file."""

    ok: bool
    records: int  # chained records verified
    start_seq: int | None  # seq of the first chained record (anchor)
    start_prev: str | None  # the first record's `prev` (cross-file anchor)
    broken_at: int | None  # 1-based line number of the first break, else None
    reason: str
    # True iff the verified region begins at genesis (seq 0, prev == genesis).
    # A keyless single-file chain can prove the records from its first to its
    # last are unaltered and contiguous, but NOT that its first record is the
    # true beginning (head-truncation) or its last the true end (tail-
    # truncation). `anchored` is the head-truncation signal: a log that was
    # built from genesis but no longer starts there has had leading records
    # removed. Tail-truncation is undetectable from the file alone and is
    # caught only by the off-host seam comparison. See ADR 0007.
    anchored: bool = False
    # Whether the audit file existed and was readable. `verify_chain` is
    # structural and treats a missing file as "no break found" (ok=True,
    # records=0); the CLI applies a fail-closed policy and rejects a missing
    # or empty log so `--verify-audit` never blesses an absent audit trail.
    present: bool = True


def verify_chain(path: str) -> ChainResult:
    """Verify the hash chain of an audit ``jsonl`` file.

    Walks the file once, skipping any leading legacy (unchained) records,
    and verifies that from the first chained record to EOF the chain is
    internally consistent: each ``seq`` increments by one, each ``prev``
    equals the previous record's ``chain``, and each record's body
    recomputes to its stated ``chain``.

    What this proves, and what it does NOT (a keyless single-file chain):
    it proves the records from the first surviving one to the last are
    unaltered, contiguous, and correctly ordered. It does *not* prove the
    first surviving record is the true beginning (head-truncation) or the
    last is the true end (tail-truncation) — both leave a shorter but
    internally valid sub-chain. ``ChainResult.anchored`` is the
    head-truncation signal: a log built from genesis but no longer starting
    at seq 0 / genesis ``prev`` has had leading records removed (or is a
    mid-stream rotation segment). Tail-truncation is undetectable from the
    file alone; catch it with the cross-rotation seam against the off-host
    copy (the prior file's last ``chain`` == this file's first ``prev``).
    Never raises.
    """
    try:
        p = Path(path).expanduser()
        if not p.is_file():
            return ChainResult(
                True, 0, None, None, None, f"audit file not found: {path}", present=False
            )
    except Exception as exc:  # noqa: BLE001 - never raise from a verifier
        return ChainResult(
            False, 0, None, None, None, f"cannot access audit file: {exc}", present=False
        )

    records = 0
    started = False
    start_seq: int | None = None
    start_prev: str | None = None
    expected_seq = 0
    expected_prev = _CHAIN_GENESIS
    try:
        with p.open("r", encoding="utf-8", errors="replace") as fh:
            for lineno, raw in enumerate(fh, start=1):
                line = raw.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    if started:
                        return ChainResult(
                            False,
                            records,
                            start_seq,
                            start_prev,
                            lineno,
                            f"line {lineno}: invalid JSON inside the chained region",
                        )
                    continue
                if not _is_chained(rec):
                    if started:
                        return ChainResult(
                            False,
                            records,
                            start_seq,
                            start_prev,
                            lineno,
                            f"line {lineno}: record missing chain fields inside the chained region",
                        )
                    continue  # leading legacy / unchained record
                if not started:
                    started = True
                    start_seq = expected_seq = rec["seq"]
                    start_prev = expected_prev = rec["prev"]
                    if rec["seq"] == 0 and rec["prev"] != _CHAIN_GENESIS:
                        return ChainResult(
                            False,
                            records,
                            start_seq,
                            start_prev,
                            lineno,
                            f"line {lineno}: seq 0 must anchor to genesis",
                        )
                if rec["seq"] != expected_seq:
                    return ChainResult(
                        False,
                        records,
                        start_seq,
                        start_prev,
                        lineno,
                        f"line {lineno}: expected seq {expected_seq}, found {rec['seq']}",
                    )
                if rec["prev"] != expected_prev:
                    return ChainResult(
                        False,
                        records,
                        start_seq,
                        start_prev,
                        lineno,
                        f"line {lineno}: prev does not match the previous record's chain",
                    )
                body = {k: v for k, v in rec.items() if k != "chain"}
                if _chain_value(rec["prev"], body) != rec["chain"]:
                    return ChainResult(
                        False,
                        records,
                        start_seq,
                        start_prev,
                        lineno,
                        f"line {lineno}: record body does not match its chain hash (tampered)",
                    )
                records += 1
                expected_prev = rec["chain"]
                expected_seq += 1
    except OSError as exc:
        return ChainResult(False, records, start_seq, start_prev, None, f"read error: {exc}")

    if not started:
        return ChainResult(
            True, 0, None, None, None, "no chained records found (empty or unchained log)"
        )
    anchored = start_seq == 0 and start_prev == _CHAIN_GENESIS
    if anchored:
        reason = f"chain intact and genesis-anchored: {records} record(s) from seq 0"
    else:
        # Internally valid, but the first surviving record is not genesis:
        # either leading records were excised (head-truncation) or this is a
        # mid-stream rotation segment. The verifier cannot tell which from one
        # file; the fail-closed CLI rejects this by default and the operator
        # asserts a rotation segment with `--segment`.
        reason = (
            f"chain internally consistent: {records} record(s) from seq {start_seq}, "
            f"but NOT genesis-anchored (leading records removed, or a mid-stream "
            f"rotation segment — verify the seam against the prior file)"
        )
    return ChainResult(True, records, start_seq, start_prev, None, reason, anchored=anchored)


class AuditLogger:
    """Writes structured audit records. Construction never raises."""

    def __init__(
        self,
        path: str,
        also_stderr: bool = False,
        fmt: str = "jsonl",
        chain: bool = False,
    ) -> None:
        self.path = path
        self.degraded = False
        self.degraded_reason = ""
        self.format = fmt
        # Tamper-evident chain state. Serialized by `_chain_lock` so the
        # ordering invariant (seq monotonic, prev == previous chain) holds
        # even if a future caller records from another thread (e.g. the
        # seccomp-notify supervisor in ADR 0006). When `chain` is off the
        # lock is never taken and the record path is byte-identical to v0.1.
        self.chain = chain
        self._chain_lock = threading.Lock()
        self._seq = 0
        self._prev = _CHAIN_GENESIS
        self._log = logging.getLogger("relay_shell.audit")
        self._log.setLevel(logging.INFO)
        self._log.propagate = False
        for handler in list(self._log.handlers):
            # Close before removing so the prior WatchedFileHandler releases
            # its file descriptor deterministically instead of waiting on
            # the next GC pass. Re-initializing AuditLogger on the same
            # process-global logger (--check-config, tests) used to leak
            # one fd per construction.
            with contextlib.suppress(Exception):
                handler.close()
            self._log.removeHandler(handler)

        sink: logging.Handler
        try:
            target = Path(path).expanduser()
            target.parent.mkdir(parents=True, exist_ok=True)
            # Pre-create using O_APPEND to stay compatible with append-only
            # hardened files (e.g., chattr +a on Linux).
            fd = os.open(str(target), os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
            os.close(fd)
            # Defensive for existing files that might already be too permissive.
            with contextlib.suppress(OSError):
                target.chmod(0o600)
            sink = WatchedFileHandler(str(target), encoding="utf-8")
        except OSError as exc:  # unwritable path -> degrade, never crash
            self.degraded = True
            self.degraded_reason = str(exc)
            sink = logging.StreamHandler(sys.stderr)
        sink.setFormatter(logging.Formatter("%(message)s"))
        self._log.addHandler(sink)

        if also_stderr and not self.degraded:
            echo = logging.StreamHandler(sys.stderr)
            echo.setFormatter(logging.Formatter("AUDIT %(message)s"))
            self._log.addHandler(echo)

        if self.chain:
            self._resume_chain()

    def _resume_chain(self) -> None:
        """Continue an existing chain across restarts and log rotation.

        Reads the last on-disk record and resumes from its ``seq`` + ``chain``
        so a restart does not reset the chain to genesis mid-stream.
        Best-effort: a missing / empty / unchained / unparseable tail leaves
        the chain at genesis (seq 0). That produces a *visible seam* a
        verifier reports — a seq reset, never a silent gap. Never raises;
        construction of the audit logger must not fail.
        """
        with contextlib.suppress(Exception):
            last = self.tail(1).strip()
            if not last:
                return
            rec = json.loads(last)
            if _is_chained(rec):
                self._seq = int(rec["seq"]) + 1
                self._prev = str(rec["chain"])

    def record(
        self,
        *,
        tool: str,
        args: dict[str, Any],
        output: str,
        exit_code: int | None,
        tier: int,
        request_id: str = "",
        client_id: str = "",
        denied: bool = False,
    ) -> None:
        """Append one audit line. Best-effort; swallows its own errors."""
        entry: dict[str, Any] = {
            "ts": now_iso(),
            "tool": tool,
            "tier": tier,
            "denied": denied,
            "args": args,
            "output_sha256": sha256_hex(output),
            "output_len": len(output.encode("utf-8", "replace")),
            "exit_code": exit_code,
        }
        if request_id:
            entry["request_id"] = request_id
        if client_id:
            entry["client_id"] = client_id
        # Audit must never break a tool call.
        with contextlib.suppress(Exception):
            formatter = _FORMATTERS.get(self.format, _format_jsonl)
            if self.chain:
                # Append the chain fields (seq/prev), commit to them with a
                # `chain` hash, and advance the in-memory anchor only after
                # the line is emitted. If emit raises, the chain does not
                # advance, so it stays consistent with what is on disk.
                with self._chain_lock:
                    entry["seq"] = self._seq
                    entry["prev"] = self._prev
                    chain = _chain_value(self._prev, entry)
                    entry["chain"] = chain
                    self._log.info(formatter(entry))
                    self._seq += 1
                    self._prev = chain
            else:
                self._log.info(formatter(entry))

    def tail(self, lines: int) -> str:
        """Return the last ``lines`` audit records as on-disk text lines.

        Records are returned in their original on-disk order (oldest first).
        The empty string is returned if the audit file does not exist, is
        empty, or cannot be read - this method must never raise; it is
        consumed by a read-only diagnostic tool and a failure here should
        not break the caller.

        Reading is opened on a fresh fd; the writer's append-only fd is
        untouched so this is safe to call concurrently with normal tool
        execution. ``WatchedFileHandler`` line-buffers each emit, so any
        record returned here is structurally complete.

        Implementation reads backward from end-of-file in 8 KiB chunks
        and stops as soon as it has ``lines + 1`` newlines (the +1
        catches a partial leading line). Worst-case memory is bounded
        by ``lines * record_size + chunk_size``, not by file size, so
        the bounded-execution invariant holds even when the audit log
        has not rotated in a long time.
        """
        if lines <= 0:
            return ""
        # Outer `except Exception` keeps the contract literal: even an
        # exotic OSError subclass, a ValueError from a path with an
        # embedded NUL, or an unexpected decoding failure must collapse
        # to "" rather than propagate to the diagnostic tool's caller.
        try:
            path = Path(self.path).expanduser()
            with path.open("rb") as fh:
                fh.seek(0, os.SEEK_END)
                size = fh.tell()
                if size == 0:
                    return ""

                chunk_size = 8192
                data = b""
                offset = size
                # Read backward until we have at least one more newline
                # than requested, or we hit the start of the file.
                while offset > 0 and data.count(b"\n") <= lines:
                    read = min(chunk_size, offset)
                    offset -= read
                    fh.seek(offset)
                    data = fh.read(read) + data

            text = data.decode("utf-8", errors="replace")
            # Drop blank trailing lines (logger does not write them, but
            # a caller might tail a partial write window) and strip the
            # line terminator on each record for consistent line output.
            records = [ln for ln in text.splitlines() if ln.strip()]
            return "\n".join(records[-lines:])
        except Exception:  # noqa: BLE001 - contract is "never raise"
            return ""
