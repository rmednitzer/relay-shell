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
from logging.handlers import WatchedFileHandler
from pathlib import Path
from typing import Any

from .util import now_iso, sha256_hex

__all__ = ["AuditLogger"]


class AuditLogger:
    """Writes structured audit records. Construction never raises."""

    def __init__(self, path: str, also_stderr: bool = False) -> None:
        self.path = path
        self.degraded = False
        self.degraded_reason = ""
        self._log = logging.getLogger("relay_shell.audit")
        self._log.setLevel(logging.INFO)
        self._log.propagate = False
        for handler in list(self._log.handlers):
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
            self._log.info(json.dumps(entry, default=str, ensure_ascii=False))

    def tail(self, lines: int) -> str:
        """Return the last ``lines`` audit records as JSONL.

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
            # line terminator on each record for consistent JSONL output.
            records = [ln for ln in text.splitlines() if ln.strip()]
            return "\n".join(records[-lines:])
        except Exception:  # noqa: BLE001 - contract is "never raise"
            return ""
