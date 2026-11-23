"""Small, dependency-free helpers: time, hashing, clamping, truncation, ids."""

from __future__ import annotations

import hashlib
import secrets
from datetime import UTC, datetime

__all__ = [
    "clamp",
    "gen_id",
    "now_iso",
    "sha256_hex",
    "truncate",
]


def now_iso() -> str:
    """Current UTC time as an ISO 8601 string with offset."""
    return datetime.now(UTC).isoformat()


def sha256_hex(data: str | bytes) -> str:
    """Hex SHA-256 of a string (UTF-8) or bytes."""
    if isinstance(data, str):
        data = data.encode("utf-8", "replace")
    return hashlib.sha256(data).hexdigest()


def clamp(value: int, lo: int, hi: int) -> int:
    """Clamp ``value`` into the inclusive ``[lo, hi]`` range."""
    if lo > hi:
        lo, hi = hi, lo
    return max(lo, min(hi, value))


def truncate(text: str, limit: int) -> str:
    """Return ``text`` truncated to ``limit`` UTF-8 bytes with a marker.

    Truncation is on a byte budget (not characters) so the result is safe to
    hash and bound regardless of multi-byte content.
    """
    raw = text.encode("utf-8", "replace")
    if len(raw) <= limit:
        return text
    head = raw[:limit].decode("utf-8", "replace")
    return f"{head}\n\n[TRUNCATED - {len(raw)} bytes total, {limit} shown]"


# 128 bits of entropy (defence in depth). Session and forward handles act as
# bearer handles: whoever presents one can drive the PTY or close the forward.
# Today every approved client can already list them (sessions are shared by
# design, docs/auth.md), so guessing adds nothing; the wider id keeps handles
# unguessable if they ever appear where the listing does not (logs, transcripts,
# a future per-client view). The previous token_hex(6) gave 48 bits.
_ID_ENTROPY_BYTES = 16


def gen_id(prefix: str) -> str:
    """An unguessable id (128 random bits, hex) with a human-readable prefix."""
    return f"{prefix}-{secrets.token_hex(_ID_ENTROPY_BYTES)}"
