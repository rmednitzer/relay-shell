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
    "utf8_len",
]


def now_iso() -> str:
    """Current UTC time as an ISO 8601 string with offset."""
    return datetime.now(UTC).isoformat()


def sha256_hex(data: str | bytes) -> str:
    """Hex SHA-256 of a string (UTF-8) or bytes."""
    if isinstance(data, str):
        data = data.encode("utf-8", "replace")
    return hashlib.sha256(data).hexdigest()


def utf8_len(text: str) -> int:
    """Length of ``text`` in UTF-8 bytes."""
    return len(text.encode("utf-8", "replace"))


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


def gen_id(prefix: str) -> str:
    """A short, unguessable id with a human-readable prefix."""
    return f"{prefix}-{secrets.token_hex(6)}"
