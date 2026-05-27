"""Unit tests for SshPool that don't need an in-process SSH server.

The heavier integration tests in ``test_ssh_integration.py`` exercise
the real asyncssh protocol stack; these unit tests focus on the
connection-cache + single-flight semantics in isolation by
monkeypatching ``asyncssh.connect``.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import asyncssh
import pytest

from relay_shell.config import Settings
from relay_shell.inventory import Inventory
from relay_shell.sshpool import SshPool


class _MockConn:
    """Minimal asyncssh connection surface used by SshPool."""

    def __init__(self) -> None:
        self._closed = False

    def is_closed(self) -> bool:
        return self._closed

    def close(self) -> None:
        self._closed = True


def _make_pool(tmp_path: Path) -> SshPool:
    settings = Settings(
        transport="stdio",
        audit_path=str(tmp_path / "audit.jsonl"),
        ssh_known_hosts="ignore",
        ssh_config=str(tmp_path / "no_ssh_config"),
        ssh_connect_timeout=5,
        ssh_keepalive=0,
    )
    inv = Inventory(str(tmp_path / "no_ssh_config"), "").load()
    return SshPool(settings=settings, inventory=inv)


async def test_connect_single_flight_for_same_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """F-2 regression: concurrent connect() to the same target dedupes.

    Pre-fix N concurrent connect() callers for the same key each missed
    the cache (the cache check happened inside the lock; the
    ``asyncssh.connect`` happened outside), so each fired a real connect
    and N-1 of those connections were silently leaked when the second
    writer overwrote the cache slot.
    """
    call_count = 0

    async def fake_connect(*_args: object, **_kwargs: object) -> _MockConn:
        nonlocal call_count
        call_count += 1
        # Yield long enough for other callers to pile up at the cache miss.
        await asyncio.sleep(0.05)
        return _MockConn()

    monkeypatch.setattr(asyncssh, "connect", fake_connect)
    pool = _make_pool(tmp_path)

    conns = await asyncio.gather(*[pool.connect("h1.example") for _ in range(5)])

    assert call_count == 1, (
        f"single-flight: expected 1 underlying asyncssh.connect, got {call_count}. "
        "Pre-fix this would be 5."
    )
    assert all(c is conns[0] for c in conns), (
        "All concurrent callers must receive the same connection object."
    )


async def test_connect_different_targets_do_not_dedupe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Distinct targets must NOT share a single in-flight slot — the
    cache key is ``user@host:port`` and single-flighting per-key only."""
    call_count = 0

    async def fake_connect(*_args: object, **_kwargs: object) -> _MockConn:
        nonlocal call_count
        call_count += 1
        await asyncio.sleep(0.02)
        return _MockConn()

    monkeypatch.setattr(asyncssh, "connect", fake_connect)
    pool = _make_pool(tmp_path)

    await asyncio.gather(
        pool.connect("h1.example"),
        pool.connect("h2.example"),
        pool.connect("h3.example"),
    )

    assert call_count == 3


async def test_connect_failure_clears_inflight_slot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A failed connect must clear the in-flight future so a follow-up
    call retries rather than awaits a stale failed future forever."""
    attempts = 0

    async def fake_connect(*_args: object, **_kwargs: object) -> _MockConn:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise OSError("simulated transport failure")
        return _MockConn()

    monkeypatch.setattr(asyncssh, "connect", fake_connect)
    pool = _make_pool(tmp_path)

    with pytest.raises(OSError, match="simulated"):
        await pool.connect("h1.example")
    # Slot must be released; a follow-up attempt re-dials.
    conn = await pool.connect("h1.example")
    assert conn is not None
    assert attempts == 2
