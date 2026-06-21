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


class _TrackingConn:
    """Conn variant that records ``close()`` calls."""

    def __init__(self) -> None:
        self._closed = False
        self.close_count = 0

    def is_closed(self) -> bool:
        return self._closed

    def close(self) -> None:
        self._closed = True
        self.close_count += 1


class _SlowSftp:
    """Fake SFTP client whose transfers sleep, to exercise the per-call cap.

    Mirrors the asyncssh surface ``SshPool.sftp_put`` / ``sftp_get`` use:
    ``conn.start_sftp_client()`` returns an async context manager, and
    ``put`` / ``get`` are awaitable transfers.
    """

    def __init__(self, delay: float) -> None:
        self._delay = delay
        self.exited = False

    async def __aenter__(self) -> _SlowSftp:
        return self

    async def __aexit__(self, *_exc: object) -> None:
        self.exited = True

    async def put(self, *_a: object, **_k: object) -> None:
        await asyncio.sleep(self._delay)

    async def get(self, *_a: object, **_k: object) -> None:
        await asyncio.sleep(self._delay)


class _SftpConn(_MockConn):
    def __init__(self, delay: float) -> None:
        super().__init__()
        self.sftp = _SlowSftp(delay)

    def start_sftp_client(self) -> _SlowSftp:
        return self.sftp


_CK: dict[str, object] = {"user": "", "port": 0, "key_path": "", "known_hosts": "", "jump": ""}


async def test_sftp_put_timeout_fires(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # F-6: a hung transfer is bounded by the per-call timeout, not just the
    # connection keepalive. The put sleeps 5s; the 1s cap must win.
    conn = _SftpConn(delay=5.0)

    async def fake_connect(*_a: object, **_k: object) -> _SftpConn:
        return conn

    monkeypatch.setattr(asyncssh, "connect", fake_connect)
    pool = _make_pool(tmp_path)
    msg = await pool.sftp_put(
        "h1.example", "/local/x", "/remote/x", recurse=False, connect_kwargs=_CK, timeout=1
    )
    assert msg.startswith("[TIMEOUT after 1s]")
    assert conn.sftp.exited  # the sftp client was closed on the way out


async def test_sftp_get_timeout_fires(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    conn = _SftpConn(delay=5.0)

    async def fake_connect(*_a: object, **_k: object) -> _SftpConn:
        return conn

    monkeypatch.setattr(asyncssh, "connect", fake_connect)
    pool = _make_pool(tmp_path)
    msg = await pool.sftp_get(
        "h1.example", "/remote/x", "/local/x", recurse=False, connect_kwargs=_CK, timeout=1
    )
    assert msg.startswith("[TIMEOUT after 1s]")


async def test_sftp_put_no_cap_completes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # timeout=0 (the default) keeps the historical behaviour: no per-call cap.
    conn = _SftpConn(delay=0.0)

    async def fake_connect(*_a: object, **_k: object) -> _SftpConn:
        return conn

    monkeypatch.setattr(asyncssh, "connect", fake_connect)
    pool = _make_pool(tmp_path)
    msg = await pool.sftp_put(
        "h1.example", "/local/x", "/remote/x", recurse=False, connect_kwargs=_CK, timeout=0
    )
    assert msg.startswith("uploaded")


async def test_close_all_during_connect_discards_conn(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``close_all`` while an owner's ``asyncssh.connect`` is in flight
    cancels the in-flight future. The owner must NOT cache the
    completed connection (the registry has been cleared) and must NOT
    call ``set_result`` on the cancelled future. It should close the
    connection and surface ``CancelledError``.

    Pre-fix the owner reached ``own_future.set_result(conn)`` on a
    cancelled future, raising ``InvalidStateError`` while leaking the
    connection.
    """
    connect_gate = asyncio.Event()
    tracking: list[_TrackingConn] = []

    async def fake_connect(*_args: object, **_kwargs: object) -> _TrackingConn:
        await connect_gate.wait()
        conn = _TrackingConn()
        tracking.append(conn)
        return conn

    monkeypatch.setattr(asyncssh, "connect", fake_connect)
    pool = _make_pool(tmp_path)

    # Start the connect; it will park at connect_gate.
    task = asyncio.create_task(pool.connect("h1.example"))
    # Yield once so the task reaches the await.
    await asyncio.sleep(0)

    # Trigger close_all while the owner is mid-connect. This cancels the
    # in-flight future on the pending slot.
    await pool.close_all()

    # Release the fake connect so the owner sees it succeed, then has to
    # decide what to do with a now-cancelled future.
    connect_gate.set()

    with pytest.raises((asyncio.CancelledError, BaseException)):
        await task

    # The completed connection must have been closed (not cached) since
    # close_all already cleared the registry.
    assert len(tracking) == 1
    assert tracking[0].close_count == 1, (
        "owner must close the just-completed connection when the in-flight "
        "future was cancelled by close_all"
    )


def test_parse_forward_spec_valid_and_malformed() -> None:
    # QUAL-2: valid specs parse; malformed ones raise a *controlled* ValueError
    # that does not leak raw Python parse internals through the tool wrapper.
    assert SshPool._parse_forward_spec("L:8080:web:80") == ("L", 8080, "web", 80)
    assert SshPool._parse_forward_spec("r:9000:db:5432") == ("R", 9000, "db", 5432)
    assert SshPool._parse_forward_spec("D:1080") == ("D", 1080, "", 0)
    for bad, frag in [
        ("L:notanint:web:80", "invalid L forward spec"),
        ("L:8080:web", "invalid L forward spec"),
        ("R:8080:web:nope", "invalid R forward spec"),
        ("D:notanint", "invalid D forward spec"),
        ("X:1:2:3", "must start with L:, R: or D:"),
    ]:
        with pytest.raises(ValueError) as ei:
            SshPool._parse_forward_spec(bad)
        msg = str(ei.value)
        assert frag in msg, bad
        assert "invalid literal for int" not in msg
        assert "unpack" not in msg
