"""Unit tests for SshPool that don't need an in-process SSH server.

The heavier integration tests in ``test_ssh_integration.py`` exercise
the real asyncssh protocol stack; these unit tests focus on the
connection-cache + single-flight semantics in isolation by
monkeypatching ``asyncssh.connect``.
"""

from __future__ import annotations

import asyncio
import time
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


class _GatedStream:
    """A remote stream that blocks on ``read`` until released, then EOFs.

    Models a long-running command: ``run`` parks in ``_drain`` awaiting the
    first chunk, giving a concurrent idle sweep a window to (wrongly) evict
    the connection the run is still using.
    """

    def __init__(self, gate: asyncio.Event) -> None:
        self._gate = gate
        self._done = False

    async def read(self, _n: int) -> bytes:
        if self._done:
            return b""
        await self._gate.wait()
        self._done = True
        return b""


class _GatedProc:
    def __init__(self, gate: asyncio.Event) -> None:
        self.stdout = _GatedStream(gate)
        self.stderr = _GatedStream(gate)
        self.exit_status = 0

    async def wait_closed(self) -> None:
        return None

    def terminate(self) -> None:  # pragma: no cover - not hit on the happy path
        pass


class _GatedConn(_MockConn):
    def __init__(self, gate: asyncio.Event) -> None:
        super().__init__()
        self._gate = gate

    async def create_process(self, *_a: object, **_k: object) -> _GatedProc:
        return _GatedProc(self._gate)


async def test_long_run_connection_not_evicted_mid_flight(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A long ``run`` pins its connection so a concurrent idle sweep cannot
    close it mid-drain.

    Regression for the idle-reaper-vs-in-use bug on the ``run`` path. ``run``
    connects once and drives the channel directly, so its cache entry's
    ``last_used`` freezes at connect time. When ``max_timeout`` exceeds
    ``ssh_idle_timeout`` (both are independently configurable — a valid
    posture), a run can outlive the idle window; before the fix a concurrent
    ``connect()``'s ``_sweep_conns`` then evicted and closed the connection out
    from under the running command. ``run`` now pins for its whole duration.
    """
    gate = asyncio.Event()
    conn = _GatedConn(gate)

    async def fake_connect(*_a: object, **_k: object) -> _GatedConn:
        return conn

    monkeypatch.setattr(asyncssh, "connect", fake_connect)

    settings = Settings(
        transport="stdio",
        audit_path=str(tmp_path / "audit.jsonl"),
        ssh_known_hosts="ignore",
        ssh_config=str(tmp_path / "no_ssh_config"),
        ssh_idle_timeout=300,  # aggressive reaping ...
        max_timeout=3600,  # ... while long commands are permitted
    )
    inv = Inventory(str(tmp_path / "no_ssh_config"), "").load()
    pool = SshPool(settings=settings, inventory=inv)

    run_task = asyncio.create_task(
        pool.run("h1.example", "sleep 3600", timeout=3600, connect_kwargs=_CK)
    )
    try:
        # Let run connect + reach the drain, then confirm it pinned.
        for _ in range(50):
            await asyncio.sleep(0)
            if pool._conns:
                break
        key = next(iter(pool._conns))
        assert pool._conns[key].pins == 1, "an in-flight run must pin its connection"

        # Age the entry past the idle window and fire the sweep. The pin holds.
        pool._conns[key].last_used = time.monotonic() - 1000
        await pool._sweep_conns()
        assert key in pool._conns, "run's live connection must survive the idle sweep"
        assert not conn.is_closed(), "run's connection must not be closed mid-flight"
    finally:
        gate.set()  # let the command finish
        _out, code = await asyncio.wait_for(run_task, 5)
    assert code == 0
    # Pin released once run returned; the now-idle entry becomes evictable.
    assert pool._conns[key].pins == 0
    pool._conns[key].last_used = time.monotonic() - 1000
    await pool._sweep_conns()
    assert key not in pool._conns, "connection is evictable once the run completes"


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


async def test_sweep_conns_respects_pins(tmp_path: Path) -> None:
    """Idle reaper must not evict a pinned (in-use) connection.

    Regression for the idle-reaper-vs-in-use bug: a session / forward /
    in-flight transfer holds a connection that nothing has re-``connect()``ed
    to recently, so its ``last_used`` ages past the idle timeout. Before the
    fix the sweep evicted it and closed the socket out from under the live
    holder. With pin-counting the sweep skips ``pins > 0`` and only reaps once
    the last holder releases.
    """
    from relay_shell.sshpool import _ConnEntry

    settings = Settings(
        transport="stdio",
        audit_path=str(tmp_path / "audit.jsonl"),
        ssh_known_hosts="ignore",
        ssh_config=str(tmp_path / "no_ssh_config"),
        ssh_idle_timeout=1,
    )
    inv = Inventory(str(tmp_path / "no_ssh_config"), "").load()
    pool = SshPool(settings=settings, inventory=inv)

    conn = _MockConn()
    # last_used far in the past so the idle window has elapsed.
    entry = _ConnEntry(conn=conn, last_used=time.monotonic() - 3600, pins=1)
    pool._conns["u@h:22"] = entry

    await pool._sweep_conns()
    assert "u@h:22" in pool._conns, "pinned connection must survive the idle sweep"
    assert not conn.is_closed(), "pinned connection must not be closed"

    # Release the pin. _unpin refreshes last_used (release counts as recent
    # activity), so re-age the entry before the next sweep to prove it is now
    # evictable purely because it is no longer pinned.
    await pool._unpin(entry)
    entry.last_used = time.monotonic() - 3600
    await pool._sweep_conns()
    assert "u@h:22" not in pool._conns, "unpinned + idle connection must be evicted"
    assert conn.is_closed(), "evicted connection must be closed"


async def test_sweep_conns_evicts_closed_even_if_pinned(tmp_path: Path) -> None:
    """A *closed* connection is dead regardless of pins and must be purged so a
    re-connect does not return a dead handle — pinning only defends against
    *idle* eviction, never against reaping an already-broken socket."""
    from relay_shell.sshpool import _ConnEntry

    settings = Settings(
        transport="stdio",
        audit_path=str(tmp_path / "audit.jsonl"),
        ssh_known_hosts="ignore",
        ssh_config=str(tmp_path / "no_ssh_config"),
        ssh_idle_timeout=1800,
    )
    inv = Inventory(str(tmp_path / "no_ssh_config"), "").load()
    pool = SshPool(settings=settings, inventory=inv)

    conn = _MockConn()
    conn.close()  # mark closed/dead
    entry = _ConnEntry(conn=conn, last_used=time.monotonic(), pins=2)
    pool._conns["u@h:22"] = entry

    await pool._sweep_conns()
    assert "u@h:22" not in pool._conns, "closed connection must be purged even when pinned"


class _FakeProc:
    def __init__(self) -> None:
        self.terminated = False

    def terminate(self) -> None:
        self.terminated = True

    async def wait_closed(self) -> None:
        return None


class _ProcConn(_MockConn):
    """Conn surface for open_process: exposes create_process."""

    def __init__(self) -> None:
        super().__init__()
        self.proc = _FakeProc()

    async def create_process(self, *_a: object, **_k: object) -> _FakeProc:
        return self.proc


async def test_open_process_pins_and_transport_aclose_unpins(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A spawned session pins its connection for its whole lifetime and the
    transport releases the pin in ``aclose`` — so a mid-session idle sweep
    cannot evict the connection, but a closed session no longer holds it.
    """
    conn = _ProcConn()

    async def fake_connect(*_a: object, **_k: object) -> _ProcConn:
        return conn

    monkeypatch.setattr(asyncssh, "connect", fake_connect)

    settings = Settings(
        transport="stdio",
        audit_path=str(tmp_path / "audit.jsonl"),
        ssh_known_hosts="ignore",
        ssh_config=str(tmp_path / "no_ssh_config"),
        ssh_idle_timeout=1,
    )
    inv = Inventory(str(tmp_path / "no_ssh_config"), "").load()
    pool = SshPool(settings=settings, inventory=inv)

    tr = await pool.open_process("h1.example", command="", cols=80, rows=24, connect_kwargs=_CK)
    key = next(iter(pool._conns))
    assert pool._conns[key].pins == 1, "open_process must pin the connection"

    # Age the entry past the idle window; the pin must keep it alive.
    pool._conns[key].last_used = time.monotonic() - 3600
    await pool._sweep_conns()
    assert key in pool._conns, "pinned session connection survives the idle sweep"

    # Closing the session releases the pin; the now-idle connection is reaped.
    await tr.aclose()
    assert pool._conns[key].pins == 0, "aclose must release the pin"
    pool._conns[key].last_used = time.monotonic() - 3600
    await pool._sweep_conns()
    assert key not in pool._conns, "connection is evictable once the session closes"


async def test_add_forward_enforces_cap(tmp_path: Path) -> None:
    """SSH-3: a saturated forward pool refuses new forwards.

    A persuaded client looping ``ssh_forward`` would otherwise grow
    ``_forwards`` without bound and exhaust local fds / listen ports. The
    pre-check fires before any dial, so this needs no real connection.
    """
    from relay_shell.errors import ForwardError
    from relay_shell.sshpool import ForwardHandle

    settings = Settings(
        transport="stdio",
        audit_path=str(tmp_path / "audit.jsonl"),
        ssh_known_hosts="ignore",
        ssh_config=str(tmp_path / "no_ssh_config"),
        max_forwards=2,
    )
    inv = Inventory(str(tmp_path / "no_ssh_config"), "").load()
    pool = SshPool(settings=settings, inventory=inv)
    for i in range(2):
        pool._forwards[f"fwd-{i}"] = ForwardHandle(
            f"fwd-{i}", "local", "L:0:localhost:22", 1000 + i, "localhost:22", object()
        )
    assert pool.forward_count() == 2
    with pytest.raises(ForwardError, match="forward limit reached"):
        await pool.add_forward("h", "L:0:localhost:22", connect_kwargs={})
    # The refused call neither dialled nor grew the registry.
    assert pool.forward_count() == 2
