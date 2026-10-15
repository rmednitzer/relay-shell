from __future__ import annotations

import asyncio
import os
import re
import signal
import time
from pathlib import Path

import pytest

from relay_shell.config import Settings
from relay_shell.errors import SessionError
from relay_shell.sessions import LocalPtyTransport, SessionRegistry


async def _spawn(reg: SessionRegistry, argv: list[str]) -> str:
    tr = await LocalPtyTransport.spawn(argv, cwd=None, env=dict(os.environ), cols=80, rows=24)
    sess = await reg.add(kind="local", title=" ".join(argv), transport=tr, cols=80, rows=24)
    return sess.id


async def test_local_pty_roundtrip() -> None:
    reg = SessionRegistry(max_sessions=8, idle_timeout=60, buffer_cap=65536)
    try:
        sid = await _spawn(reg, ["/bin/cat"])
        await reg.send(sid, b"ping-123\n")
        out = await reg.recv(sid, timeout=3.0, max_bytes=4096)
        assert "ping-123" in out
        await reg.kill(sid, signal.SIGTERM)
        await reg.close(sid)
    finally:
        await reg.shutdown()


async def test_recv_timeout_returns_empty_quickly() -> None:
    reg = SessionRegistry(8, 60, 65536)
    try:
        sid = await _spawn(reg, ["/bin/cat"])
        out = await reg.recv(sid, timeout=0.2, max_bytes=1024)
        assert out == ""
    finally:
        await reg.shutdown()


async def test_session_limit_enforced() -> None:
    reg = SessionRegistry(max_sessions=1, idle_timeout=60, buffer_cap=4096)
    try:
        await _spawn(reg, ["/bin/cat"])
        with pytest.raises(SessionError):
            await _spawn(reg, ["/bin/cat"])
    finally:
        await reg.shutdown()


async def test_unknown_session_raises() -> None:
    reg = SessionRegistry(8, 60, 4096)
    with pytest.raises(SessionError):
        await reg.recv("nope", 0.1, 100)


async def test_closed_session_reports_exit() -> None:
    reg = SessionRegistry(8, 60, 65536)
    try:
        sid = await _spawn(reg, ["/bin/sh", "-c", "echo done; exit 0"])
        seen = ""
        for _ in range(20):
            seen += await reg.recv(sid, timeout=0.5, max_bytes=4096)
            if "ended" in seen or "done" in seen:
                break
        assert "done" in seen or "ended" in seen
    finally:
        await reg.shutdown()


async def test_session_recv_ended_message_shape_with_exit() -> None:
    """Pin the exact wire shape of the ``ended`` sentinel when exit_code is known.

    Client renderers grep for this marker, so the shape is frozen (leading
    newline, bracket pair, ``exit=N`` field). Both branches (with and without
    exit) sit side by side in ``SessionRegistry.recv``; test both.
    """
    reg = SessionRegistry(8, 60, 65536)
    pattern = re.compile(r"^\n\[session [A-Za-z0-9_\-]+ ended, exit=-?\d+\]$")
    try:
        sid = await _spawn(reg, ["/bin/sh", "-c", "exit 0"])
        sess = reg._sessions[sid]
        # Drain any preamble to reach the closed-buffer branch.
        for _ in range(40):
            await reg.recv(sid, timeout=0.2, max_bytes=4096)
            if sess.closed and not sess.buffer:
                break
        # Force exit_code directly instead of waiting for the OS to set
        # returncode on the asyncio process: the branch under test is
        # "closed with exit_code set" vs "closed with exit_code None", and
        # where exit_code came from is irrelevant to the wire format.
        sess.exit_code = 7
        out = await reg.recv(sid, timeout=0.1, max_bytes=4096)
        assert pattern.match(out), f"unexpected ended shape: {out!r}"
        assert out == f"\n[session {sid} ended, exit=7]"
    finally:
        await reg.shutdown()


async def test_session_recv_ended_message_shape_without_exit() -> None:
    """When ``exit_code`` is None at teardown, the marker omits the exit field."""
    reg = SessionRegistry(8, 60, 65536)
    pattern = re.compile(r"^\n\[session [A-Za-z0-9_\-]+ ended\]$")
    try:
        sid = await _spawn(reg, ["/bin/sh", "-c", "exit 0"])
        sess = reg._sessions[sid]
        for _ in range(40):
            await reg.recv(sid, timeout=0.2, max_bytes=4096)
            if sess.closed and not sess.buffer:
                break
        sess.exit_code = None
        out = await reg.recv(sid, timeout=0.1, max_bytes=4096)
        assert pattern.match(out), f"unexpected ended shape: {out!r}"
        assert out == f"\n[session {sid} ended]"
    finally:
        await reg.shutdown()


async def test_active_recv_waiter_not_reaped_by_idle_sweep() -> None:
    """A session with a live ``recv()`` waiter is in use and must survive the sweep.

    Regression: ``recv`` refreshed ``last_used`` only at entry, so a long poll
    (``timeout`` > the registry idle timeout) let the session age past idle
    while a client was blocked on it, and a concurrent ``_sweep`` (fired by
    ``list``) tore it down under the waiter. The sweep now skips any session
    with ``_waiters > 0``.
    """
    # idle_timeout=1s; the recv below polls for 3s, longer than idle.
    reg = SessionRegistry(max_sessions=8, idle_timeout=1, buffer_cap=65536)
    try:
        sid = await _spawn(reg, ["/bin/cat"])  # stays alive, produces no output
        recv_task = asyncio.create_task(reg.recv(sid, timeout=3.0, max_bytes=4096))
        # Let recv register itself as a waiter.
        await asyncio.sleep(0.1)
        assert reg._sessions[sid]._waiters == 1, "recv must mark the session in-use"

        # Wait past the idle window, then trigger a sweep via list().
        await asyncio.sleep(1.3)
        listed = await reg.list()
        assert any(s["id"] == sid for s in listed), (
            "session with a live recv waiter must not be idle-reaped"
        )
        assert sid in reg._sessions

        # The waiter times out and returns empty, not the 'ended' sentinel a
        # mid-wait teardown would inject.
        out = await recv_task
        assert out == "", f"waiter should time out cleanly, got {out!r}"
        assert reg._sessions[sid]._waiters == 0, "waiter count released on return"
    finally:
        await reg.shutdown()


async def test_pty_spawn_failure_does_not_leak_master_fd() -> None:
    """A failed PTY spawn must release both pty ends, not just the slave.

    Regression: when ``create_subprocess_exec`` raised, ``LocalPtyTransport.spawn``
    closed only ``slave_fd``, leaking the master fd once per failed spawn.
    """
    argv = ["/nonexistent-relay-shell-binary"]
    # Warm-up: the first spawn may lazily allocate event-loop plumbing
    # (child-watcher pipes); measure only once that exists.
    with pytest.raises(FileNotFoundError):
        await LocalPtyTransport.spawn(argv, cwd=None, env={}, cols=80, rows=24)
    before = sorted(os.listdir("/proc/self/fd"))
    for _ in range(3):
        with pytest.raises(FileNotFoundError):
            await LocalPtyTransport.spawn(argv, cwd=None, env={}, cols=80, rows=24)
    after = sorted(os.listdir("/proc/self/fd"))
    assert after == before, "failed PTY spawn leaked a file descriptor"


class _RecordingTransport:
    """Transport double that records ``aclose``; satisfies the Protocol."""

    def __init__(self) -> None:
        self.closed = False

    async def write(self, data: bytes) -> None:  # pragma: no cover - unused
        pass

    def resize(self, cols: int, rows: int) -> None:  # pragma: no cover - unused
        pass

    def signal(self, sig: int) -> None:  # pragma: no cover - unused
        pass

    @property
    def returncode(self) -> int | None:
        return None

    async def read_loop(self, sink: object) -> None:
        # Stay "running" until cancelled at teardown, like a live PTY.
        await asyncio.Event().wait()

    async def aclose(self) -> None:
        self.closed = True


async def test_register_session_closes_transport_when_registry_refuses(tmp_path: Path) -> None:
    """The shared spawn-registration path reaps a refused transport (R-003).

    Regression: ``shell_spawn`` / ``ssh_spawn`` registered the new transport
    directly with ``sessions.add``, so a refusal (session limit) surfaced as
    the tool's error string while the running child stayed unsupervised.
    """
    from relay_shell.server import Relay

    settings = Settings(
        transport="stdio",
        audit_path=str(tmp_path / "audit.jsonl"),
        ssh_known_hosts="ignore",
        ssh_config=str(tmp_path / "no_ssh_config"),
        max_sessions=1,
    )
    app = Relay(settings)
    first = _RecordingTransport()
    second = _RecordingTransport()
    try:
        await app.register_session(kind="local", title="one", transport=first, cols=80, rows=24)
        with pytest.raises(SessionError):
            await app.register_session(
                kind="local", title="two", transport=second, cols=80, rows=24
            )
    finally:
        await app.sessions.shutdown()
    assert second.closed, "refused transport must be closed, not leaked"
    assert first.closed  # closed by the registry shutdown, not the failure path


async def test_oversized_winsize_is_clamped_not_leaked(monkeypatch: pytest.MonkeyPatch) -> None:
    # struct.pack("H") raises struct.error above 65535, which is not an OSError,
    # so it escaped _set_winsize and leaked the pty fds in LocalPtyTransport.spawn.
    import fcntl
    import os

    from relay_shell import sessions

    seen: list[bytes] = []
    monkeypatch.setattr(fcntl, "ioctl", lambda _fd, _op, packed: seen.append(packed))
    sessions._set_winsize(0, cols=70000, rows=99999)
    assert seen and seen[0][:4] == b"\xff\xff\xff\xff"
    before = len(os.listdir("/proc/self/fd")) if os.path.isdir("/proc/self/fd") else None
    for _ in range(3):
        tr = await sessions.LocalPtyTransport.spawn(
            ["/bin/sh", "-c", "exit 0"], cwd=None, env=dict(os.environ), cols=70000, rows=70000
        )
        await tr.aclose()
    if before is not None:
        assert len(os.listdir("/proc/self/fd")) <= before + 1


async def _timed_close(argv: list[str], settle: float = 0.4) -> tuple[float, int | None]:
    tr = await LocalPtyTransport.spawn(argv, cwd=None, env=dict(os.environ), cols=80, rows=24)
    await asyncio.sleep(settle)  # let the child install its traps / reach its prompt
    start = time.monotonic()
    await tr.aclose()
    return time.monotonic() - start, tr.returncode


@pytest.mark.parametrize("shell", ["/bin/sh", "/bin/bash"])
async def test_closing_an_interactive_shell_does_not_wait_out_the_sigterm_grace(
    shell: str,
) -> None:
    """Interactive shells ignore SIGTERM, so closing one must not wait out the 5 s grace
    and end in SIGKILL; SIGHUP, which a closing terminal sends, ends it at once."""
    if not Path(shell).exists():
        pytest.skip(f"{shell} not installed")
    elapsed, rc = await _timed_close([shell, "-i"])
    assert elapsed < 2.0, f"close took {elapsed:.2f}s"
    assert rc == -signal.SIGHUP


async def test_close_gives_sigterm_handlers_their_turn_before_hangup() -> None:
    """A daemon that shuts down on SIGTERM but reloads on SIGHUP must see SIGTERM only."""
    script = 'trap "exit 0" TERM; trap "exit 7" HUP; while :; do sleep 0.05; done'
    elapsed, rc = await _timed_close(["/bin/bash", "-c", script])
    assert elapsed < 2.0
    assert rc == 0, "the child saw SIGHUP before its SIGTERM handler could finish"


async def test_close_still_kills_a_child_that_ignores_term_and_hup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from relay_shell import sessions

    monkeypatch.setattr(sessions, "_TERM_GRACE", 1.2)
    script = 'trap "" TERM HUP; while :; do sleep 0.05; done'
    elapsed, rc = await _timed_close(["/bin/sh", "-c", script])
    assert 1.0 < elapsed < 4.0
    assert rc == -signal.SIGKILL


def _live_group_members(pgid: int) -> list[int]:
    """Non-zombie processes in process group ``pgid`` (a reaped-by-nobody zombie is not live)."""
    live = []
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            stat = Path(f"/proc/{entry}/stat").read_text()
        except OSError:
            continue
        state, _ppid, group = stat[stat.rindex(")") + 2 :].split()[:3]
        if state != "Z" and int(group) == pgid:
            live.append(int(entry))
    return live


@pytest.mark.parametrize(
    "script",
    [
        # Leader ignores SIGTERM and ends on SIGHUP; the descendant ignores both.
        'trap "" TERM; (trap "" TERM HUP; exec sleep 300) & wait',
        # Leader ends on SIGTERM (already true before the SIGHUP step).
        '(trap "" TERM HUP; exec sleep 300) & wait',
    ],
    ids=["leader-ends-on-hup", "leader-ends-on-term"],
)
async def test_close_reaps_group_members_that_outlive_the_leader(
    monkeypatch: pytest.MonkeyPatch, script: str
) -> None:
    """The leader exiting says nothing about group descendants that ignore SIGTERM and
    SIGHUP. Regression: close returned with them still running and the session removed."""
    from relay_shell import sessions

    monkeypatch.setattr(sessions, "_TERM_GRACE", 1.5)
    tr = await LocalPtyTransport.spawn(
        ["/bin/bash", "-c", script], cwd=None, env=dict(os.environ), cols=80, rows=24
    )
    pgid = tr._proc.pid
    await asyncio.sleep(0.5)
    assert len(_live_group_members(pgid)) >= 1  # the descendant is up
    await tr.aclose()
    deadline = time.monotonic() + 2
    while _live_group_members(pgid) and time.monotonic() < deadline:  # noqa: ASYNC110
        await asyncio.sleep(0.05)  # SIGKILL delivery is asynchronous; /proc has no event
    leftover = _live_group_members(pgid)
    for pid in leftover:
        os.kill(pid, signal.SIGKILL)
    assert not leftover, f"close left group members running: {leftover}"


async def test_close_with_an_empty_group_does_not_wait_for_the_grace(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from relay_shell import sessions

    monkeypatch.setattr(sessions, "_TERM_GRACE", 5.0)
    elapsed, rc = await _timed_close(["/bin/sleep", "30"])
    assert elapsed < 1.0
    assert rc == -signal.SIGTERM
