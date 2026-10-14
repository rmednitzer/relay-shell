"""A14-R10: cancelling a close/sweep must not leak sessions or leave a child running."""

from __future__ import annotations

import asyncio
import contextlib
import os
import signal
import time

from relay_shell.sessions import LocalPtyTransport, SessionRegistry


class _Gated:
    """Session transport whose aclose waits on a gate and records completion."""

    def __init__(self, gate: asyncio.Event | None = None) -> None:
        self.gate = gate
        self.started = asyncio.Event()
        self.closed = False

    async def write(self, data: bytes) -> None:
        return None

    def resize(self, cols: int, rows: int) -> None:
        return None

    def signal(self, sig: int) -> None:
        return None

    @property
    def returncode(self) -> int | None:
        return None

    async def read_loop(self, sink: object) -> None:
        await asyncio.Event().wait()

    async def aclose(self) -> None:
        self.started.set()
        if self.gate is not None:
            await self.gate.wait()
        self.closed = True


async def _add(reg: SessionRegistry, tr: _Gated) -> str:
    sess = await reg.add(kind="local", title="t", transport=tr, cols=80, rows=24)
    return sess.id


async def test_cancelled_sweep_still_tears_down_every_doomed_session() -> None:
    """Pre-fix: ``_sweep`` popped all doomed sessions, then a cancel during the first
    teardown left the rest unregistered and never closed (orphaned children and fds)."""
    reg = SessionRegistry(max_sessions=8, idle_timeout=0.05, buffer_cap=65536)
    gate = asyncio.Event()
    first, second = _Gated(gate), _Gated(gate)
    await _add(reg, first)
    await _add(reg, second)
    await asyncio.sleep(0.2)  # both idle past the window

    sweep = asyncio.ensure_future(reg._sweep())
    await asyncio.wait_for(first.started.wait(), 2)
    sweep.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await sweep
    assert sweep.cancelled()

    gate.set()
    for _ in range(100):
        if first.closed and second.closed:
            break
        await asyncio.sleep(0.02)
    assert first.closed and second.closed, "an unregistered session was never torn down"
    assert reg.count() == 0


async def test_cancelled_close_still_finishes_teardown() -> None:
    reg = SessionRegistry(max_sessions=8, idle_timeout=60, buffer_cap=65536)
    gate = asyncio.Event()
    tr = _Gated(gate)
    sid = await _add(reg, tr)

    closing = asyncio.ensure_future(reg.close(sid))
    await asyncio.wait_for(tr.started.wait(), 2)
    closing.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await closing
    assert closing.cancelled()

    gate.set()
    for _ in range(100):
        if tr.closed:
            break
        await asyncio.sleep(0.02)
    assert tr.closed, "the session was unregistered but its transport was never closed"


async def test_cancelled_shutdown_still_tears_down_every_session() -> None:
    reg = SessionRegistry(max_sessions=8, idle_timeout=60, buffer_cap=65536)
    gate = asyncio.Event()
    trs = [_Gated(gate), _Gated(gate), _Gated(gate)]
    for tr in trs:
        await _add(reg, tr)

    stopping = asyncio.ensure_future(reg.shutdown())
    await asyncio.wait_for(trs[0].started.wait(), 2)
    stopping.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await stopping

    gate.set()
    for _ in range(100):
        if all(t.closed for t in trs):
            break
        await asyncio.sleep(0.02)
    assert all(t.closed for t in trs)


async def test_cancelled_aclose_kills_a_term_ignoring_child() -> None:
    """Pre-fix: a cancel during the SIGTERM grace wait skipped SIGKILL, so a child that
    ignores SIGTERM kept running after its session was gone."""
    tr = await LocalPtyTransport.spawn(
        ["/bin/sh", "-c", 'trap "" TERM; echo up; while :; do sleep 0.1; done'],
        cwd=None,
        env=dict(os.environ),
        cols=80,
        rows=24,
    )
    pid = tr._proc.pid
    await asyncio.sleep(0.3)  # let the shell install its trap
    closing = asyncio.ensure_future(tr.aclose())
    await asyncio.sleep(0.3)  # SIGTERM sent and ignored; now inside the grace wait
    closing.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await closing

    deadline = time.monotonic() + 3
    alive = True
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            alive = False
            break
        # A zombie still answers kill(0); reap it through the asyncio handle.
        if tr._proc.returncode is not None:
            alive = False
            break
        await asyncio.sleep(0.05)
    if alive:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(os.getpgid(pid), signal.SIGKILL)
    assert not alive, "a cancelled close left a SIGTERM-ignoring child running"
