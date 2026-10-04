"""A cancelled call must still be audited and must not leave its command running.

Regression for audit finding H1 (2026-10-04): ``Relay.run`` wrote the audit
record only after ``work()`` returned and caught ``Exception`` (not
``CancelledError``), and the executors killed their child only on timeout. A
client disconnect or MCP cancellation therefore produced an executed command
with no audit record and an orphaned process.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import time
from pathlib import Path
from typing import Any

import pytest

from relay_shell.config import Settings
from relay_shell.inventory import Inventory
from relay_shell.server import Relay
from relay_shell.shelltools import run_command
from relay_shell.sshpool import SshPool
from relay_shell.util import sha256_hex


def _records(settings: Settings) -> list[dict[str, Any]]:
    path = Path(settings.audit_path)
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def _wait_for_text(path: Path, timeout: float = 5.0) -> str:
    """Block (off the loop) until ``path`` holds non-empty text."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with contextlib.suppress(OSError):
            text = path.read_text().strip()
            if text:
                return text
        time.sleep(0.02)
    raise AssertionError(f"{path} was never written")


async def _run(relay: Relay, work: Any, *, text: str = "echo hi") -> str:
    return await relay.run(
        tool="shell_exec",
        ctx=None,
        audit_args={"command": text},
        policy_text=text,
        max_output=4096,
        work=work,
    )


async def test_cancelled_call_is_audited_and_reraised(settings: Settings) -> None:
    relay = Relay(settings)
    started = asyncio.Event()

    async def work() -> tuple[str, int | None]:
        started.set()
        await asyncio.Event().wait()  # never finishes on its own
        return ("unreachable", 0)

    task = asyncio.create_task(_run(relay, work))
    await started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    (rec,) = _records(settings)
    assert rec["tool"] == "shell_exec"
    assert rec["action"] == "cancelled"
    assert rec["denied"] is False
    assert rec["exit_code"] is None
    assert rec["args"] == {"command": "echo hi"}
    assert rec["output_sha256"] == sha256_hex("[CANCELLED]")  # a marker, never a body
    counters = relay.metrics.snapshot_counters()["relay_shell_tool_calls_total"]
    key = (("mode", "open"), ("outcome", "cancelled"), ("tier", "1"), ("tool", "shell_exec"))
    assert counters[key] == 1


async def test_cancel_kills_the_local_command(tmp_path: Path) -> None:
    pidfile = tmp_path / "pid"
    marker = tmp_path / "marker"
    task = asyncio.create_task(
        run_command(f"echo $$ > {pidfile}; sleep 2; touch {marker}", timeout=60)
    )
    pid = int(await asyncio.to_thread(_wait_for_text, pidfile))
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    await asyncio.sleep(2.5)  # long enough for the command to have finished on its own
    assert not marker.exists(), "the cancelled command kept running"
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)


class _HangingStream:
    async def read(self, _n: int) -> bytes:
        await asyncio.Event().wait()
        return b""


class _Proc:
    def __init__(self) -> None:
        self.stdout = _HangingStream()
        self.stderr = _HangingStream()
        self.exit_status = None
        self.terminated = False

    def terminate(self) -> None:
        self.terminated = True

    async def wait_closed(self) -> None:
        return None


class _Conn:
    def __init__(self) -> None:
        self.proc = _Proc()
        self.created = asyncio.Event()

    def is_closed(self) -> bool:
        return False

    async def create_process(self, *_a: object, **_k: object) -> _Proc:
        self.created.set()
        return self.proc


async def test_cancel_terminates_the_remote_command(
    settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    conn = _Conn()
    pool = SshPool(settings=settings, inventory=Inventory(settings.ssh_config, "").load())

    async def fake_connect(*_a: object, **_k: object) -> _Conn:
        return conn

    monkeypatch.setattr(pool, "connect", fake_connect)
    task = asyncio.create_task(
        pool.run("h.example", "sleep 999", timeout=60, connect_kwargs={}, max_output_bytes=1024)
    )
    await conn.created.wait()
    await asyncio.sleep(0)  # let run() park in the drain
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert conn.proc.terminated


async def test_intent_record_is_written_before_the_work_runs(settings: Settings) -> None:
    relay = Relay(settings.model_copy(update={"audit_intent": True}))
    seen_during_work: list[dict[str, Any]] = []

    async def work() -> tuple[str, int | None]:
        seen_during_work.extend(_records(settings))  # what is on disk mid-command
        return ("done", 0)

    await _run(relay, work)

    (during,) = seen_during_work
    assert during["action"] == "intent"
    assert during["exit_code"] is None
    intent, done = _records(settings)
    assert intent == during
    assert "action" not in done
    assert done["exit_code"] == 0
    assert done["args"] == intent["args"]


async def test_default_stays_one_record_per_call(settings: Settings) -> None:
    relay = Relay(settings)

    async def work() -> tuple[str, int | None]:
        return ("done", 0)

    await _run(relay, work)
    (rec,) = _records(settings)
    assert "action" not in rec


async def test_denied_call_writes_no_intent_record(settings: Settings) -> None:
    cfg = settings.model_copy(update={"audit_intent": True, "policy_deny": "forbidden"})
    relay = Relay(cfg)

    async def work() -> tuple[str, int | None]:  # pragma: no cover - must not run
        raise AssertionError("denied work executed")

    await _run(relay, work, text="forbidden thing")
    (rec,) = _records(settings)
    assert rec["denied"] is True
    assert "action" not in rec


async def test_cancel_before_start_does_not_break_the_runner(settings: Settings) -> None:
    """A task cancelled while still queued must not corrupt later calls."""
    relay = Relay(settings)

    async def slow() -> tuple[str, int | None]:
        await asyncio.sleep(10)
        return ("x", 0)

    async def quick() -> tuple[str, int | None]:
        return ("ok", 0)

    task = asyncio.create_task(_run(relay, slow))
    await asyncio.sleep(0)
    task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await task
    assert (await _run(relay, quick)).startswith("[exit 0]")
