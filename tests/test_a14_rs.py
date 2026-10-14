"""A14-RS regressions: seccomp degraded wiring, cancellation windows, SSH target tokens.

Each test fails on the code before the fix (reproduce-then-fix, see BACKLOG A14-RS).
"""

from __future__ import annotations

import asyncio
import contextlib
from pathlib import Path
from typing import Any

import asyncssh
import pytest

from relay_shell import seccomp
from relay_shell.config import Settings
from relay_shell.errors import RelayError
from relay_shell.inventory import Inventory
from relay_shell.server import Relay
from relay_shell.sshpool import SshPool

_CK: dict[str, object] = {"user": "", "port": 0, "key_path": "", "known_hosts": "", "jump": ""}


def _pool(tmp_path: Path, config_text: str = "") -> SshPool:
    cfg = tmp_path / "ssh_config"
    cfg.write_text(config_text)
    settings = Settings(
        transport="stdio",
        audit_path=str(tmp_path / "audit.jsonl"),
        ssh_known_hosts="ignore",
        ssh_config=str(cfg),
        ssh_connect_timeout=5,
        ssh_keepalive=0,
    )
    return SshPool(settings=settings, inventory=Inventory(str(cfg), "").load())


class _Conn:
    def __init__(self) -> None:
        self._closed = False
        self.proc = _Proc()
        self.listener = _Listener()

    def is_closed(self) -> bool:
        return self._closed

    def close(self) -> None:
        self._closed = True

    async def create_process(self, *_a: object, **_k: object) -> _Proc:
        return self.proc

    async def forward_local_port(self, *_a: object, **_k: object) -> _Listener:
        hook = getattr(self, "after_listen", None)
        if hook is not None:
            await hook()
        return self.listener


class _Proc:
    def __init__(self) -> None:
        self.terminated = False
        self.closed = False

    def terminate(self) -> None:
        self.terminated = True

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        return None


class _Listener:
    def __init__(self) -> None:
        self.closed = False

    def get_port(self) -> int:
        return 4242

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        return None


async def _hold_lock(pool: SshPool) -> tuple[asyncio.Event, asyncio.Event, asyncio.Task[None]]:
    held, release = asyncio.Event(), asyncio.Event()

    async def _holder() -> None:
        async with pool._lock:
            held.set()
            await release.wait()

    task = asyncio.ensure_future(_holder())
    await held.wait()
    return held, release, task


# -- on_degraded is wired ---------------------------------------------------


def test_seccomp_degrade_marks_audit_degraded(
    settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A monitor that fails open must surface as an audit gap (ADR 0006)."""
    monkeypatch.setattr(
        seccomp,
        "platform_support",
        lambda: seccomp.PlatformSupport(True, "", "x86_64", "6.1"),
    )
    relay = Relay(settings.model_copy(update={"seccomp_notify": True}))
    assert not relay.audit.degraded
    monitor = relay._seccomp_monitor("req-1")
    assert monitor is not None
    monitor._degrade("no usable seccomp handshake from child")
    assert relay.audit.degraded
    assert "seccomp" in relay.audit.degraded_reason
    assert "no usable seccomp handshake" in relay.audit.degraded_reason


def test_seccomp_degrade_keeps_the_first_reason(
    settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        seccomp,
        "platform_support",
        lambda: seccomp.PlatformSupport(True, "", "x86_64", "6.1"),
    )
    relay = Relay(settings.model_copy(update={"seccomp_notify": True}))
    relay.audit.mark_degraded("audit write failed at runtime")
    monitor = relay._seccomp_monitor("req-1")
    assert monitor is not None
    monitor._degrade("later")
    assert relay.audit.degraded_reason == "audit write failed at runtime"


# -- cancellation windows ---------------------------------------------------


async def test_open_process_cancelled_while_pinning_releases_process(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Cancelled between create_process and the transport: no orphaned remote PTY."""
    conn = _Conn()

    async def fake_connect(*_a: object, **_k: object) -> _Conn:
        return conn

    monkeypatch.setattr(asyncssh, "connect", fake_connect)
    pool = _pool(tmp_path)
    await pool.connect("h1.example")  # warm the cache so the open path is lock-only
    _, release, holder = await _hold_lock(pool)

    task = asyncio.ensure_future(
        pool.open_process("h1.example", command="", cols=80, rows=24, connect_kwargs=_CK)
    )
    await asyncio.sleep(0.05)  # parked on pool._lock inside connect()/_pin()
    task.cancel()
    release.set()
    await holder
    with contextlib.suppress(asyncio.CancelledError):
        await task
    assert task.cancelled()
    # Whichever await the cancel landed on, nothing may be left behind.
    key = next(iter(pool._conns))
    assert pool._conns[key].pins == 0
    if conn.proc.terminated or conn.proc.closed:
        assert conn.proc.closed


async def test_open_process_cancel_after_create_process_closes_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    conn = _Conn()
    gate = asyncio.Event()
    created = asyncio.Event()

    async def slow_create(*_a: object, **_k: object) -> _Proc:
        created.set()
        return conn.proc

    conn.create_process = slow_create  # type: ignore[method-assign]

    async def fake_connect(*_a: object, **_k: object) -> _Conn:
        return conn

    monkeypatch.setattr(asyncssh, "connect", fake_connect)
    pool = _pool(tmp_path)
    await pool.connect("h1.example")

    real_pin = pool._pin

    async def blocked_pin(c: Any) -> Any:
        gate.set()
        await asyncio.sleep(3600)
        return await real_pin(c)

    pool._pin = blocked_pin  # type: ignore[method-assign]
    task = asyncio.ensure_future(
        pool.open_process("h1.example", command="", cols=80, rows=24, connect_kwargs=_CK)
    )
    await gate.wait()
    assert created.is_set()
    task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await task
    assert conn.proc.closed, "the opened remote process must be closed on cancellation"


async def test_add_forward_cancelled_before_tracking_closes_listener(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Cancelled after the listener exists but before it is tracked: it must not leak."""
    conn = _Conn()

    async def fake_connect(*_a: object, **_k: object) -> _Conn:
        return conn

    monkeypatch.setattr(asyncssh, "connect", fake_connect)
    pool = _pool(tmp_path)
    await pool.connect("h1.example")

    held = asyncio.Event()
    release = asyncio.Event()

    async def _holder() -> None:
        async with pool._lock:
            held.set()
            await release.wait()

    holder: asyncio.Task[None] | None = None

    async def after_listen() -> None:
        # Start contending for the pool lock only once the listener is bound.
        nonlocal holder
        holder = asyncio.ensure_future(_holder())
        await held.wait()

    conn.after_listen = after_listen  # type: ignore[attr-defined]
    task = asyncio.ensure_future(
        pool.add_forward("h1.example", "L:0:localhost:22", connect_kwargs=_CK)
    )
    await held.wait()
    await asyncio.sleep(0.05)  # add_forward is now parked on the tracking lock
    task.cancel()
    release.set()
    assert holder is not None
    await holder
    with contextlib.suppress(asyncio.CancelledError):
        await task
    assert task.cancelled()
    assert pool.forward_count() == 0
    assert conn.listener.closed, "an untracked listener would stay bound forever"
    key = next(iter(pool._conns))
    assert pool._conns[key].pins == 0


# -- caller-supplied SSH target tokens ---------------------------------------

_PROXY_CFG = "Host *\n  ProxyCommand ssh -W %h:%p bastion\n"


@pytest.mark.parametrize(
    "target",
    [
        "x -oProxyCommand=touch$IFS/tmp/pwn y",
        "-oProxyCommand=id",
        "host\nevil ssh-rsa AAAA",
        "host;id",
        "$(id)",
        "h\tx",
        "a b",
        "",
        "u@-oProxyCommand=id",
        "-x@host",
        "u v@host",
        "h" * 300,
    ],
)
async def test_connect_rejects_hostile_targets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, target: str
) -> None:
    """The host/user are substituted into ProxyCommand tokens and known_hosts lines."""
    called: list[object] = []

    async def fake_connect(*a: object, **_k: object) -> _Conn:
        called.append(a)
        return _Conn()

    monkeypatch.setattr(asyncssh, "connect", fake_connect)
    pool = _pool(tmp_path, _PROXY_CFG)
    with pytest.raises(RelayError, match="invalid ssh"):
        await pool.connect(target)
    assert not called, "asyncssh must never see a hostile target"


@pytest.mark.parametrize(
    ("kw"),
    [
        {"user": "a b"},
        {"user": "-oProxyCommand=id"},
        {"user": "a;b"},
        {"user": "$(id)"},
        {"jump": "j1 -oProxyCommand=id"},
        {"jump": "ok,evil host"},
        {"jump": "-oProxyCommand=id"},
        {"jump": "u v@j"},
        {"jump": "j,"},
    ],
)
async def test_connect_rejects_hostile_user_and_jump(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kw: dict[str, str]
) -> None:
    called: list[object] = []

    async def fake_connect(*a: object, **_k: object) -> _Conn:
        called.append(a)
        return _Conn()

    monkeypatch.setattr(asyncssh, "connect", fake_connect)
    pool = _pool(tmp_path, _PROXY_CFG)
    with pytest.raises(RelayError, match="invalid ssh"):
        await pool.connect("h1.example", **kw)  # type: ignore[arg-type]
    assert not called


@pytest.mark.parametrize(
    "target",
    [
        "db1.example",
        "db1",
        "10.0.0.5",
        "u@db1.example",
        "svc_user@db-1.example.org",
        "[2001:db8::1]",
        "2001:db8::1",
        "fe80::1%eth0",
        "u@[2001:db8::1]",
        "Host_1",
    ],
)
async def test_connect_accepts_ordinary_targets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, target: str
) -> None:
    async def fake_connect(*_a: object, **_k: object) -> _Conn:
        return _Conn()

    monkeypatch.setattr(asyncssh, "connect", fake_connect)
    pool = _pool(tmp_path)
    assert await pool.connect(target, jump="j1.example,ops@j2.example:2222") is not None


async def test_connect_trusts_operator_inventory_aliases(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Operator-written aliases and hostnames are not caller input and stay as written."""

    async def fake_connect(*_a: object, **_k: object) -> _Conn:
        return _Conn()

    monkeypatch.setattr(asyncssh, "connect", fake_connect)
    pool = _pool(tmp_path, "Host bastion+ops\n  Hostname real.example\n")
    # An ssh_config alias is a literal key in the inventory, so it is trusted as-is.
    assert pool.inventory.knows("bastion+ops")
    assert await pool.connect("bastion+ops") is not None
