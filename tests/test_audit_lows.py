"""Low-severity items from the 2026-10-04 audit (L1, L2, L3, L6, L7, L9)."""

from __future__ import annotations

import asyncio
import gc
import logging
from pathlib import Path
from typing import Any

import asyncssh
import pytest

import relay_shell.sshpool as sshpool_mod
from relay_shell.__main__ import _note_env_file, main
from relay_shell.config import Settings, get_settings
from relay_shell.inventory import Inventory
from relay_shell.sessions import SessionRegistry, _utf8_cut
from relay_shell.sshpool import SshPool


def _pool(tmp_path: Path) -> SshPool:
    cfg = Settings(
        audit_path=str(tmp_path / "audit.jsonl"),
        ssh_known_hosts="ignore",
        ssh_config=str(tmp_path / "none"),
        ssh_keepalive=0,
    )
    return SshPool(settings=cfg, inventory=Inventory(cfg.ssh_config, "").load())


# --- L1: a failed connect must not leave an unretrieved future ----------------


async def test_failed_connect_logs_no_unretrieved_future(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    contexts: list[dict[str, Any]] = []
    asyncio.get_running_loop().set_exception_handler(lambda _loop, ctx: contexts.append(ctx))

    async def refuse(*_a: object, **_k: object) -> Any:
        raise OSError("connection refused")

    monkeypatch.setattr(asyncssh, "connect", refuse)
    pool = _pool(tmp_path)
    with pytest.raises(OSError, match="refused"):
        await pool.connect("h.example")
    gc.collect()
    await asyncio.sleep(0)
    assert [c.get("message") for c in contexts if "never retrieved" in str(c.get("message"))] == []


# --- L2: a lingering channel is not a command timeout -------------------------


class _Stream:
    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = chunks

    async def read(self, _n: int) -> bytes:
        return self._chunks.pop(0) if self._chunks else b""


class _LingeringProc:
    def __init__(self) -> None:
        self.stdout = _Stream([b"hello\n"])
        self.stderr = _Stream([])
        self.exit_status = 0

    def terminate(self) -> None:  # pragma: no cover - must not be needed
        raise AssertionError("a finished command must not be terminated")

    async def wait_closed(self) -> None:
        await asyncio.Event().wait()  # the peer never closes the channel


class _LingeringConn:
    def is_closed(self) -> bool:
        return False

    async def create_process(self, *_a: object, **_k: object) -> _LingeringProc:
        return _LingeringProc()


async def test_a_channel_that_lingers_after_eof_keeps_the_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sshpool_mod, "_WAIT_CLOSED_TIMEOUT", 0.05)
    pool = _pool(tmp_path)

    async def fake_connect(*_a: object, **_k: object) -> _LingeringConn:
        return _LingeringConn()

    monkeypatch.setattr(pool, "connect", fake_connect)
    out, code = await pool.run("h.example", "echo hello", timeout=30, connect_kwargs={})
    assert out == "hello\n"
    assert code == 0
    assert "TIMEOUT" not in out


# --- L3: a bad deny/allow regex is a clean configuration error ----------------


@pytest.mark.parametrize("field", ["policy_deny", "policy_allow"])
def test_invalid_policy_regex_is_rejected_at_load(field: str) -> None:
    with pytest.raises(ValueError, match=f"{field} is not a valid regular expression"):
        Settings(**{field: "("})
    assert Settings(**{field: r"^ssh_keyscan|rm\s+-rf"})


def test_main_reports_an_invalid_policy_regex_without_a_traceback(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("RELAY_SHELL_POLICY_DENY", "(")
    get_settings.cache_clear()
    try:
        assert main([]) == 2
        err = capsys.readouterr().err
        assert "invalid configuration" in err and "policy_deny" in err
        assert "Traceback" not in err
    finally:
        get_settings.cache_clear()


def test_main_reports_a_server_assembly_failure_cleanly(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    monkeypatch.setenv("RELAY_SHELL_AUDIT_PATH", str(tmp_path / "a.jsonl"))
    get_settings.cache_clear()

    def boom(_settings: Settings) -> None:
        raise RuntimeError("assembly broke")

    monkeypatch.setattr("relay_shell.__main__.build_server", boom)
    try:
        assert main([]) == 2
        assert "build_server failed: assembly broke" in capsys.readouterr().err
    finally:
        get_settings.cache_clear()


# --- L6: session_recv must not split a multibyte character --------------------


@pytest.mark.parametrize("text", ["é" * 40, "日本語のテキスト" * 5, "😀" * 20, "a😀b" * 15])
@pytest.mark.parametrize("chunk", [1, 2, 3, 4, 5, 7])
def test_utf8_cut_never_splits_a_character(text: str, chunk: int) -> None:
    data = bytearray(text.encode())
    out = bytearray()
    while data:
        n = _utf8_cut(data, chunk)
        assert 0 < n <= max(chunk, 4) or n == len(data)
        out += data[:n]
        del data[:n]
    assert bytes(out).decode() == text  # strict decode: no U+FFFD, nothing lost


def test_utf8_cut_falls_back_on_binary_data() -> None:
    assert _utf8_cut(bytearray(b"\x80" * 20), 5) == 5
    assert _utf8_cut(bytearray(b"abc"), 10) == 3


class _OneShotTransport:
    def __init__(self, payload: bytes) -> None:
        self._payload = payload
        self.returncode = None

    async def write(self, data: bytes) -> None:  # pragma: no cover
        pass

    def resize(self, cols: int, rows: int) -> None:  # pragma: no cover
        pass

    def signal(self, sig: int) -> None:  # pragma: no cover
        pass

    async def read_loop(self, sink: object) -> None:
        assert callable(sink)
        sink(self._payload)
        await asyncio.Event().wait()

    async def aclose(self) -> None:
        pass


async def test_recv_reassembles_multibyte_text_across_small_reads() -> None:
    text = "héllo wörld 日本 😀 fin"
    reg = SessionRegistry(2, 60, 65536)
    try:
        sess = await reg.add(
            kind="local",
            title="t",
            transport=_OneShotTransport(text.encode()),
            cols=80,
            rows=24,
        )
        got = ""
        for _ in range(60):
            chunk = await reg.recv(sess.id, 0.05, 5)
            if not chunk:
                break
            got += chunk
        assert got == text
        assert "�" not in got
    finally:
        await reg.shutdown()


# --- L9: `ProxyJump none` means no jump host ----------------------------------


def test_proxyjump_none_is_no_jump_host(tmp_path: Path) -> None:
    cfg = tmp_path / "config"
    cfg.write_text(
        "Host direct\n  HostName 10.0.0.1\n  ProxyJump none\n"
        "Host viabastion\n  HostName 10.0.0.2\n  ProxyJump bastion.example\n"
    )
    inv_file = tmp_path / "inv.json"
    inv_file.write_text('{"x": {"hostname": "10.0.0.3", "jump": "None"}}')
    inv = Inventory(str(cfg), str(inv_file)).load()
    assert inv.resolve("direct").jump is None
    assert inv.resolve("viabastion").jump == "bastion.example"
    assert inv.resolve("x").jump is None


# --- L7: say so when settings come from ./.env --------------------------------


def test_env_file_in_the_working_directory_is_logged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.chdir(tmp_path)
    with caplog.at_level(logging.WARNING, logger="relay_shell"):
        _note_env_file()
        assert caplog.records == []  # nothing to report without a .env
        (tmp_path / ".env").write_text("RELAY_SHELL_POLICY_MODE=open\n")
        _note_env_file()
    (rec,) = caplog.records
    assert str(tmp_path / ".env") in rec.getMessage()
    assert "working directory" in rec.getMessage()
