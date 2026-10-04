"""Input typed at a secret prompt must not reach the audit log (audit H5, M6).

``session_send`` audited its ``data`` argument after keyword redaction only. A
password typed at a ``sudo`` prompt has no keyword, so it was written verbatim
to a log that is meant to be shipped off-host - and the tool docs recommend
exactly that workflow.
"""

from __future__ import annotations

import asyncio
import json
import re
import time
from pathlib import Path
from typing import Any

import pytest

from relay_shell.config import Settings
from relay_shell.server import build_server
from relay_shell.sessions import SessionRegistry, _looks_like_secret_prompt

# A prompt with echo off, exactly like sudo / ssh / passwd while reading a secret.
_PROMPT_CMD = "/bin/sh -c 'printf \"[sudo] password for bob: \"; stty -echo; read x; echo done'"
# Echo off but no recognisable prompt text: only the terminal state gives it away.
_SILENT_CMD = "/bin/sh -c 'stty -echo; sleep 30'"
_SECRET = "hunter2-S3cr3tV4lue"


def _text(result: Any) -> str:
    return "".join(getattr(c, "text", "") for c in result.content)


def _sid(spawn_out: str) -> str:
    match = re.search(r"session (\S+) started", spawn_out)
    assert match, spawn_out
    return match.group(1)


def _audit(settings: Settings) -> list[dict[str, Any]]:
    path = Path(settings.audit_path)
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


async def _wait_for(reg: SessionRegistry, sid: str, needle: str) -> None:
    deadline = time.monotonic() + 5
    seen = ""
    while needle not in seen and time.monotonic() < deadline:
        seen += await reg.recv(sid, 0.2, 4096)
    assert needle in seen, seen


@pytest.mark.parametrize(
    ("tail", "expected"),
    [
        (b"[sudo] password for bob: ", True),
        (b"Password:", True),
        (b"Enter passphrase for key '/home/u/.ssh/id_ed25519': ", True),
        (b"\x1b[1mPassword\x1b[0m: ", True),  # ANSI-decorated
        (b"Verification code: ", True),
        (b"line one\r\nPassword: ", True),  # only the last line counts
        (b"Password: ok\r\nuser@host:~$ ", False),  # prompt already answered
        (b"user@host:~$ ", False),
        (b"the password policy requires 12 characters\r\n", False),
        (b"", False),
    ],
)
def test_secret_prompt_detection(tail: bytes, expected: bool) -> None:
    assert _looks_like_secret_prompt(tail) is expected


async def test_registry_flags_a_password_prompt_and_clears_it_on_send() -> None:
    reg = SessionRegistry(4, 60, 65536)
    sess = None
    try:
        from relay_shell.sessions import LocalPtyTransport

        transport = await LocalPtyTransport.spawn(
            ["/bin/sh", "-c", 'printf "Password: "; read x; echo got'],
            cwd=None,
            env={"PATH": "/usr/bin:/bin"},
            cols=80,
            rows=24,
        )
        sess = await reg.add(kind="local", title="t", transport=transport, cols=80, rows=24)
        await _wait_for(reg, sess.id, "Password:")
        assert await reg.awaiting_secret(sess.id) is True
        await reg.send(sess.id, b"anything\n")
        assert await reg.awaiting_secret(sess.id) is False  # the prompt was answered
    finally:
        await reg.shutdown()


async def test_registry_detects_echo_off_without_any_prompt_text() -> None:
    from relay_shell.sessions import LocalPtyTransport

    reg = SessionRegistry(4, 60, 65536)
    try:
        transport = await LocalPtyTransport.spawn(
            ["/bin/sh", "-c", "stty -echo; sleep 30"],
            cwd=None,
            env={"PATH": "/usr/bin:/bin"},
            cols=80,
            rows=24,
        )
        sess = await reg.add(kind="local", title="t", transport=transport, cols=80, rows=24)
        deadline = time.monotonic() + 5
        # Polling a kernel tty flag: there is no event to wait on.
        while not await reg.awaiting_secret(sess.id) and time.monotonic() < deadline:  # noqa: ASYNC110
            await asyncio.sleep(0.05)
        assert await reg.awaiting_secret(sess.id) is True
    finally:
        await reg.shutdown()


async def test_unknown_session_is_not_a_secret_prompt() -> None:
    assert await SessionRegistry(1, 60, 1024).awaiting_secret("nope") is False


async def test_typed_secret_is_withheld_from_the_audit_log(settings: Settings) -> None:
    mcp = build_server(settings)
    sid = _sid(_text(await mcp.call_tool("shell_spawn", {"command": _PROMPT_CMD})))
    try:
        await asyncio.sleep(0.5)  # let the prompt render
        await mcp.call_tool("session_send", {"session_id": sid, "data": _SECRET})
    finally:
        await mcp.call_tool("session_kill", {"session_id": sid})

    raw = Path(settings.audit_path).read_text(encoding="utf-8")
    assert _SECRET not in raw
    (rec,) = [r for r in _audit(settings) if r["tool"] == "session_send"]
    assert rec["args"]["data"] == "[REDACTED: secret prompt]"
    assert rec["args"]["data_len"] == len(_SECRET)
    assert rec["args"]["session_id"] == sid


async def test_typed_secret_with_echo_off_and_no_prompt_text_is_withheld(
    settings: Settings,
) -> None:
    mcp = build_server(settings)
    sid = _sid(_text(await mcp.call_tool("shell_spawn", {"command": _SILENT_CMD})))
    try:
        await asyncio.sleep(0.5)
        await mcp.call_tool("session_send", {"session_id": sid, "data": _SECRET})
    finally:
        await mcp.call_tool("session_kill", {"session_id": sid})
    assert _SECRET not in Path(settings.audit_path).read_text(encoding="utf-8")


async def test_ordinary_input_is_still_audited_verbatim(settings: Settings) -> None:
    """Compatibility: a normal command typed into a session is recorded as before."""
    mcp = build_server(settings)
    sid = _sid(_text(await mcp.call_tool("shell_spawn", {"command": "/bin/sh"})))
    try:
        await asyncio.sleep(0.3)
        await mcp.call_tool("session_send", {"session_id": sid, "data": "echo hello-world"})
    finally:
        await mcp.call_tool("session_kill", {"session_id": sid})
    (rec,) = [r for r in _audit(settings) if r["tool"] == "session_send"]
    assert rec["args"]["data"] == "echo hello-world"
    assert "data_len" not in rec["args"]


async def test_hash_mode_never_records_typed_content(settings: Settings) -> None:
    from relay_shell.util import sha256_hex

    mcp = build_server(settings.model_copy(update={"audit_session_input": "hash"}))
    sid = _sid(_text(await mcp.call_tool("shell_spawn", {"command": "/bin/sh"})))
    try:
        await asyncio.sleep(0.3)
        await mcp.call_tool("session_send", {"session_id": sid, "data": "echo hello-world"})
    finally:
        await mcp.call_tool("session_kill", {"session_id": sid})
    raw = Path(settings.audit_path).read_text(encoding="utf-8")
    assert "hello-world" not in raw
    (rec,) = [r for r in _audit(settings) if r["tool"] == "session_send"]
    assert "data" not in rec["args"]
    assert rec["args"]["data_len"] == len("echo hello-world")
    assert rec["args"]["data_sha256"] == sha256_hex("echo hello-world")


def test_audit_session_input_rejects_unknown_values(settings: Settings) -> None:
    with pytest.raises(ValueError, match="audit_session_input"):
        Settings(audit_session_input="full")
    assert Settings(audit_session_input=" HASH ").audit_session_input == "hash"


# --- M6: the identity used by transfers, forwards and spawns is audited -------


async def test_transfer_forward_and_spawn_audit_the_connection_identity(
    settings: Settings, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    mcp = build_server(settings)
    relay = mcp.relay  # type: ignore[attr-defined]

    async def boom(*_a: object, **_k: object) -> Any:
        raise OSError("no network in this test")

    monkeypatch.setattr(relay.ssh, "connect", boom)
    ident = {
        "user": "deploy",
        "port": 2222,
        "key_path": "/keys/id_a",
        "jump": "bastion.example",
        "known_hosts": "strict",
    }
    local = tmp_path / "f"
    local.write_text("x")
    await mcp.call_tool(
        "ssh_upload",
        {
            "host": "h",
            "local_path": str(local),
            "remote_path": "/r",
            "recursive": True,
            **ident,
        },
    )
    await mcp.call_tool(
        "ssh_download", {"host": "h", "remote_path": "/r", "local_path": str(local), **ident}
    )
    await mcp.call_tool("ssh_forward", {"host": "h", "spec": "D:1080", **ident})
    await mcp.call_tool("ssh_spawn", {"host": "h", **ident})

    by_tool = {r["tool"]: r["args"] for r in _audit(settings)}
    for tool in ("ssh_upload", "ssh_download", "ssh_forward", "ssh_spawn"):
        args = by_tool[tool]
        assert args["user"] == "deploy", tool
        assert args["port"] == 2222, tool
        assert args["key_path"] == "/keys/id_a", tool
        assert args["jump"] == "bastion.example", tool
        assert args["known_hosts"] == "strict", tool
    assert by_tool["ssh_upload"]["recursive"] is True
    assert by_tool["ssh_download"]["recursive"] is False
