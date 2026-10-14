"""A14-T1: targeted tests for branches the audit found uncovered.

OAuth load/exchange guards, hash-chain `prev` linkage, `session_kill` signal parsing, the
success paths of the SSH transfer/spawn/forward wrappers, and `RELAY_SHELL_AUDIT_STDERR`.
"""

from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any

import pytest
from mcp.server.auth.provider import AuthorizationCode, TokenError
from mcp.shared.auth import OAuthClientInformationFull

from helpers import audit_lines, text
from relay_shell.audit import AuditLogger, _chain_value, verify_chain
from relay_shell.auth.oauth import FileOAuthProvider
from relay_shell.config import Settings
from relay_shell.server import build_server
from relay_shell.sshpool import ForwardHandle, SshPool

# -- OAuth -----------------------------------------------------------------


def _provider(tmp_path: Path) -> FileOAuthProvider:
    return FileOAuthProvider(
        str(tmp_path / "oauth"),
        single_client=False,
        access_ttl=3600,
        refresh_ttl=86400,
        code_ttl=300,
        require_approval=False,
    )


def _client(cid: str = "client-a") -> OAuthClientInformationFull:
    return OAuthClientInformationFull(client_id=cid, redirect_uris=["https://x/cb"])


def _code_record(
    expires_at: float, client_id: str = "client-a", resource: str | None = None
) -> dict[str, Any]:
    return {
        "client_id": client_id,
        "scopes": ["mcp:tools"],
        "expires_at": expires_at,
        "code_challenge": "",
        "redirect_uri": "https://x/cb",
        "redirect_uri_provided_explicitly": True,
        "resource": resource,
    }


async def test_load_authorization_code_drops_an_expired_code(tmp_path: Path) -> None:
    p = _provider(tmp_path)
    from relay_shell.auth.oauth import _hashed

    p._codes.save({_hashed("expired-code"): _code_record(time.time() - 5)})
    assert await p.load_authorization_code(_client(), "expired-code") is None
    assert p._codes.load() == {}, "the stale record is removed on the way"


async def test_load_authorization_code_refuses_another_clients_code(tmp_path: Path) -> None:
    from relay_shell.auth.oauth import _hashed

    p = _provider(tmp_path)
    p._codes.save({_hashed("code-1"): _code_record(time.time() + 60, "client-a", p._resource)})
    assert await p.load_authorization_code(_client("client-b"), "code-1") is None
    assert await p.load_authorization_code(_client("client-a"), "code-1") is not None


async def test_exchange_authorization_code_refuses_a_different_client(tmp_path: Path) -> None:
    from relay_shell.auth.oauth import _hashed

    p = _provider(tmp_path)
    p._codes.save({_hashed("code-1"): _code_record(time.time() + 60, "client-a")})
    code = AuthorizationCode(
        code="code-1",
        scopes=["mcp:tools"],
        expires_at=time.time() + 60,
        client_id="client-a",
        code_challenge="",
        redirect_uri="https://x/cb",  # type: ignore[arg-type]
        redirect_uri_provided_explicitly=True,
    )
    with pytest.raises(TokenError) as excinfo:
        await p.exchange_authorization_code(_client("client-b"), code)
    assert "does not belong" in (excinfo.value.error_description or "")
    assert p._tokens.load() == {}, "nothing was issued"


async def test_load_refresh_token_refuses_an_expired_token(tmp_path: Path) -> None:
    p = _provider(tmp_path)
    p.__dict__["_refresh_ttl"] = -5  # issue an already-expired refresh token
    issued = p._issue("client-a", ["mcp:tools"])
    assert issued.refresh_token is not None
    assert await p.load_refresh_token(_client(), issued.refresh_token) is None


async def test_exchange_refresh_token_refuses_a_different_client(tmp_path: Path) -> None:
    p = _provider(tmp_path)
    issued = p._issue("client-a", ["mcp:tools"])
    assert issued.refresh_token is not None
    refresh = await p.load_refresh_token(_client("client-a"), issued.refresh_token)
    assert refresh is not None
    with pytest.raises(TokenError) as excinfo:
        await p.exchange_refresh_token(_client("client-b"), refresh, ["mcp:tools"])
    assert "does not belong" in (excinfo.value.error_description or "")


# -- audit chain ----------------------------------------------------------


def test_verify_chain_reports_a_prev_mismatch_with_a_valid_hash(tmp_path: Path) -> None:
    """Only the linkage is wrong: seq is right and the record's own hash is consistent."""
    path = tmp_path / "audit.jsonl"
    log = AuditLogger(str(path), chain=True)
    for i in range(3):
        log.record(tool="t", args={"i": i}, output="o", exit_code=0, tier=1)
    recs = [json.loads(ln) for ln in path.read_text().splitlines()]
    forged = dict(recs[1])
    forged["prev"] = "e" * 64
    forged["chain"] = _chain_value(
        forged["prev"], {k: v for k, v in forged.items() if k != "chain"}
    )
    recs[1] = forged
    path.write_text("\n".join(json.dumps(r) for r in recs) + "\n", encoding="utf-8")
    result = verify_chain(str(path))
    assert not result.ok
    assert result.broken_at == 2
    assert "prev does not match" in result.reason


# -- audit stderr ---------------------------------------------------------


def test_audit_stderr_echoes_the_record_without_the_output_body(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "audit.jsonl"
    log = AuditLogger(str(path), also_stderr=True)
    log.record(tool="shell_exec", args={"command": "ls"}, output="BODY-SECRET", exit_code=0, tier=1)
    err = capsys.readouterr().err
    assert err.startswith("AUDIT {")
    assert '"tool": "shell_exec"' in err or '"tool":"shell_exec"' in err
    assert "BODY-SECRET" not in err
    assert "BODY-SECRET" not in path.read_text()


def test_audit_stderr_is_off_by_default(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    log = AuditLogger(str(tmp_path / "audit.jsonl"))
    log.record(tool="t", args={}, output="o", exit_code=0, tier=1)
    assert capsys.readouterr().err == ""


# -- session_kill ---------------------------------------------------------


@pytest.fixture
def cfg(settings: Settings) -> Settings:
    return settings


async def _spawn_cat(mcp: Any) -> str:
    out = text((await mcp.call_tool("shell_spawn", {"command": "cat"})).content)
    match = re.search(r"session (\S+) started", out)
    assert match, out
    return match.group(1)


@pytest.mark.parametrize("name", ["TERM", "sigterm", " SIGTERM ", "KILL", "SIGHUP"])
async def test_session_kill_accepts_real_signal_names(cfg: Settings, name: str) -> None:
    mcp = build_server(cfg)
    sid = await _spawn_cat(mcp)
    out = text(
        (await mcp.call_tool("session_kill", {"session_id": sid, "signal_name": name})).content
    )
    assert "killed and closed" in out, out


@pytest.mark.parametrize("name", ["BOGUS", "_IGN", "_DFL", "NSIG", "", "0", "SIG", "SIGSIGTERM"])
async def test_session_kill_refuses_an_unknown_signal_and_leaves_the_session(
    cfg: Settings, name: str
) -> None:
    mcp = build_server(cfg)
    sid = await _spawn_cat(mcp)
    try:
        out = text(
            (await mcp.call_tool("session_kill", {"session_id": sid, "signal_name": name})).content
        )
        assert "unknown signal" in out, out
        listed = text((await mcp.call_tool("session_list", {})).content)
        assert sid in listed, "an unknown signal must not close the session"
    finally:
        await mcp.call_tool("session_kill", {"session_id": sid, "signal_name": "KILL"})


async def test_session_kill_without_close_reports_the_signal(cfg: Settings) -> None:
    mcp = build_server(cfg)
    sid = await _spawn_cat(mcp)
    out = text(
        (
            await mcp.call_tool(
                "session_kill", {"session_id": sid, "signal_name": "usr1", "close": False}
            )
        ).content
    )
    assert "sent SIGUSR1" in out
    await mcp.call_tool("session_kill", {"session_id": sid, "signal_name": "KILL"})


# -- SSH wrapper success paths ----------------------------------------------


class _Transport:
    def __init__(self) -> None:
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
        import asyncio

        await asyncio.Event().wait()

    async def aclose(self) -> None:
        self.closed = True


async def test_ssh_spawn_registers_a_session_and_audits_the_connection(
    cfg: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: dict[str, Any] = {}

    async def fake_open(self: SshPool, target: str, **kw: Any) -> _Transport:
        seen.update(target=target, **kw)
        return _Transport()

    monkeypatch.setattr(SshPool, "open_process", fake_open)
    mcp = build_server(cfg)
    out = text(
        (
            await mcp.call_tool(
                "ssh_spawn",
                {"host": "h1.example", "command": "top", "cols": 100, "rows": 30, "user": "ops"},
            )
        ).content
    )
    assert re.search(r"session ssh-\S+ started \(ssh h1\.example\)", out), out
    assert seen["target"] == "h1.example" and seen["command"] == "top"
    assert (seen["cols"], seen["rows"]) == (100, 30)
    assert seen["connect_kwargs"]["user"] == "ops"
    rec = [r for r in audit_lines(Path(cfg.audit_path)) if r["tool"] == "ssh_spawn"][-1]
    assert rec["args"]["host"] == "h1.example" and rec["args"]["size"] == "100x30"
    listed = text((await mcp.call_tool("session_list", {})).content)
    assert '"kind": "ssh"' in listed


async def test_ssh_upload_and_download_pass_their_arguments_through(
    cfg: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[tuple[str, tuple[Any, ...], dict[str, Any]]] = []

    async def put(self: SshPool, target: str, local: str, remote: str, **kw: Any) -> str:
        calls.append(("put", (target, local, remote), kw))
        return f"uploaded {local} -> {target}:{remote}"

    async def get(self: SshPool, target: str, remote: str, local: str, **kw: Any) -> str:
        calls.append(("get", (target, remote, local), kw))
        return f"downloaded {target}:{remote} -> {local}"

    monkeypatch.setattr(SshPool, "sftp_put", put)
    monkeypatch.setattr(SshPool, "sftp_get", get)
    mcp = build_server(cfg)
    up = text(
        (
            await mcp.call_tool(
                "ssh_upload",
                {
                    "host": "h1.example",
                    "local_path": "/tmp/a",
                    "remote_path": "/srv/a",
                    "recursive": True,
                },
            )
        ).content
    )
    down = text(
        (
            await mcp.call_tool(
                "ssh_download",
                {
                    "host": "h1.example",
                    "remote_path": "/srv/b",
                    "local_path": "/tmp/b",
                    "timeout": 5,
                },
            )
        ).content
    )
    assert up == "uploaded /tmp/a -> h1.example:/srv/a"
    assert down == "downloaded h1.example:/srv/b -> /tmp/b"
    assert calls[0][2]["recurse"] is True and calls[0][2]["timeout"] == 0
    assert calls[1][2]["recurse"] is False and calls[1][2]["timeout"] == 5
    tools = {r["tool"]: r for r in audit_lines(Path(cfg.audit_path))}
    assert tools["ssh_upload"]["args"]["local"] == "/tmp/a"
    assert tools["ssh_download"]["args"]["remote"] == "/srv/b"


async def test_ssh_forward_success_list_and_close(
    cfg: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _Listener:
        closed = False

        def close(self) -> None:
            self.closed = True

        async def wait_closed(self) -> None:
            return None

    pool_forwards: dict[str, ForwardHandle] = {}

    async def add(self: SshPool, target: str, spec: str, **kw: Any) -> ForwardHandle:
        handle = ForwardHandle("fwd-1", "local", spec, 4242, "db:5432", _Listener())
        pool_forwards[handle.id] = handle
        self._forwards[handle.id] = handle
        return handle

    monkeypatch.setattr(SshPool, "add_forward", add)
    mcp = build_server(cfg)
    out = text(
        (await mcp.call_tool("ssh_forward", {"host": "h1.example", "spec": "L:0:db:5432"})).content
    )
    assert out == "forward fwd-1 active: local L:0:db:5432 listening on port 4242"
    listed = json.loads(text((await mcp.call_tool("ssh_forward_list", {})).content))
    assert listed[0]["id"] == "fwd-1" and listed[0]["listen_port"] == 4242
    closed = text((await mcp.call_tool("ssh_forward_close", {"forward_id": "fwd-1"})).content)
    assert closed == "closed forward fwd-1"
    assert text((await mcp.call_tool("ssh_forward_list", {})).content) == "[]"
