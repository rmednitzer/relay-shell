"""Audit identity comes from verified OAuth, never request metadata."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from mcp.server.auth.provider import AccessToken

from relay_shell.auth.oauth import FileOAuthProvider
from relay_shell.config import Settings
from relay_shell.server import _ctx_ids, build_server


@pytest.mark.parametrize("request_id", [0, 17, "request-a"])
def test_correlation_preserves_valid_ids_without_trusting_metadata(
    request_id: int | str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("relay_shell.server.get_access_token", lambda: None)
    context = SimpleNamespace(request_id=request_id, client_id="forged-client")
    assert _ctx_ids(context) == (str(request_id), "")


def test_missing_context_has_no_fabricated_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("relay_shell.server.get_access_token", lambda: None)
    assert _ctx_ids(None) == ("", "")


def test_token_is_the_only_client_identity_source(monkeypatch: pytest.MonkeyPatch) -> None:
    token = AccessToken(token="fixture", client_id="verified-client", scopes=["mcp:tools"])
    monkeypatch.setattr("relay_shell.server.get_access_token", lambda: token)
    context = SimpleNamespace(request_id=0, client_id="forged-client")
    assert _ctx_ids(context) == ("0", "verified-client")


def _settings(tmp_path: Path, *, auth_enabled: bool = True) -> Settings:
    return Settings(
        transport="http",
        http_host="127.0.0.1",
        audit_path=str(tmp_path / "audit.jsonl"),
        auth_enabled=auth_enabled,
        auth_issuer="http://127.0.0.1:8080",
        auth_state_dir=str(tmp_path / "oauth"),
        ssh_config=str(tmp_path / "no-ssh-config"),
        policy_mode="open",
    )


def _call(request_id: int, *, tool: str = "server_info") -> dict:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "params": {
            "name": tool,
            "arguments": {"command": "echo audit-test-$((21 + 21))-only"}
            if tool == "shell_exec"
            else {},
            "_meta": {"client_id": "forged-client"},
        },
    }


async def test_http_authentication_attribution_and_context_isolation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cfg = _settings(tmp_path)
    provider = FileOAuthProvider(
        cfg.auth_state_dir,
        single_client=True,
        access_ttl=3600,
        refresh_ttl=3600,
        code_ttl=60,
        resource_url=cfg.auth_issuer,
    )
    first = provider._issue("verified-first", ["mcp:tools"])
    second = provider._issue("verified-second", ["mcp:tools"])
    monkeypatch.setattr("relay_shell.auth.make_oauth_provider", lambda _cfg: provider)
    mcp = build_server(cfg)
    app = mcp.streamable_http_app(stateless_http=True, json_response=True)
    headers = {
        "Accept": "application/json, text/event-stream",
        "MCP-Protocol-Version": "2025-03-26",
    }
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://127.0.0.1:8080",
            headers=headers,
        ) as client,
    ):
        unauthenticated = await client.post("/mcp", json=_call(90))
        assert unauthenticated.status_code == 401
        invalid = await client.post(
            "/mcp", json=_call(91), headers={"Authorization": "Bearer invalid-fixture"}
        )
        assert invalid.status_code == 401
        replies = await asyncio.gather(
            client.post(
                "/mcp",
                json=_call(0, tool="shell_exec"),
                headers={"Authorization": f"Bearer {first.access_token}"},
            ),
            client.post(
                "/mcp", json=_call(2), headers={"Authorization": f"Bearer {second.access_token}"}
            ),
        )
        assert all(reply.status_code == 200 for reply in replies)
        assert all(
            "result" in reply.json() and not reply.json()["result"].get("isError", False)
            for reply in replies
        )
        again = await client.post("/mcp", json=_call(92))
        assert again.status_code == 401
    raw = Path(cfg.audit_path).read_text()
    records = [json.loads(line) for line in raw.splitlines()]
    calls = {
        record["request_id"]: record
        for record in records
        if record["tool"] in {"shell_exec", "server_info"}
    }
    assert set(calls) == {"0", "2"}
    assert calls["0"]["client_id"] == "verified-first"
    assert calls["2"]["client_id"] == "verified-second"
    assert len(calls["0"]["output_sha256"]) == 64
    assert "audit-test-42-only" not in raw
    assert "forged-client" not in raw
    assert first.access_token not in raw and second.access_token not in raw


async def test_unprotected_http_does_not_trust_caller_identity(tmp_path: Path) -> None:
    cfg = _settings(tmp_path, auth_enabled=False)
    mcp = build_server(cfg)
    app = mcp.streamable_http_app(stateless_http=True, json_response=True)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://127.0.0.1:8080",
            headers={
                "Accept": "application/json, text/event-stream",
                "MCP-Protocol-Version": "2025-03-26",
            },
        ) as client,
    ):
        response = await client.post("/mcp", json=_call(3))
        assert response.status_code == 200
    records = [json.loads(line) for line in Path(cfg.audit_path).read_text().splitlines()]
    record = next(item for item in records if item["tool"] == "server_info")
    assert record["request_id"] == "3"
    assert record.get("client_id", "") == ""
