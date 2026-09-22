"""Resource binding is enforced at issuance, renewal and actual HTTP admission."""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse

import httpx
import pytest
from mcp.server.auth.provider import TokenError
from mcp.shared.auth import OAuthClientInformationFull

from relay_shell.auth.oauth import FileOAuthProvider, build_auth_settings, make_oauth_provider
from relay_shell.auth.resource import TokenResourceMiddleware, normalize_resource
from relay_shell.config import Settings
from relay_shell.server import build_server

RESOURCE = "http://127.0.0.1:8080/mcp"


def provider(path: Path) -> FileOAuthProvider:
    return FileOAuthProvider(
        str(path),
        single_client=False,
        access_ttl=3600,
        refresh_ttl=7200,
        code_ttl=300,
        resource_url=RESOURCE,
    )


def test_resource_settings_are_explicit_and_keep_legacy_identifier_default() -> None:
    old = build_auth_settings("https://example.org")
    assert old.validate_token_resource is True
    assert str(old.resource_server_url) == "https://example.org/"
    new = build_auth_settings("https://auth.example.org", RESOURCE)
    assert str(new.resource_server_url) == RESOURCE


@pytest.mark.parametrize(
    "bad", ["", "/mcp", "javascript:evil", "https://x/#fragment", "https://u:p@x/mcp"]
)
def test_reject_unsafe_resource_identifier(bad: str) -> None:
    with pytest.raises(ValueError):
        normalize_resource(bad)


async def test_access_and_refresh_reject_missing_or_foreign_binding(tmp_path: Path) -> None:
    p = provider(tmp_path)
    client = OAuthClientInformationFull(
        client_id="client", redirect_uris=["https://client.example/cb"]
    )
    issued = p._issue("client", ["mcp:tools"])
    assert issued.refresh_token
    access = await p.load_access_token(issued.access_token)
    refresh = await p.load_refresh_token(client, issued.refresh_token)
    assert access and access.resource == RESOURCE
    assert refresh and refresh.resource == RESOURCE
    valid = p._tokens.load()
    for target in (None, "https://wrong.example/mcp", ""):
        records = json.loads(json.dumps(valid))
        for rec in records.values():
            if target is None:
                rec.pop("resource")
            else:
                rec["resource"] = target
        p._tokens.save(records)
        assert await p.load_access_token(issued.access_token) is None
        assert await p.load_refresh_token(client, issued.refresh_token) is None
    p._tokens.save(valid)
    replacement = await p.exchange_refresh_token(client, refresh, ["mcp:tools"])
    bound = await p.load_access_token(replacement.access_token)
    assert bound and bound.resource == RESOURCE
    assert await p.load_refresh_token(client, issued.refresh_token) is None


async def test_refresh_does_not_trust_forged_scope_or_audience_object(tmp_path: Path) -> None:
    p = provider(tmp_path)
    client = OAuthClientInformationFull(
        client_id="client", redirect_uris=["https://client.example/cb"]
    )
    issued = p._issue("client", ["mcp:tools"])
    refresh = await p.load_refresh_token(client, issued.refresh_token or "")
    assert refresh
    forged = refresh.model_copy(update={"resource": "https://wrong.example", "scopes": ["admin"]})
    try:
        await p.exchange_refresh_token(client, forged, ["admin"])
    except TokenError as exc:
        assert exc.error == "invalid_scope"
    else:
        pytest.fail("Unrecorded scope accepted")
    # The stored grant, never caller object fields, determines the resource.
    second = p._issue("client", ["mcp:tools"])
    refresh2 = await p.load_refresh_token(client, second.refresh_token or "")
    assert refresh2
    renewed = await p.exchange_refresh_token(
        client, refresh2.model_copy(update={"resource": "https://wrong.example"}), []
    )
    access = await p.load_access_token(renewed.access_token)
    assert access and access.resource == RESOURCE


async def test_real_http_pkce_binding_and_wrong_resource_rejection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cfg = Settings(
        transport="http",
        auth_enabled=True,
        auth_issuer="http://127.0.0.1:8080",
        auth_resource_url=RESOURCE,
        auth_state_dir=str(tmp_path / "oauth"),
        audit_path=str(tmp_path / "audit.jsonl"),
        ssh_config=str(tmp_path / "none"),
    )
    p = make_oauth_provider(cfg)
    monkeypatch.setattr("relay_shell.auth.make_oauth_provider", lambda _cfg: p)
    app = build_server(cfg).streamable_http_app(stateless_http=True, json_response=True)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://127.0.0.1:8080",
            headers={"Accept": "application/json, text/event-stream"},
        ) as c,
    ):
        registration = await c.post(
            "/register",
            json={
                "redirect_uris": ["https://client.example/cb"],
                "token_endpoint_auth_method": "none",
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
            },
        )
        assert registration.status_code == 201
        cid = registration.json()["client_id"]
        verifier = "v" * 64
        challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
            .decode()
            .rstrip("=")
        )
        args = {
            "response_type": "code",
            "client_id": cid,
            "redirect_uri": "https://client.example/cb",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "scope": "mcp:tools",
            "state": "fixture",
            "resource": RESOURCE,
        }
        wrong_auth = await c.get(
            "/authorize", params={**args, "resource": "https://wrong.example/mcp"}
        )
        assert "code=" not in wrong_auth.headers.get("location", "")
        ok = await c.get("/authorize", params=args)
        assert ok.status_code in (302, 303)
        code = parse_qs(urlparse(ok.headers["location"]).query)["code"][0]
        form = {
            "grant_type": "authorization_code",
            "client_id": cid,
            "code": code,
            "redirect_uri": "https://client.example/cb",
            "code_verifier": verifier,
            "resource": RESOURCE,
        }
        for bad in (
            "https://wrong.example/mcp",
            RESOURCE + "-other",
            RESOURCE + "?x=1",
            RESOURCE + "#x",
            "",
        ):
            denied = await c.post("/token", data={**form, "resource": bad})
            assert denied.status_code == 400
            assert "access_token" not in denied.text
        duplicate = urlencode(form) + "&resource=" + RESOURCE
        assert (
            await c.post(
                "/token",
                content=duplicate,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
        ).status_code == 400
        valid = await c.post("/token", data=form)
        assert valid.status_code == 200, valid.text
        tokens = valid.json()
        call = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "server_info", "arguments": {}},
        }
        reply = await c.post(
            "/mcp", json=call, headers={"Authorization": "Bearer " + tokens["access_token"]}
        )
        assert reply.status_code == 200 and "result" in reply.json()
        wrong_refresh = await c.post(
            "/token",
            data={
                "grant_type": "refresh_token",
                "client_id": cid,
                "refresh_token": tokens["refresh_token"],
                "resource": "https://wrong.example",
            },
        )
        assert wrong_refresh.status_code == 400
        renewed = await c.post(
            "/token",
            data={
                "grant_type": "refresh_token",
                "client_id": cid,
                "refresh_token": tokens["refresh_token"],
                "resource": RESOURCE,
            },
        )
        assert renewed.status_code == 200
        assert (await c.post("/token", data=form)).status_code == 400
        records = p._tokens.load()
        records[tokens["access_token"]]["resource"] = "https://wrong.example"
        p._tokens.save(records)
        refused = await c.post(
            "/mcp", json=call, headers={"Authorization": "Bearer " + tokens["access_token"]}
        )
        assert refused.status_code == 401
        metadata = await c.get("/.well-known/oauth-protected-resource/mcp")
        assert metadata.status_code == 200 and metadata.json()["resource"] == RESOURCE
    log = Path(cfg.audit_path).read_text()
    assert tokens["access_token"] not in log and tokens["refresh_token"] not in log


async def test_token_guard_bounds_body_and_preserves_other_paths() -> None:
    calls = []

    async def downstream(scope, receive, send):
        calls.append(scope["path"])

    app = TokenResourceMiddleware(downstream, resource_url=RESOURCE)
    sent = []

    async def send(message):
        sent.append(message)

    async def receive():
        return {"type": "http.request", "body": b"x" * 65537, "more_body": False}

    scope = {"type": "http", "path": "/token", "method": "POST", "headers": []}
    await app(scope, receive, send)
    assert not calls and sent[0]["status"] == 413
    await app({**scope, "path": "/mcp"}, receive, send)
    assert calls == ["/mcp"]

    async def disconnect():
        return {"type": "http.disconnect"}

    await app(scope, disconnect, send)
    assert calls == ["/mcp"]
