"""Operator approval gate for OAuth clients (audit H4, 2026-10-04).

Dynamic registration is open to whoever can reach ``/register``, and the
authorization endpoint issues a code to any registered client with no login step.
Before this gate the first party to register obtained tokens (shell execution as
the service user), and a corrupt ``clients.json`` read as "no clients", which
reopened registration and let a caller replace the real client.
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from mcp.server.auth.provider import AuthorizationParams, AuthorizeError
from mcp.shared.auth import OAuthClientInformationFull

from relay_shell.__main__ import main
from relay_shell.auth.admin import approve_client, list_clients, reject_client
from relay_shell.auth.oauth import FileOAuthProvider, StoreUnreadableError, make_oauth_provider
from relay_shell.config import Settings, get_settings
from relay_shell.server import build_server

RESOURCE = "https://relay.example.org"
REDIRECT = "https://client.example/cb"


def _provider(tmp_path: Path, *, approval: bool, single: bool = True) -> FileOAuthProvider:
    return FileOAuthProvider(
        str(tmp_path / "oauth"),
        single_client=single,
        access_ttl=3600,
        refresh_ttl=86400,
        code_ttl=300,
        resource_url=RESOURCE,
        require_approval=approval,
    )


def _client(cid: str = "client-a", redirect: str = REDIRECT) -> OAuthClientInformationFull:
    return OAuthClientInformationFull(
        client_id=cid, redirect_uris=[redirect], token_endpoint_auth_method="none"
    )


def _params(redirect: str = REDIRECT) -> AuthorizationParams:
    return AuthorizationParams(
        state="s",
        scopes=["mcp:tools"],
        code_challenge="c" * 43,
        redirect_uri=redirect,  # type: ignore[arg-type]
        redirect_uri_provided_explicitly=True,
        resource=RESOURCE,
    )


async def test_new_client_is_pending_until_the_operator_approves(tmp_path: Path) -> None:
    p = _provider(tmp_path, approval=True)
    await p.register_client(_client())
    with pytest.raises(AuthorizeError) as exc:
        await p.authorize(_client(), _params())
    assert exc.value.error == "access_denied"

    assert approve_client(str(tmp_path / "oauth"), "client-a") is True
    url = await p.authorize(_client(), _params())  # takes effect without a restart
    assert "code=" in url


async def test_the_gate_is_off_for_a_directly_built_provider_by_default(tmp_path: Path) -> None:
    p = _provider(tmp_path, approval=False)
    await p.register_client(_client())
    assert "code=" in await p.authorize(_client(), _params())


def test_settings_default_requires_approval_and_reaches_the_provider(tmp_path: Path) -> None:
    cfg = Settings(audit_path=str(tmp_path / "a"), auth_state_dir=str(tmp_path / "o"))
    assert cfg.auth_require_approval is True
    assert make_oauth_provider(cfg)._require_approval is True
    off = cfg.model_copy(update={"auth_require_approval": False})
    assert make_oauth_provider(off)._require_approval is False


async def test_clients_registered_before_the_gate_are_carried_over_as_approved(
    tmp_path: Path,
) -> None:
    old = _provider(tmp_path, approval=False)  # an install from before the gate existed
    await old.register_client(_client())
    (tmp_path / "oauth" / "approvals.json").unlink()  # exactly what such an install has on disk

    upgraded = _provider(tmp_path, approval=True)
    assert "code=" in await upgraded.authorize(_client(), _params())
    (row,) = list_clients(str(tmp_path / "oauth"))
    assert (row.status, row.legacy) == ("approved", True)


async def test_a_second_registrant_is_still_refused_and_stays_pending(tmp_path: Path) -> None:
    p = _provider(tmp_path, approval=True)
    await p.register_client(_client("first", "https://evil.example/cb"))
    with pytest.raises(ValueError, match="closed"):
        await p.register_client(_client("legit", REDIRECT))
    assert [r.client_id for r in list_clients(str(tmp_path / "oauth"))] == ["first"]


async def test_identical_reregistration_does_not_reset_an_approval(tmp_path: Path) -> None:
    p = _provider(tmp_path, approval=True)
    await p.register_client(_client())
    approve_client(str(tmp_path / "oauth"), "client-a")
    await p.register_client(_client())  # a client re-running DCR with the same metadata
    assert "code=" in await p.authorize(_client(), _params())


async def test_corrupt_clients_file_refuses_registration_and_is_left_intact(
    tmp_path: Path,
) -> None:
    p = _provider(tmp_path, approval=True)
    await p.register_client(_client("real", REDIRECT))
    clients = tmp_path / "oauth" / "clients.json"
    clients.write_text('{"real": {"client_id"', encoding="utf-8")  # truncated mid-write

    with pytest.raises(ValueError, match="unreadable"):
        await p.register_client(_client("attacker", "https://evil.example/cb"))
    assert clients.read_text(encoding="utf-8") == '{"real": {"client_id"'  # not overwritten
    assert await p.get_client("real") is None  # and nothing authenticates as it


async def test_corrupt_approvals_file_fails_closed(tmp_path: Path) -> None:
    p = _provider(tmp_path, approval=True)
    await p.register_client(_client())
    approve_client(str(tmp_path / "oauth"), "client-a")
    (tmp_path / "oauth" / "approvals.json").write_text("not json", encoding="utf-8")
    with pytest.raises(AuthorizeError):
        await p.authorize(_client(), _params())


def test_admin_list_approve_reject(tmp_path: Path) -> None:
    import asyncio

    async def seed() -> None:
        p = _provider(tmp_path, approval=True, single=False)
        await p.register_client(_client("a", "https://a.example/cb"))
        await p.register_client(_client("b", "https://b.example/cb"))
        p._issue("a", ["mcp:tools"], resource=RESOURCE)
        p._issue("b", ["mcp:tools"], resource=RESOURCE)

    asyncio.run(seed())
    state = str(tmp_path / "oauth")
    assert {(r.client_id, r.status) for r in list_clients(state)} == {
        ("a", "pending"),
        ("b", "pending"),
    }
    assert approve_client(state, "nope") is False
    assert reject_client(state, "nope") is False

    assert approve_client(state, "a") is True
    assert {(r.client_id, r.status) for r in list_clients(state)} == {
        ("a", "approved"),
        ("b", "pending"),
    }

    assert reject_client(state, "b") is True
    assert [r.client_id for r in list_clients(state)] == ["a"]
    tokens = json.loads((tmp_path / "oauth" / "tokens.json").read_text())
    assert {rec["client_id"] for rec in tokens.values()} == {"a"}  # b's tokens are gone, a's stay
    approvals = json.loads((tmp_path / "oauth" / "approvals.json").read_text())
    assert set(approvals) == {"a"}


async def test_rejecting_the_only_client_reopens_registration(tmp_path: Path) -> None:
    p = _provider(tmp_path, approval=True)
    await p.register_client(_client("squatter", "https://evil.example/cb"))
    assert reject_client(str(tmp_path / "oauth"), "squatter") is True
    await p.register_client(_client("legit", REDIRECT))  # the intended client can now register
    assert [r.client_id for r in list_clients(str(tmp_path / "oauth"))] == ["legit"]


def test_admin_surfaces_an_unreadable_store(tmp_path: Path) -> None:
    _provider(tmp_path, approval=True)
    (tmp_path / "oauth" / "clients.json").write_text("{", encoding="utf-8")
    with pytest.raises(StoreUnreadableError):
        list_clients(str(tmp_path / "oauth"))
    with pytest.raises(FileNotFoundError):
        list_clients(str(tmp_path / "missing"))


def test_cli_list_approve_reject(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import asyncio

    state = tmp_path / "oauth"
    monkeypatch.setenv("RELAY_SHELL_AUTH_STATE_DIR", str(state))
    get_settings.cache_clear()
    try:
        asyncio.run(_provider(tmp_path, approval=True).register_client(_client()))

        assert main(["--auth-list"]) == 0
        assert "client-a  pending" in capsys.readouterr().out
        assert main(["--auth-list", "--json"]) == 0
        (row,) = json.loads(capsys.readouterr().out)
        assert row["status"] == "pending" and row["redirect_uris"] == [REDIRECT]

        assert main(["--auth-approve", "client-a"]) == 0
        assert main(["--auth-list"]) == 0
        assert "client-a  approved" in capsys.readouterr().out
        assert main(["--auth-approve", "ghost"]) == 2
        assert "no such client" in capsys.readouterr().err

        assert main(["--auth-reject", "client-a"]) == 0
        assert main(["--auth-list"]) == 0
        assert "no clients registered" in capsys.readouterr().out
        assert main(["--auth-reject", "client-a"]) == 2

        (state / "clients.json").write_text("{", encoding="utf-8")
        assert main(["--auth-list"]) == 2  # an unreadable store is an error, not "empty"
    finally:
        get_settings.cache_clear()


async def test_http_flow_pending_client_gets_no_code_until_approved(
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
    assert cfg.auth_require_approval is True  # the shipped default, not overridden here
    provider = make_oauth_provider(cfg)
    monkeypatch.setattr("relay_shell.auth.make_oauth_provider", lambda _cfg: provider)
    app = build_server(cfg).streamable_http_app(stateless_http=True, json_response=True)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://127.0.0.1:8080",
            headers={"Accept": "application/json, text/event-stream"},
        ) as c,
    ):
        reg = await c.post(
            "/register",
            json={
                "redirect_uris": [REDIRECT],
                "token_endpoint_auth_method": "none",
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
            },
        )
        assert reg.status_code == 201  # registration itself is still open
        cid = reg.json()["client_id"]
        verifier = "v" * 64
        challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
            .decode()
            .rstrip("=")
        )
        args = {
            "response_type": "code",
            "client_id": cid,
            "redirect_uri": REDIRECT,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "scope": "mcp:tools",
            "state": "fixture",
            "resource": RESOURCE,
        }
        pending = await c.get("/authorize", params=args)
        location = pending.headers.get("location", "")
        assert "code=" not in location
        assert parse_qs(urlparse(location).query).get("error") == ["access_denied"]

        assert approve_client(str(tmp_path / "oauth"), cid) is True
        approved = await c.get("/authorize", params=args)
        assert "code=" in approved.headers["location"]
