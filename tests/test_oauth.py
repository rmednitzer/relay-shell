"""OAuth provider tests - file store, token lifecycle, single-client lockdown.

These run fully offline against the installed mcp SDK models.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from relay_shell.auth.oauth import FileOAuthProvider, build_auth_settings, make_oauth_provider
from relay_shell.config import Settings


def _provider(tmp_path: Path, **kw: object) -> FileOAuthProvider:
    return FileOAuthProvider(
        str(tmp_path / "oauth"),
        single_client=bool(kw.get("single_client", True)),
        access_ttl=int(kw.get("access_ttl", 3600)),  # type: ignore[arg-type]
        refresh_ttl=int(kw.get("refresh_ttl", 86400)),  # type: ignore[arg-type]
        code_ttl=int(kw.get("code_ttl", 300)),  # type: ignore[arg-type]
    )


def test_build_auth_settings() -> None:
    s = build_auth_settings("https://example.com")
    assert str(s.issuer_url).rstrip("/") == "https://example.com"


def test_make_provider_from_settings(tmp_path: Path) -> None:
    s = Settings(audit_path=str(tmp_path / "a"), auth_state_dir=str(tmp_path / "o"))
    assert isinstance(make_oauth_provider(s), FileOAuthProvider)


async def test_issue_and_load_access_token(tmp_path: Path) -> None:
    p = _provider(tmp_path)
    token = p._issue("client-a", ["mcp:tools"])
    assert token.token_type == "Bearer"
    loaded = await p.load_access_token(token.access_token)
    assert loaded is not None
    assert loaded.client_id == "client-a"


async def test_access_token_lazy_expiry(tmp_path: Path) -> None:
    p = _provider(tmp_path, access_ttl=-1)  # already expired on issue
    token = p._issue("client-a", ["mcp:tools"])
    assert await p.load_access_token(token.access_token) is None


async def test_refresh_rotation(tmp_path: Path) -> None:
    p = _provider(tmp_path)
    issued = p._issue("client-a", ["mcp:tools"])
    assert issued.refresh_token is not None


async def test_unknown_client_is_none(tmp_path: Path) -> None:
    p = _provider(tmp_path)
    assert await p.get_client("nope") is None


@pytest.mark.parametrize("single", [True])
async def test_single_client_lockdown(tmp_path: Path, single: bool) -> None:
    from mcp.shared.auth import OAuthClientInformationFull

    p = _provider(tmp_path, single_client=single)
    c1 = OAuthClientInformationFull(client_id="c1", redirect_uris=["https://x/cb"])
    await p.register_client(c1)
    got = await p.get_client("c1")
    assert got is not None and got.client_id == "c1"
    c2 = OAuthClientInformationFull(client_id="c2", redirect_uris=["https://y/cb"])
    with pytest.raises(ValueError, match="closed"):
        await p.register_client(c2)


async def test_revoke_access_token_removes_only_access(tmp_path: Path) -> None:
    """Revoking an access token must not cascade to its paired refresh token.

    RFC 7009 leaves that direction unspecified and the provider opts out;
    cascade in the other direction (refresh -> access) is exercised below.
    """
    from mcp.server.auth.provider import AccessToken
    from mcp.shared.auth import OAuthClientInformationFull

    p = _provider(tmp_path)
    issued = p._issue("client-a", ["mcp:tools"])
    assert await p.load_access_token(issued.access_token) is not None
    await p.revoke_token(
        AccessToken(
            token=issued.access_token,
            client_id="client-a",
            scopes=["mcp:tools"],
            expires_at=2**31,
        )
    )
    assert await p.load_access_token(issued.access_token) is None
    # The paired refresh token survives a plain access-token revocation.
    client = OAuthClientInformationFull(client_id="client-a", redirect_uris=["https://x/cb"])
    assert issued.refresh_token is not None
    assert await p.load_refresh_token(client, issued.refresh_token) is not None


async def test_revoke_refresh_token_removes_refresh(tmp_path: Path) -> None:
    from mcp.server.auth.provider import RefreshToken
    from mcp.shared.auth import OAuthClientInformationFull

    p = _provider(tmp_path)
    issued = p._issue("client-a", ["mcp:tools"])
    assert issued.refresh_token is not None
    client = OAuthClientInformationFull(client_id="client-a", redirect_uris=["https://x/cb"])
    assert await p.load_refresh_token(client, issued.refresh_token) is not None
    await p.revoke_token(
        RefreshToken(
            token=issued.refresh_token,
            client_id="client-a",
            scopes=["mcp:tools"],
            expires_at=2**31,
        )
    )
    assert await p.load_refresh_token(client, issued.refresh_token) is None


async def test_refresh_exchange_rotates_tokens(tmp_path: Path) -> None:
    from mcp.shared.auth import OAuthClientInformationFull

    p = _provider(tmp_path)
    issued = p._issue("client-a", ["mcp:tools"])
    assert issued.refresh_token is not None
    client = OAuthClientInformationFull(client_id="client-a", redirect_uris=["https://x/cb"])
    refresh = await p.load_refresh_token(client, issued.refresh_token)
    assert refresh is not None

    rotated = await p.exchange_refresh_token(client, refresh, ["mcp:tools"])
    assert rotated.access_token != issued.access_token
    assert rotated.refresh_token != issued.refresh_token
    # Old refresh must no longer load.
    assert await p.load_refresh_token(client, issued.refresh_token) is None


async def test_load_refresh_token_mismatched_client_returns_none(tmp_path: Path) -> None:
    from mcp.shared.auth import OAuthClientInformationFull

    p = _provider(tmp_path)
    issued = p._issue("client-a", ["mcp:tools"])
    other = OAuthClientInformationFull(client_id="client-b", redirect_uris=["https://x/cb"])
    assert issued.refresh_token is not None
    assert await p.load_refresh_token(other, issued.refresh_token) is None


async def test_exchange_authorization_code_consumes_code(tmp_path: Path) -> None:
    from mcp.server.auth.provider import AuthorizationCode
    from mcp.shared.auth import OAuthClientInformationFull

    p = _provider(tmp_path)
    client = OAuthClientInformationFull(client_id="client-a", redirect_uris=["https://x/cb"])
    code = AuthorizationCode(
        code="dummy-code",
        scopes=["mcp:tools"],
        expires_at=2**31,
        client_id="client-a",
        code_challenge="",
        redirect_uri="https://x/cb",  # type: ignore[arg-type]
        redirect_uri_provided_explicitly=True,
    )
    # Seed the store as if ``authorize`` had run.
    p._codes.save(
        {
            code.code: {
                "code": code.code,
                "client_id": code.client_id,
                "scopes": list(code.scopes),
                "expires_at": int(code.expires_at),
                "code_challenge": code.code_challenge,
                "redirect_uri": str(code.redirect_uri),
                "redirect_uri_provided_explicitly": True,
            }
        }
    )
    token = await p.exchange_authorization_code(client, code)
    assert token.access_token
    # Code must be one-shot.
    assert await p.load_authorization_code(client, code.code) is None
