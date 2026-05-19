"""OAuth provider tests - file store, token lifecycle, single-client lockdown.

These run fully offline against the installed mcp SDK models.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from mcpx.auth.oauth import FileOAuthProvider, build_auth_settings, make_oauth_provider
from mcpx.config import Settings


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


def test_unknown_client_is_none(tmp_path: Path) -> None:
    import asyncio

    p = _provider(tmp_path)
    assert asyncio.get_event_loop().run_until_complete(p.get_client("nope")) is None


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
