"""A14-A11b: refresh-token reuse detection, trailing-newline secrets, fail-closed approval."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from mcp.shared.auth import OAuthClientInformationFull

from relay_shell.auth import oauth
from relay_shell.auth.oauth import FileOAuthProvider, make_oauth_provider


def _provider(tmp_path: Path, **kw: object) -> FileOAuthProvider:
    return FileOAuthProvider(
        str(tmp_path / "oauth"),
        single_client=False,
        access_ttl=3600,
        refresh_ttl=86400,
        code_ttl=300,
        require_approval=False,
        **kw,  # type: ignore[arg-type]
    )


def _client(cid: str = "client-a") -> OAuthClientInformationFull:
    return OAuthClientInformationFull(client_id=cid, redirect_uris=["https://x/cb"])


async def _rotate(p: FileOAuthProvider, cid: str = "client-a") -> tuple[str, str, str]:
    """Issue a pair and rotate it once; return (old_access, old_refresh, new_access)."""
    issued = p._issue(cid, ["mcp:tools"])
    assert issued.refresh_token is not None
    refresh = await p.load_refresh_token(_client(cid), issued.refresh_token)
    assert refresh is not None
    rotated = await p.exchange_refresh_token(_client(cid), refresh, ["mcp:tools"])
    return issued.access_token, issued.refresh_token, rotated.access_token


async def test_replayed_refresh_token_after_the_grace_window_revokes_the_client(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    p = _provider(tmp_path)
    old_access, old_refresh, new_access = await _rotate(p)
    # Another client's tokens must be untouched.
    other = p._issue("client-b", ["mcp:tools"])
    assert await p.load_access_token(old_access) is not None, "valid until expiry or reuse"

    real_now = oauth._now()
    monkeypatch.setattr(oauth, "_now", lambda: real_now + oauth._REUSE_GRACE_SECONDS + 5)
    assert await p.load_refresh_token(_client(), old_refresh) is None

    assert await p.load_access_token(old_access) is None
    assert await p.load_access_token(new_access) is None, "the whole family is revoked"
    assert await p.load_access_token(other.access_token) is not None


async def test_replay_inside_the_grace_window_is_refused_but_revokes_nothing(
    tmp_path: Path,
) -> None:
    p = _provider(tmp_path)
    _old_access, old_refresh, new_access = await _rotate(p)
    assert await p.load_refresh_token(_client(), old_refresh) is None
    assert await p.load_access_token(new_access) is not None


async def test_a_replay_by_another_client_id_does_not_revoke_the_owner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    p = _provider(tmp_path)
    _old_access, old_refresh, new_access = await _rotate(p)
    real_now = oauth._now()
    monkeypatch.setattr(oauth, "_now", lambda: real_now + 60)
    assert await p.load_refresh_token(_client("client-b"), old_refresh) is None
    assert await p.load_access_token(new_access) is not None


async def test_spent_markers_hold_no_raw_token_and_expire_with_the_token(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    p = _provider(tmp_path)
    _old_access, old_refresh, _new_access = await _rotate(p)
    text = (tmp_path / "oauth" / "tokens.json").read_text(encoding="utf-8")
    assert old_refresh not in text
    spent = [k for k in json.loads(text) if k.startswith(oauth._SPENT_PREFIX)]
    assert len(spent) == 1
    # A later issue after the refresh lifetime purges the marker like any expired record.
    real_now = oauth._now()
    monkeypatch.setattr(oauth, "_now", lambda: real_now + 86400 + 10)
    p._issue("client-a", ["mcp:tools"])
    assert not [k for k in p._tokens.load() if k.startswith(oauth._SPENT_PREFIX)]


async def test_marker_survives_the_legacy_record_migration(tmp_path: Path) -> None:
    p = _provider(tmp_path)
    await _rotate(p)
    before = {k for k in p._tokens.load() if k.startswith(oauth._SPENT_PREFIX)}
    p._migrate_secret_storage()
    assert {k for k in p._tokens.load() if k.startswith(oauth._SPENT_PREFIX)} == before


async def test_secrets_with_a_trailing_newline_are_not_valid(tmp_path: Path) -> None:
    p = _provider(tmp_path)
    issued = p._issue("client-a", ["mcp:tools"])
    assert await p.load_access_token(issued.access_token) is not None
    assert await p.load_access_token(issued.access_token + "\n") is None
    assert await p.load_refresh_token(_client(), (issued.refresh_token or "") + "\n") is None
    assert oauth._SECRET_RE.match("abc\n") is None


def test_approval_is_required_unless_explicitly_turned_off(tmp_path: Path) -> None:
    default = FileOAuthProvider(
        str(tmp_path / "a"), single_client=False, access_ttl=60, refresh_ttl=60, code_ttl=60
    )
    assert default._require_approval is True
    # A settings object that lacks the field must not open the gate either.
    bare = SimpleNamespace(
        auth_state_dir=str(tmp_path / "b"),
        auth_single_client=False,
        auth_access_ttl=60,
        auth_refresh_ttl=60,
        auth_code_ttl=60,
        auth_issuer="https://relay.example.org",
    )
    assert make_oauth_provider(bare)._require_approval is True
    bare.auth_require_approval = False  # type: ignore[attr-defined]
    assert make_oauth_provider(bare)._require_approval is False
