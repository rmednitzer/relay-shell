"""OAuth state-store hardening (audit M8, 2026-10-04).

Secrets used to be stored as the dictionary keys of ``tokens.json`` / ``codes.json``
(and repeated in a ``token`` / ``code`` field), so any copy of the state directory
yielded usable bearer credentials; expired records were only removed when presented
and every authenticated request read the whole file on the event loop.
"""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from mcp.server.auth.provider import AuthorizationParams
from mcp.shared.auth import OAuthClientInformationFull

from relay_shell.auth.oauth import FileOAuthProvider, _hashed

RESOURCE = "https://relay.example.org"
REDIRECT = "https://client.example/cb"


def _provider(tmp_path: Path) -> FileOAuthProvider:
    return FileOAuthProvider(
        str(tmp_path / "oauth"),
        single_client=False,
        access_ttl=3600,
        refresh_ttl=86400,
        code_ttl=300,
        resource_url=RESOURCE,
    )


def _client() -> OAuthClientInformationFull:
    return OAuthClientInformationFull(
        client_id="client-a", redirect_uris=[REDIRECT], token_endpoint_auth_method="none"
    )


def _file(tmp_path: Path, name: str) -> Path:
    return tmp_path / "oauth" / name


def _params() -> AuthorizationParams:
    return AuthorizationParams(
        state="s",
        scopes=["mcp:tools"],
        code_challenge="c" * 43,
        redirect_uri=REDIRECT,  # type: ignore[arg-type]
        redirect_uri_provided_explicitly=True,
        resource=RESOURCE,
    )


async def test_no_raw_secret_is_written_to_disk(tmp_path: Path) -> None:
    p = _provider(tmp_path)
    client = _client()
    await p.register_client(client)
    issued = p._issue("client-a", ["mcp:tools"], resource=RESOURCE)
    url = await p.authorize(client, _params())
    code = parse_qs(urlparse(url).query)["code"][0]

    tokens_text = _file(tmp_path, "tokens.json").read_text()
    codes_text = _file(tmp_path, "codes.json").read_text()
    assert issued.access_token not in tokens_text
    assert (issued.refresh_token or "") not in tokens_text
    assert code not in codes_text

    tokens = json.loads(tokens_text)
    assert set(tokens) == {
        _hashed(issued.access_token),
        "refresh:" + _hashed(issued.refresh_token or ""),
    }
    assert all("token" not in rec for rec in tokens.values())
    (codes,) = [json.loads(codes_text)]
    assert set(codes) == {_hashed(code)}
    assert all("code" not in rec for rec in codes.values())


async def test_hashed_storage_still_authenticates_and_rotates(tmp_path: Path) -> None:
    p = _provider(tmp_path)
    client = _client()
    await p.register_client(client)

    url = await p.authorize(client, _params())
    code = parse_qs(urlparse(url).query)["code"][0]
    loaded = await p.load_authorization_code(client, code)
    assert loaded is not None and loaded.code == code
    issued = await p.exchange_authorization_code(client, loaded)
    assert await p.load_authorization_code(client, code) is None  # single use

    access = await p.load_access_token(issued.access_token)
    assert access is not None and access.token == issued.access_token
    refresh = await p.load_refresh_token(client, issued.refresh_token or "")
    assert refresh is not None and refresh.token == issued.refresh_token
    rotated = await p.exchange_refresh_token(client, refresh, [])
    assert await p.load_refresh_token(client, issued.refresh_token or "") is None
    assert await p.load_access_token(rotated.access_token) is not None

    await p.revoke_token(access)
    assert await p.load_access_token(issued.access_token) is None


async def test_a_stored_hash_cannot_be_replayed_as_a_bearer_secret(tmp_path: Path) -> None:
    p = _provider(tmp_path)
    client = _client()
    await p.register_client(client)
    issued = p._issue("client-a", ["mcp:tools"], resource=RESOURCE)
    url = await p.authorize(client, _params())
    code = parse_qs(urlparse(url).query)["code"][0]

    stored_access = _hashed(issued.access_token)  # what a copy of the state dir reveals
    stored_refresh = _hashed(issued.refresh_token or "")
    stored_code = _hashed(code)
    digest = stored_access.removeprefix("sha256:")

    assert await p.load_access_token(stored_access) is None
    assert await p.load_access_token("refresh:" + stored_refresh) is None
    assert await p.load_access_token(digest) is None
    assert await p.load_refresh_token(client, stored_refresh) is None
    assert await p.load_refresh_token(client, digest) is None
    assert await p.load_authorization_code(client, stored_code) is None
    assert await p.load_authorization_code(client, stored_code.removeprefix("sha256:")) is None


async def test_malformed_secrets_are_refused_without_a_lookup(tmp_path: Path) -> None:
    p = _provider(tmp_path)
    client = _client()
    for bad in ("", "a:b", "x" * 600, "has space", "new\nline"):
        assert await p.load_access_token(bad) is None
        assert await p.load_refresh_token(client, bad) is None
        assert await p.load_authorization_code(client, bad) is None


async def test_records_from_before_hashing_are_migrated_on_start(tmp_path: Path) -> None:
    state = tmp_path / "oauth"
    state.mkdir(mode=0o700)
    now = int(time.time())
    legacy_tokens: dict[str, Any] = {
        "legacyAccessTokenAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA": {
            "token": "legacyAccessTokenAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "client_id": "client-a",
            "scopes": ["mcp:tools"],
            "resource": RESOURCE,
            "expires_at": now + 600,
        },
        "refresh:legacyRefreshTokenBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB": {
            "token": "legacyRefreshTokenBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
            "client_id": "client-a",
            "scopes": ["mcp:tools"],
            "resource": RESOURCE,
            "expires_at": now + 600,
        },
        "legacyExpired": {
            "token": "legacyExpired",
            "client_id": "client-a",
            "scopes": ["mcp:tools"],
            "resource": RESOURCE,
            "expires_at": now - 10,
        },
    }
    (state / "tokens.json").write_text(json.dumps(legacy_tokens))
    legacy_codes = {
        "legacyCodeCCCC": {
            "code": "legacyCodeCCCC",
            "client_id": "client-a",
            "scopes": ["mcp:tools"],
            "expires_at": now + 100,
            "code_challenge": "c" * 43,
            "redirect_uri": REDIRECT,
            "redirect_uri_provided_explicitly": True,
            "resource": RESOURCE,
        }
    }
    (state / "codes.json").write_text(json.dumps(legacy_codes))
    access_raw = next(
        k for k in legacy_tokens if not k.startswith("refresh:") and "Expired" not in k
    )
    refresh_raw = next(k for k in legacy_tokens if k.startswith("refresh:")).removeprefix(
        "refresh:"
    )

    p = _provider(tmp_path)  # construction migrates

    on_disk = (state / "tokens.json").read_text() + (state / "codes.json").read_text()
    for secret in (access_raw, refresh_raw, "legacyCodeCCCC", "legacyExpired"):
        assert secret not in on_disk, secret
    assert all(
        k.startswith(("sha256:", "refresh:sha256:"))
        for k in json.loads((state / "tokens.json").read_text())
    )
    # Credentials issued before the upgrade keep working; the expired one is gone.
    assert await p.load_access_token(access_raw) is not None
    client = _client()
    assert await p.load_refresh_token(client, refresh_raw) is not None
    assert await p.load_authorization_code(client, "legacyCodeCCCC") is not None
    assert len(json.loads((state / "tokens.json").read_text())) == 2

    again = (state / "tokens.json").read_text()
    _provider(tmp_path)  # idempotent: a second start changes nothing
    assert (state / "tokens.json").read_text() == again


async def test_expired_records_are_purged_when_new_ones_are_written(tmp_path: Path) -> None:
    p = _provider(tmp_path)
    old = p._issue("client-a", ["mcp:tools"], resource=RESOURCE)
    tokens_file = _file(tmp_path, "tokens.json")
    records = json.loads(tokens_file.read_text())
    for rec in records.values():
        rec["expires_at"] = int(time.time()) - 5
    tokens_file.write_text(json.dumps(records))

    new = p._issue("client-a", ["mcp:tools"], resource=RESOURCE)  # never presenting `old`
    remaining = json.loads(tokens_file.read_text())
    assert set(remaining) == {
        _hashed(new.access_token),
        "refresh:" + _hashed(new.refresh_token or ""),
    }
    assert _hashed(old.access_token) not in remaining


async def test_access_token_lookup_does_not_block_the_event_loop(tmp_path: Path) -> None:
    p = _provider(tmp_path)
    issued = p._issue("client-a", ["mcp:tools"], resource=RESOURCE)
    seen: list[int] = []
    real_load = p._tokens.load

    def spy(*args: Any, **kwargs: Any) -> dict[str, Any]:
        seen.append(threading.get_ident())
        return real_load(*args, **kwargs)

    p._tokens.load = spy  # type: ignore[method-assign]
    assert await p.load_access_token(issued.access_token) is not None
    assert seen
    assert threading.get_ident() not in seen  # the file read ran on a worker thread
