"""File-backed OAuth 2.1 authorization-server provider.

Modeled on a production MCP gateway's provider: dynamic client registration
with optional single-client lockdown, PKCE (the SDK enforces the challenge),
short-lived authorization codes, rotating refresh tokens, and lazy expiry on
read. State is three JSON files under ``auth_state_dir``; no database.

This is optional and only constructed for the HTTP transport when
``RELAY_SHELL_AUTH_ENABLED=true``. Errors here must surface as auth failures, never
as a crashed transport, so reconstruction is defensive.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import secrets
import time
from pathlib import Path
from typing import Any

from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    OAuthAuthorizationServerProvider,
    RefreshToken,
    TokenError,
    construct_redirect_uri,
)
from mcp.server.auth.settings import (
    AuthSettings,
    ClientRegistrationOptions,
    RevocationOptions,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from pydantic import AnyHttpUrl

__all__ = ["FileOAuthProvider", "build_auth_settings", "make_oauth_provider"]

_SCOPES = ["mcp:tools"]
_REFRESH_PREFIX = "refresh:"


def _now() -> int:
    return int(time.time())


_DIR_MODE = 0o700
_FILE_MODE = 0o600


class _Store:
    """Tiny JSON file store. Each call reads/writes the whole file.

    Directory and file permissions are set explicitly so the security
    expectation does not depend on the caller's umask. systemd's
    ``UMask=0077`` in the hardening drop-in matches this, but an operator
    running the HTTP transport ad-hoc (tests, dev shells) gets the same
    private permissions for free.
    """

    def __init__(self, path: Path) -> None:
        self._path = path
        parent = self._path.parent
        parent.mkdir(parents=True, exist_ok=True)
        # mkdir(mode=...) only applies when the directory is freshly
        # created and never to existing parents; chmod is idempotent and
        # covers both. Best-effort: a parent we cannot chmod (e.g. owned
        # by another user) is the operator's responsibility, not fatal.
        with contextlib.suppress(OSError):
            parent.chmod(_DIR_MODE)

    def load(self) -> dict[str, Any]:
        try:
            data: Any = json.loads(self._path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
        return data if isinstance(data, dict) else {}

    def save(self, data: dict[str, Any]) -> None:
        tmp = self._path.with_suffix(self._path.suffix + ".tmp")
        payload = json.dumps(data, indent=2, default=str)
        # Race-free: create the temp file with 0o600 atomically rather than
        # writing first and chmod'ing after.
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, _FILE_MODE)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(payload)
        tmp.replace(self._path)


class FileOAuthProvider(OAuthAuthorizationServerProvider):  # type: ignore[type-arg]
    """OAuth 2.1 AS provider with file-backed state."""

    def __init__(
        self,
        state_dir: str,
        *,
        single_client: bool,
        access_ttl: int,
        refresh_ttl: int,
        code_ttl: int,
    ) -> None:
        base = Path(state_dir).expanduser()
        self._clients = _Store(base / "clients.json")
        self._codes = _Store(base / "codes.json")
        self._tokens = _Store(base / "tokens.json")
        self._single_client = single_client
        self._access_ttl = access_ttl
        self._refresh_ttl = refresh_ttl
        self._code_ttl = code_ttl
        # Single per-provider lock serializes every read-modify-write
        # against the three JSON stores. The atomic `tmp.replace` inside
        # ``_Store.save`` guarantees disk consistency for one writer; this
        # lock guarantees cross-coroutine consistency under concurrent
        # HTTP-transport traffic (token rotation, register-client, revoke).
        self._lock = asyncio.Lock()

    # --- clients ---
    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        data = self._clients.load().get(client_id)
        if not data:
            return None
        try:
            return OAuthClientInformationFull.model_validate(data)
        except Exception:  # noqa: BLE001
            return None

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        cid = client_info.client_id or ""
        if not cid:
            raise ValueError("client_id is required")
        async with self._lock:
            clients = self._clients.load()
            if self._single_client and clients and cid not in clients:
                raise ValueError("Dynamic client registration is closed (single-client lockdown).")
            clients[cid] = json.loads(client_info.model_dump_json())
            self._clients.save(clients)

    # --- authorization codes ---
    async def authorize(
        self, client: OAuthClientInformationFull, params: AuthorizationParams
    ) -> str:
        code = secrets.token_urlsafe(48)
        async with self._lock:
            codes = self._codes.load()
            codes[code] = {
                "code": code,
                "client_id": client.client_id or "",
                "scopes": list(getattr(params, "scopes", None) or _SCOPES),
                "expires_at": _now() + self._code_ttl,
                "code_challenge": getattr(params, "code_challenge", ""),
                "redirect_uri": str(params.redirect_uri),
                "redirect_uri_provided_explicitly": bool(
                    getattr(params, "redirect_uri_provided_explicitly", True)
                ),
                "resource": getattr(params, "resource", None),
            }
            self._codes.save(codes)
        return construct_redirect_uri(
            str(params.redirect_uri), code=code, state=getattr(params, "state", None)
        )

    def _build_auth_code(self, rec: dict[str, Any]) -> AuthorizationCode | None:
        try:
            return AuthorizationCode(
                code=rec["code"],
                scopes=rec["scopes"],
                expires_at=float(rec["expires_at"]),
                client_id=rec["client_id"],
                code_challenge=rec.get("code_challenge", ""),
                redirect_uri=rec["redirect_uri"],
                redirect_uri_provided_explicitly=rec.get("redirect_uri_provided_explicitly", True),
            )
        except Exception:  # noqa: BLE001
            return None

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> AuthorizationCode | None:
        async with self._lock:
            codes = self._codes.load()
            rec = codes.get(authorization_code)
            if not rec or rec.get("client_id") != (client.client_id or ""):
                return None
            if int(rec.get("expires_at", 0)) < _now():
                codes.pop(authorization_code, None)
                self._codes.save(codes)
                return None
            return self._build_auth_code(rec)

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode
    ) -> OAuthToken:
        async with self._lock:
            codes = self._codes.load()
            record = codes.pop(authorization_code.code, None)
            if record is None:
                # Race: two concurrent token requests both loaded the same
                # code; the first removed it, the second finds it gone.
                # An authorization code is one-shot per RFC 6749 §4.1.2;
                # refuse via TokenError so the MCP token handler renders
                # an OAuth ``invalid_grant`` response (HTTP 400), not 500.
                raise TokenError(
                    error="invalid_grant",
                    error_description="authorization code already used or expired",
                )
            if record.get("client_id") != (client.client_id or ""):
                # Defense in depth: ``load_authorization_code`` already
                # validates the client, but re-check here in case a future
                # caller skips that step.
                raise TokenError(
                    error="invalid_grant",
                    error_description="authorization code does not belong to this client",
                )
            self._codes.save(codes)
            scopes = list(authorization_code.scopes or _SCOPES)
            # _issue is sync and does its own load/save on tokens.json; the
            # caller's lock covers both stores atomically from a concurrent
            # coroutine's view.
            return self._issue(client.client_id or "", scopes)

    # --- tokens ---
    def _issue(self, client_id: str, scopes: list[str]) -> OAuthToken:
        access = secrets.token_urlsafe(48)
        refresh = secrets.token_urlsafe(48)
        tokens = self._tokens.load()
        tokens[access] = {
            "token": access,
            "client_id": client_id,
            "scopes": scopes,
            "expires_at": _now() + self._access_ttl,
        }
        tokens[_REFRESH_PREFIX + refresh] = {
            "token": refresh,
            "client_id": client_id,
            "scopes": scopes,
            "expires_at": _now() + self._refresh_ttl,
        }
        self._tokens.save(tokens)
        return OAuthToken(
            access_token=access,
            token_type="Bearer",
            expires_in=self._access_ttl,
            refresh_token=refresh,
            scope=" ".join(scopes),
        )

    async def load_access_token(self, token: str) -> AccessToken | None:
        async with self._lock:
            tokens = self._tokens.load()
            rec = tokens.get(token)
            if not rec:
                return None
            if int(rec.get("expires_at", 0)) < _now():
                tokens.pop(token, None)
                self._tokens.save(tokens)
                return None
            try:
                return AccessToken(
                    token=rec["token"],
                    client_id=rec["client_id"],
                    scopes=rec["scopes"],
                    expires_at=int(rec["expires_at"]),
                )
            except Exception:  # noqa: BLE001
                return None

    async def load_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: str
    ) -> RefreshToken | None:
        rec = self._tokens.load().get(_REFRESH_PREFIX + refresh_token)
        if not rec or rec.get("client_id") != (client.client_id or ""):
            return None
        if int(rec.get("expires_at", 0)) < _now():
            return None
        try:
            return RefreshToken(
                token=rec["token"],
                client_id=rec["client_id"],
                scopes=rec["scopes"],
                expires_at=int(rec["expires_at"]),
            )
        except Exception:  # noqa: BLE001
            return None

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        async with self._lock:
            tokens = self._tokens.load()
            store_key = _REFRESH_PREFIX + refresh_token.token
            record = tokens.pop(store_key, None)
            if record is None:
                # Race: two concurrent refresh requests both loaded the
                # same token; the first rotated it, the second finds it
                # gone. Refuse via TokenError (rendered as OAuth
                # ``invalid_grant`` HTTP 400 by the MCP token handler)
                # so rotation stays single-use.
                raise TokenError(
                    error="invalid_grant",
                    error_description="refresh token already used or expired",
                )
            if record.get("client_id") != (client.client_id or ""):
                raise TokenError(
                    error="invalid_grant",
                    error_description="refresh token does not belong to this client",
                )
            self._tokens.save(tokens)
            effective = list(scopes or refresh_token.scopes or _SCOPES)
            return self._issue(client.client_id or "", effective)

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        async with self._lock:
            tokens = self._tokens.load()
            raw = getattr(token, "token", "")
            tokens.pop(raw, None)
            tokens.pop(_REFRESH_PREFIX + raw, None)
            self._tokens.save(tokens)


def build_auth_settings(issuer: str) -> AuthSettings:
    url = AnyHttpUrl(issuer)
    return AuthSettings(
        issuer_url=url,
        resource_server_url=url,
        client_registration_options=ClientRegistrationOptions(
            enabled=True, valid_scopes=_SCOPES, default_scopes=_SCOPES
        ),
        revocation_options=RevocationOptions(enabled=True),
        required_scopes=_SCOPES,
    )


def make_oauth_provider(settings: Any) -> FileOAuthProvider:
    return FileOAuthProvider(
        settings.auth_state_dir,
        single_client=settings.auth_single_client,
        access_ttl=settings.auth_access_ttl,
        refresh_ttl=settings.auth_refresh_ttl,
        code_ttl=settings.auth_code_ttl,
    )
