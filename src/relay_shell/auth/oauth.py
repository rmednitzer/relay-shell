"""File-backed OAuth 2.1 authorization-server provider.

Modeled on a production MCP gateway's provider: dynamic client registration
with optional single-client lockdown, PKCE (the SDK enforces the challenge),
short-lived authorization codes, rotating refresh tokens, and lazy expiry on
read. State is file-backed under ``auth_state_dir``; no database.

This is optional and only constructed for the HTTP transport when
``RELAY_SHELL_AUTH_ENABLED=true``. Errors here must surface as auth failures, never
as a crashed transport, so reconstruction is defensive.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import re
import secrets
import time
from pathlib import Path
from typing import Any

from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    AuthorizeError,
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

from relay_shell.util import sha256_hex

from .resource import normalize_resource

__all__ = [
    "FileOAuthProvider",
    "StoreUnreadableError",
    "build_auth_settings",
    "make_oauth_provider",
]

_log = logging.getLogger("relay_shell.auth")
_SCOPES = ["mcp:tools"]
_REFRESH_PREFIX = "refresh:"
# Secrets (access / refresh tokens, authorization codes) are stored under the
# SHA-256 of the secret, never the secret itself, so a copy of the state directory
# (a backup, a stray file read) does not yield usable bearer credentials.
_HASH_PREFIX = "sha256:"
# What `secrets.token_urlsafe` can produce. A presented secret outside this set is
# never looked up: it could otherwise be a *stored key* (`sha256:<hex>`,
# `refresh:...`) replayed as if it were the secret.
_SECRET_RE = re.compile(r"^[A-Za-z0-9_-]{1,512}$")


def _hashed(secret: str) -> str:
    return _HASH_PREFIX + sha256_hex(secret)


def _is_hashed_key(key: str) -> bool:
    return key.startswith((_HASH_PREFIX, _REFRESH_PREFIX + _HASH_PREFIX))


def _purge_expired(records: dict[str, Any], now: int) -> dict[str, Any]:
    """Drop records whose ``expires_at`` has passed (they are otherwise only
    removed when presented, so unused ones would accumulate forever)."""

    def _live(rec: Any) -> bool:
        try:
            return isinstance(rec, dict) and int(rec.get("expires_at", 0)) >= now
        except (TypeError, ValueError):
            return False

    return {k: v for k, v in records.items() if _live(v)}


def _now() -> int:
    return int(time.time())


_DIR_MODE = 0o700
_FILE_MODE = 0o600


class StoreUnreadableError(Exception):
    """A state file exists but cannot be parsed (as opposed to being absent)."""


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
        # Create the store dir private *at creation*: mkdir's mode is masked
        # by umask, but 0o700 carries no group/other bits to begin with, so a
        # dir we create is 0o700 regardless of the caller's umask — no
        # world-readable window before the chmod below. `mode=` applies only
        # to a freshly-created leaf, never to an existing dir.
        parent.mkdir(mode=_DIR_MODE, parents=True, exist_ok=True)
        # Tighten a pre-existing dir too; best-effort, since a dir owned by
        # another user (e.g. operator-provisioned) is not ours to chmod.
        with contextlib.suppress(OSError):
            parent.chmod(_DIR_MODE)
        # Fail closed on an actually-insecure store (SEC-8). The secret files
        # are written 0o600 regardless, but a group/other-accessible store dir
        # lets other local users list or tamper with the token files. If the
        # dir is still group/other-accessible here — we could neither create
        # nor tighten it to 0o700 — refuse rather than run with an exposed
        # token store. A correctly-0o700 dir owned by any user passes.
        mode = parent.stat().st_mode & 0o777
        if mode & 0o077:
            raise PermissionError(
                f"OAuth state dir {parent} is group/other-accessible "
                f"(mode {mode:#o}); expected 0o700. Refusing to use an exposed "
                "token store."
            )

    def exists(self) -> bool:
        return self._path.exists()

    def load(self, *, strict: bool = False) -> dict[str, Any]:
        """Read the store; an absent file is empty.

        Tolerant by default: an unreadable file also reads as empty. ``strict``
        distinguishes the two - a file that exists but cannot be parsed raises
        :class:`StoreUnreadableError` instead of masquerading as an empty store,
        which matters wherever "empty" would *open* something (client registration).
        """
        try:
            data: Any = json.loads(self._path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {}
        except (OSError, json.JSONDecodeError) as exc:
            if strict:
                raise StoreUnreadableError(f"{self._path.name} exists but is unreadable") from exc
            return {}
        if isinstance(data, dict):
            return data
        if strict:
            raise StoreUnreadableError(f"{self._path.name} does not hold a JSON object")
        return {}

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
        resource_url: str = "https://localhost:8080",
        require_approval: bool = False,
    ) -> None:
        self._resource = normalize_resource(resource_url)
        base = Path(state_dir).expanduser()
        self._require_approval = require_approval
        self._approvals = _Store(base / "approvals.json")
        self._clients = _Store(base / "clients.json")
        self._codes = _Store(base / "codes.json")
        self._tokens = _Store(base / "tokens.json")
        self._single_client = single_client
        self._access_ttl = access_ttl
        self._refresh_ttl = refresh_ttl
        self._code_ttl = code_ttl
        self._migrate_secret_storage()
        self._migrate_legacy_approvals()
        # Single per-provider lock serializes every read-modify-write
        # against the JSON stores. The atomic `tmp.replace` inside
        # ``_Store.save`` guarantees disk consistency for one writer; this
        # lock guarantees cross-coroutine consistency under concurrent
        # HTTP-transport traffic (token rotation, register-client, revoke).
        self._lock = asyncio.Lock()

    def _migrate_secret_storage(self) -> None:
        """Rewrite pre-hashing records so no raw secret stays on disk (idempotent).

        Records written before secrets were hashed are keyed by the raw token / code
        (refresh tokens as ``refresh:<raw>``) and repeat it in a ``token`` / ``code``
        field. Re-key them by hash and drop the field; entries already hashed are left
        alone. Expired records are dropped on the way.
        """
        now = _now()
        for store, field_name in ((self._tokens, "token"), (self._codes, "code")):
            data = store.load()
            legacy = [k for k in data if not _is_hashed_key(k)]
            if not legacy:
                continue
            migrated: dict[str, Any] = {k: v for k, v in data.items() if _is_hashed_key(k)}
            for key, rec in data.items():
                if _is_hashed_key(key) or not isinstance(rec, dict):
                    continue
                rec = {k: v for k, v in rec.items() if k != field_name}
                if key.startswith(_REFRESH_PREFIX):
                    migrated[_REFRESH_PREFIX + _hashed(key[len(_REFRESH_PREFIX) :])] = rec
                else:
                    migrated[_hashed(key)] = rec
            store.save(_purge_expired(migrated, now))

    # --- operator approval ---
    def _migrate_legacy_approvals(self) -> None:
        """Clients registered before approvals existed stay approved.

        With no ``approvals.json`` yet, every client already on disk predates the
        approval gate and was accepted under the old rules; carry them over as
        approved so an upgrade does not lock the operator's existing client out.
        A fresh install (no clients) writes nothing: its first client registers as
        pending.
        """
        if self._approvals.exists():
            return
        try:
            legacy = self._clients.load(strict=True)
        except StoreUnreadableError:
            return  # fail closed: nothing is approved until the operator repairs it
        if legacy:
            self._approvals.save({cid: {"approved": True, "legacy": True} for cid in legacy})

    def _is_approved(self, client_id: str) -> bool:
        if not self._require_approval:
            return True
        try:
            rec = self._approvals.load(strict=True).get(client_id)
        except StoreUnreadableError:
            return False  # fail closed
        return isinstance(rec, dict) and rec.get("approved") is True

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
            try:
                clients = self._clients.load(strict=True)
            except StoreUnreadableError as exc:
                # An unparsable clients.json must not read as "no clients": that
                # would reopen registration and let a caller replace the real client.
                raise ValueError(
                    "OAuth client store is unreadable; refusing registration "
                    "(repair or restore clients.json)"
                ) from exc
            incoming = json.loads(client_info.model_dump_json())
            # Single-client lockdown freezes registration once the first client
            # is registered. The earlier guard only refused a *new* client_id
            # (`cid not in clients`), so an attacker who learned the existing
            # client_id (and reached the CIDR-allowed registration endpoint)
            # could re-register it and overwrite its `redirect_uri` — steering
            # the next authorization code to an attacker URL (AUTH-2). Refuse
            # anything that would create or *modify* a client under lockdown; a
            # byte-identical re-registration is a harmless no-op and still
            # allowed so a client that re-runs DCR is not broken.
            if self._single_client and clients and clients.get(cid) != incoming:
                raise ValueError("Dynamic client registration is closed (single-client lockdown).")
            is_new = cid not in clients
            clients[cid] = incoming
            self._clients.save(clients)
            if is_new:
                # A new client is usable only after the operator approves it (when
                # the gate is on); an identical re-registration keeps its status.
                approvals = self._approvals.load()
                approvals[cid] = {"approved": not self._require_approval}
                self._approvals.save(approvals)

    # --- authorization codes ---
    async def authorize(
        self, client: OAuthClientInformationFull, params: AuthorizationParams
    ) -> str:
        try:
            resource = self._checked_resource(
                self._resource if params.resource is None else params.resource
            )
        except (ValueError, TokenError) as exc:
            raise AuthorizeError(
                error="invalid_target", error_description="Resource is not this server"
            ) from exc
        if not self._is_approved(client.client_id or ""):
            _log.warning(
                "authorization refused: client %s is awaiting operator approval "
                "(run: relay-shell --auth-approve %s)",
                client.client_id,
                client.client_id,
            )
            raise AuthorizeError(
                error="access_denied",
                error_description="Client is awaiting operator approval",
            )
        code = secrets.token_urlsafe(48)
        async with self._lock:
            codes = _purge_expired(self._codes.load(), _now())
            codes[_hashed(code)] = {
                "client_id": client.client_id or "",
                "scopes": list(getattr(params, "scopes", None) or _SCOPES),
                "expires_at": _now() + self._code_ttl,
                "code_challenge": getattr(params, "code_challenge", ""),
                "redirect_uri": str(params.redirect_uri),
                "redirect_uri_provided_explicitly": bool(
                    getattr(params, "redirect_uri_provided_explicitly", True)
                ),
                "resource": resource,
            }
            self._codes.save(codes)
        return construct_redirect_uri(
            str(params.redirect_uri), code=code, state=getattr(params, "state", None)
        )

    def _build_auth_code(self, code: str, rec: dict[str, Any]) -> AuthorizationCode | None:
        try:
            return AuthorizationCode(
                code=code,
                scopes=rec["scopes"],
                expires_at=float(rec["expires_at"]),
                client_id=rec["client_id"],
                code_challenge=rec.get("code_challenge", ""),
                redirect_uri=rec["redirect_uri"],
                redirect_uri_provided_explicitly=rec.get("redirect_uri_provided_explicitly", True),
                # Stored audience is authoritative; legacy unbound records fail closed.
                resource=self._checked_resource(rec.get("resource")),
            )
        except Exception:  # noqa: BLE001
            return None

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> AuthorizationCode | None:
        if not _SECRET_RE.match(authorization_code):
            return None
        async with self._lock:
            codes = self._codes.load()
            key = _hashed(authorization_code)
            if key not in codes:
                key = authorization_code  # record written before secrets were hashed
            rec = codes.get(key)
            if not rec or rec.get("client_id") != (client.client_id or ""):
                return None
            if int(rec.get("expires_at", 0)) < _now():
                codes.pop(key, None)
                self._codes.save(codes)
                return None
            return self._build_auth_code(authorization_code, rec)

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode
    ) -> OAuthToken:
        async with self._lock:
            codes = self._codes.load()
            raw = authorization_code.code
            record = codes.pop(_hashed(raw), None)
            if record is None and _SECRET_RE.match(raw):
                record = codes.pop(raw, None)  # written before secrets were hashed
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
            if int(record.get("expires_at", 0)) < _now():
                # Same defense-in-depth posture as the client check: enforce
                # expiry atomically at exchange, not only at ``load``. A code
                # valid when loaded can lapse in the load->exchange window (or a
                # caller could reach exchange without load), and expiry, like
                # client ownership, must gate token issuance. The code was
                # already popped above, so this also removes the stale record.
                self._codes.save(codes)
                raise TokenError(
                    error="invalid_grant",
                    error_description="authorization code already used or expired",
                )
            self._codes.save(codes)
            scopes = list(record["scopes"])
            resource = self._checked_resource(record.get("resource"))
            # _issue is sync and does its own load/save on tokens.json; the
            # caller's lock covers both stores atomically from a concurrent
            # coroutine's view.
            return self._issue(client.client_id or "", scopes, resource=resource)

    # --- tokens ---
    def _checked_resource(self, resource: object) -> str:
        try:
            if not isinstance(resource, str) or normalize_resource(resource) != self._resource:
                raise ValueError("resource mismatch")
        except ValueError as exc:
            raise TokenError(
                error="invalid_grant", error_description="Grant is not bound to this server"
            ) from exc
        return self._resource

    def _issue(
        self, client_id: str, scopes: list[str], *, resource: str | None = None
    ) -> OAuthToken:
        resource = self._checked_resource(self._resource if resource is None else resource)
        access = secrets.token_urlsafe(48)
        refresh = secrets.token_urlsafe(48)
        tokens = _purge_expired(self._tokens.load(), _now())
        tokens[_hashed(access)] = {
            "client_id": client_id,
            "scopes": scopes,
            "resource": resource,
            "expires_at": _now() + self._access_ttl,
        }
        tokens[_REFRESH_PREFIX + _hashed(refresh)] = {
            "client_id": client_id,
            "scopes": scopes,
            "resource": resource,
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
        # Refresh tokens live under the `refresh:` key prefix. Reject any bearer
        # string carrying that prefix so a refresh token presented as an access
        # token (`Authorization: Bearer refresh:<tok>`) cannot authenticate via
        # this lookup — token-type confusion that would otherwise grant a
        # refresh token full access-token scope for the (long) refresh TTL.
        if token.startswith(_REFRESH_PREFIX) or not _SECRET_RE.match(token):
            return None
        async with self._lock:
            # Called for every authenticated request: the whole-file read (and, on
            # expiry, write) runs off the event loop. The asyncio lock still
            # serializes it against every other store access in this process.
            return await asyncio.to_thread(self._load_access_token_sync, token)

    def _load_access_token_sync(self, token: str) -> AccessToken | None:
        tokens = self._tokens.load()
        key = _hashed(token)
        if key not in tokens:
            key = token  # record written before secrets were hashed
        rec = tokens.get(key)
        if not rec:
            return None
        if int(rec.get("expires_at", 0)) < _now():
            tokens.pop(key, None)
            self._tokens.save(tokens)
            return None
        try:
            return AccessToken(
                token=token,
                client_id=rec["client_id"],
                scopes=rec["scopes"],
                expires_at=int(rec["expires_at"]),
                resource=self._checked_resource(rec.get("resource")),
            )
        except Exception:  # noqa: BLE001
            return None

    async def load_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: str
    ) -> RefreshToken | None:
        # Hold the per-provider lock for the read, like every other store
        # access (SEC-6). Without it a concurrent revoke/rotation between this
        # load and the subsequent exchange could surface a spurious
        # invalid_grant to a legitimate refresh. asyncio.Lock is not reentrant,
        # but no lock-holding path calls this method, so there is no nested
        # acquire / deadlock.
        if not _SECRET_RE.match(refresh_token):
            return None
        async with self._lock:
            records = self._tokens.load()
            rec = records.get(_REFRESH_PREFIX + _hashed(refresh_token))
            if rec is None:
                rec = records.get(_REFRESH_PREFIX + refresh_token)  # pre-hashing record
            if not rec or rec.get("client_id") != (client.client_id or ""):
                return None
            if int(rec.get("expires_at", 0)) < _now():
                return None
            try:
                return RefreshToken(
                    token=refresh_token,
                    client_id=rec["client_id"],
                    scopes=rec["scopes"],
                    expires_at=int(rec["expires_at"]),
                    resource=self._checked_resource(rec.get("resource")),
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
            raw = refresh_token.token
            record = tokens.pop(_REFRESH_PREFIX + _hashed(raw), None)
            if record is None and _SECRET_RE.match(raw):
                record = tokens.pop(_REFRESH_PREFIX + raw, None)  # pre-hashing record
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
            if int(record.get("expires_at", 0)) < _now():
                # Enforce expiry at exchange too, mirroring the client check and
                # ``load_refresh_token``'s expiry gate — an expired refresh token
                # must not mint a fresh access/refresh pair even if exchange is
                # reached without load or the token lapsed in the load->exchange
                # window. The token was already popped above, so this also
                # removes the stale record.
                self._tokens.save(tokens)
                raise TokenError(
                    error="invalid_grant",
                    error_description="refresh token already used or expired",
                )
            self._tokens.save(tokens)
            resource = self._checked_resource(record.get("resource"))
            granted = list(record["scopes"])
            effective = list(scopes or granted)
            if not set(effective).issubset(granted):
                raise TokenError(error="invalid_scope", error_description="Scope exceeds grant")
            return self._issue(client.client_id or "", effective, resource=resource)

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        async with self._lock:
            tokens = self._tokens.load()
            raw = getattr(token, "token", "")
            for key in (
                _hashed(raw),
                _REFRESH_PREFIX + _hashed(raw),
                raw,  # records written before secrets were hashed
                _REFRESH_PREFIX + raw,
            ):
                tokens.pop(key, None)
            self._tokens.save(tokens)


def build_auth_settings(issuer: str, resource_url: str | None = None) -> AuthSettings:
    url = AnyHttpUrl(issuer)
    return AuthSettings(
        issuer_url=url,
        resource_server_url=AnyHttpUrl(normalize_resource(resource_url or issuer)),
        validate_token_resource=True,
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
        resource_url=getattr(settings, "auth_resource_url", "") or settings.auth_issuer,
        require_approval=bool(getattr(settings, "auth_require_approval", False)),
    )
