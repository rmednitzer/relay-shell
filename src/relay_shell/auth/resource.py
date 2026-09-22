"""Exact resource binding and bounded validation of OAuth token resource parameters."""

from __future__ import annotations

from typing import Any

from mcp.server.mcpserver import MCPServer
from pydantic import AnyHttpUrl
from starlette.applications import Starlette
from starlette.exceptions import HTTPException
from starlette.formparsers import MultiPartException
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send


def normalize_resource(value: str) -> str:
    url = AnyHttpUrl(value)
    if url.fragment is not None or url.username is not None or url.password is not None:
        raise ValueError("Resource must not contain credentials or a fragment")
    return str(url).removesuffix("/")


class TokenResourceMiddleware:
    """Validate what the SDK token handler parses but does not pass to providers.

    Preserve the SDK's authentication, PKCE, scope, CORS and body-limit wrappers.
    Only the token endpoint is inspected, using a bounded, replayable body.
    No credentials, submitted resource values or form bodies are logged.
    """

    def __init__(self, app: ASGIApp, *, resource_url: str) -> None:
        self.app = app
        self.resource = normalize_resource(resource_url)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if (
            scope["type"] != "http"
            or scope.get("path") != "/token"
            or scope.get("method") != "POST"
        ):
            await self.app(scope, receive, send)
            return
        chunks: list[bytes] = []
        size = 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            chunk = message.get("body", b"")
            size += len(chunk)
            if size > 65536:
                await self._reject(scope, receive, send, "invalid_request", 413)
                return
            chunks.append(chunk)
            if not message.get("more_body", False):
                break
        body = b"".join(chunks)
        consumed = False

        async def replay() -> Message:
            nonlocal consumed
            if not consumed:
                consumed = True
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()

        request = Request(scope, replay)
        try:
            async with request.form(max_files=0, max_fields=32) as form:
                values = form.getlist("resource")
                if len(values) > 1 or (
                    values
                    and (
                        not isinstance(values[0], str)
                        or normalize_resource(values[0]) != self.resource
                    )
                ):
                    await self._reject(scope, receive, send, "invalid_target", 400)
                    return
        except (ValueError, HTTPException, MultiPartException):
            await self._reject(scope, receive, send, "invalid_request", 400)
            return
        consumed = False
        await self.app(scope, replay, send)

    @staticmethod
    async def _reject(scope: Scope, receive: Receive, send: Send, error: str, status: int) -> None:
        response = JSONResponse(
            {"error": error},
            status_code=status,
            headers={
                "Cache-Control": "no-store",
                "Pragma": "no-cache",
                "Access-Control-Allow-Origin": "*",
            },
        )
        await response(scope, receive, send)


class ResourceBoundMCPServer(MCPServer[Any]):
    """Add the missing token-request resource check to the SDK HTTP application."""

    def streamable_http_app(self, **kwargs: Any) -> Starlette:
        app = super().streamable_http_app(**kwargs)
        auth = self.settings.auth
        if auth is not None and auth.resource_server_url is not None:
            app.add_middleware(TokenResourceMiddleware, resource_url=str(auth.resource_server_url))
        return app
