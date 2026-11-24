"""Streamable HTTP transport for running Drost as a long-lived network service."""

from __future__ import annotations

import hmac
import json
import os
from typing import Any, Awaitable, Callable

Scope = dict[str, Any]
Receive = Callable[[], Awaitable[dict[str, Any]]]
Send = Callable[[dict[str, Any]], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]

TOKEN_ENV = "DROST_MCP_AUTH_TOKEN"
ALLOW_UNAUTHENTICATED_ENV = "DROST_MCP_ALLOW_UNAUTHENTICATED"
HEALTH_PATH = "/healthz"


async def _send_json(send: Send, status: int, body: dict[str, Any], headers: list[tuple[bytes, bytes]] | None = None) -> None:
    payload = json.dumps(body).encode("utf-8")
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(payload)).encode())] + (headers or []),
        }
    )
    await send({"type": "http.response.body", "body": payload})


class BearerAuthMiddleware:
    """Require ``Authorization: Bearer <token>`` on every HTTP request except the health probe."""

    def __init__(self, app: ASGIApp, token: str | None) -> None:
        self.app = app
        self.token = token.encode("utf-8") if token else None

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        if scope.get("path") == HEALTH_PATH:
            await _send_json(send, 200, {"status": "ok"})
            return
        if self.token is not None and not self._authorized(scope):
            await _send_json(send, 401, {"error": "unauthorized"}, [(b"www-authenticate", b'Bearer realm="drost-mcp"')])
            return
        await self.app(scope, receive, send)

    def _authorized(self, scope: Scope) -> bool:
        for name, value in scope.get("headers", []):
            if name.lower() == b"authorization":
                scheme, _, credential = value.partition(b" ")
                return scheme.lower() == b"bearer" and hmac.compare_digest(credential.strip(), self.token or b"")
        return False


def resolve_token() -> str | None:
    token = os.environ.get(TOKEN_ENV, "").strip()
    if token:
        return token
    if os.environ.get(ALLOW_UNAUTHENTICATED_ENV, "").strip().lower() in {"1", "true", "yes"}:
        return None
    raise SystemExit(
        f"drost-mcp: refusing to serve HTTP without {TOKEN_ENV}. Drost exposes arbitrary command "
        f"execution; set a strong token or explicitly opt out with {ALLOW_UNAUTHENTICATED_ENV}=1."
    )


def build_app(mcp: Any, token: str | None) -> ASGIApp:
    # FastMCP enables DNS-rebinding protection that only accepts localhost Host headers whenever it
    # is constructed with its default 127.0.0.1 host. A network service must accept the Host its
    # clients use, so authentication is enforced by the bearer token instead.
    from mcp.server.transport_security import TransportSecuritySettings

    mcp.settings.transport_security = TransportSecuritySettings(enable_dns_rebinding_protection=False)
    return BearerAuthMiddleware(mcp.streamable_http_app(), token)


def serve(mcp: Any, host: str, port: int) -> None:
    import uvicorn

    token = resolve_token()
    mcp.settings.host = host
    mcp.settings.port = port
    app = build_app(mcp, token)
    uvicorn.run(app, host=host, port=port, log_level=mcp.settings.log_level.lower(), proxy_headers=True, forwarded_allow_ips="*")
