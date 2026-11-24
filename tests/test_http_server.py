from __future__ import annotations

import asyncio
import os
import unittest
from unittest import mock

from drost_ai.http_server import BearerAuthMiddleware, resolve_token


def _request(app, path: str, headers: list[tuple[bytes, bytes]] | None = None) -> tuple[int, bool]:
    sent: list[dict] = []
    reached = {"inner": False}

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        sent.append(message)

    scope = {"type": "http", "path": path, "headers": headers or []}
    asyncio.run(app(scope, receive, send))
    status = next((m["status"] for m in sent if m["type"] == "http.response.start"), None)
    return status, reached


class BearerAuthMiddlewareTests(unittest.TestCase):
    def setUp(self) -> None:
        self.calls = 0

        async def inner(scope, receive, send):
            self.calls += 1
            await send({"type": "http.response.start", "status": 204, "headers": []})
            await send({"type": "http.response.body", "body": b""})

        self.app = BearerAuthMiddleware(inner, "s3cret")

    def test_health_probe_is_unauthenticated(self) -> None:
        status, _ = _request(self.app, "/healthz")
        self.assertEqual(status, 200)
        self.assertEqual(self.calls, 0)

    def test_missing_and_wrong_tokens_are_rejected(self) -> None:
        self.assertEqual(_request(self.app, "/mcp")[0], 401)
        self.assertEqual(_request(self.app, "/mcp", [(b"authorization", b"Bearer nope")])[0], 401)
        self.assertEqual(_request(self.app, "/mcp", [(b"authorization", b"Basic s3cret")])[0], 401)
        self.assertEqual(self.calls, 0)

    def test_valid_token_reaches_the_mcp_app(self) -> None:
        self.assertEqual(_request(self.app, "/mcp", [(b"authorization", b"Bearer s3cret")])[0], 204)
        self.assertEqual(self.calls, 1)

    def test_lifespan_scope_passes_through(self) -> None:
        seen = []

        async def inner(scope, receive, send):
            seen.append(scope["type"])

        asyncio.run(BearerAuthMiddleware(inner, "s3cret")({"type": "lifespan"}, None, None))
        self.assertEqual(seen, ["lifespan"])


class ResolveTokenTests(unittest.TestCase):
    def test_http_requires_a_token_unless_explicitly_opted_out(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(SystemExit):
                resolve_token()
        with mock.patch.dict(os.environ, {"DROST_MCP_ALLOW_UNAUTHENTICATED": "1"}, clear=True):
            self.assertIsNone(resolve_token())
        with mock.patch.dict(os.environ, {"DROST_MCP_AUTH_TOKEN": " abc "}, clear=True):
            self.assertEqual(resolve_token(), "abc")


if __name__ == "__main__":
    unittest.main()
