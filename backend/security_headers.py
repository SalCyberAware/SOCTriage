"""Security headers on every HTTP response the backend sends.

The API returns JSON, never HTML a browser would render, so most of these are
defence in depth rather than the fix for a known hole. They cost nothing and
close off whole classes of mistakes before somebody makes one:

  * ``X-Content-Type-Options: nosniff``: a browser must believe the declared
    Content-Type. Without it, a JSON body carrying attacker-controlled text
    (an alert, a note) could be sniffed into HTML or script.
  * ``X-Frame-Options: DENY``: no page may frame a response, so nothing the
    API serves can be used in a clickjacking overlay.
  * ``Referrer-Policy: strict-origin-when-cross-origin``: a cross-origin
    request carries the origin only, never a path that might hold a case id.
  * ``Strict-Transport-Security``: once a browser has seen the API over
    HTTPS, it refuses plain HTTP to it for a year, subdomains included.
    Browsers ignore it on plain-HTTP responses, so local development is
    unaffected.

A pure ASGI middleware rather than ``@app.middleware("http")``: Starlette's
BaseHTTPMiddleware wraps the response body in an extra task, which changes
streaming and exception behaviour for every route just to add four headers.
This only edits the ``http.response.start`` message on its way out.

A header a route set itself is left alone, so a route that ever needs a
different value for one of these can still have it.
"""
from __future__ import annotations

from collections.abc import Awaitable, Callable, MutableMapping
from typing import Any

Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]

# Kept identical to the "headers" block in frontend/vercel.json.
SECURITY_HEADERS: dict[str, str] = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
}

_ENCODED = [(name.lower().encode("latin-1"), value.encode("latin-1"))
            for name, value in SECURITY_HEADERS.items()]


class SecurityHeadersMiddleware:
    """Add :data:`SECURITY_HEADERS` to every HTTP response."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                present = {name.lower() for name, _ in headers}
                headers.extend(
                    (name, value) for name, value in _ENCODED if name not in present
                )
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, send_with_headers)
