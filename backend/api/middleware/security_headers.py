"""Standard security headers on every response.

Pure ASGI rather than ``BaseHTTPMiddleware``: the latter wraps every request
in an anyio task group with a memory object stream, which costs more than
the work this middleware does. It runs on all 561 routes, so that overhead
is the floor of every response.
"""

from __future__ import annotations

from starlette.types import ASGIApp, Message, Receive, Scope, Send

_HEADERS = [
    (b"x-content-type-options", b"nosniff"),
    (b"x-frame-options", b"DENY"),
    # The legacy auditor is off, as OWASP recommends; CSP-era browsers ignore it.
    (b"x-xss-protection", b"0"),
    (b"referrer-policy", b"strict-origin-when-cross-origin"),
    (b"permissions-policy", b"camera=(), microphone=(), geolocation=()"),
]


class SecurityHeadersMiddleware:
    """Inject security headers into every HTTP response."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = message.setdefault("headers", [])
                present = {name.lower() for name, _ in headers}
                headers.extend((k, v) for k, v in _HEADERS if k not in present)
            await send(message)

        await self.app(scope, receive, send_wrapper)
