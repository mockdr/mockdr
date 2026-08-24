"""Rewrite a JSON response body from a pure-ASGI middleware.

``BaseHTTPMiddleware`` buffers every response through an anyio task group and
a memory object stream, whether or not the middleware touches it — a cost
paid on all 561 routes so that two Splunk-only middlewares can rewrite Atom
collections. This does the same job with no cost for the requests it does
not act on: the response passes through untouched until a body is actually
claimed, and only then is it collected.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable

from starlette.types import Message, Receive, Scope, Send

#: Decide from the response's status and headers whether the body is wanted.
Claim = Callable[[int, dict[bytes, bytes]], bool]
#: Turn the decoded payload into the replacement body and its content type.
Rewrite = Callable[[object], "tuple[bytes, str] | None"]


def header_map(raw: list[tuple[bytes, bytes]]) -> dict[bytes, bytes]:
    """The response headers as a lower-cased mapping."""
    return {name.lower(): value for name, value in raw}


async def rewrite_json_body(
    app: Callable[[Scope, Receive, Send], Awaitable[None]],
    scope: Scope,
    receive: Receive,
    send: Send,
    *,
    claims: Claim,
    rewrite: Rewrite,
) -> None:
    """Run ``app``, and rewrite its JSON body when ``claims`` says so.

    A body that is not claimed streams through chunk by chunk, exactly as if
    this middleware were not installed. A claimed one is collected, decoded
    and handed to ``rewrite``; a body that is not JSON, or a rewrite that
    returns ``None``, is forwarded unchanged.
    """
    start: Message | None = None
    chunks: list[bytes] = []
    claimed = False

    async def send_wrapper(message: Message) -> None:
        nonlocal start, claimed
        if message["type"] == "http.response.start":
            headers = header_map(message.get("headers", []))
            claimed = headers.get(b"content-type", b"").startswith(b"application/json") and claims(
                message["status"], headers
            )
            if not claimed:
                await send(message)
                return
            start = message
            return
        if message["type"] != "http.response.body" or not claimed:
            await send(message)
            return
        chunks.append(bytes(message.get("body", b"")))
        if message.get("more_body"):
            return
        assert start is not None  # noqa: S101 - a body cannot precede its start
        await _finish(send, start, b"".join(chunks), rewrite)

    await app(scope, receive, send_wrapper)


async def _finish(send: Send, start: Message, body: bytes, rewrite: Rewrite) -> None:
    """Send the rewritten body, or the original one when it cannot be rewritten."""
    replacement: tuple[bytes, str] | None = None
    try:
        payload = json.loads(body)
    except (ValueError, UnicodeDecodeError):
        payload = None
    if payload is not None:
        replacement = rewrite(payload)

    if replacement is None:
        await send(start)
        await send({"type": "http.response.body", "body": body})
        return

    new_body, content_type = replacement
    headers = [
        (name, value)
        for name, value in start.get("headers", [])
        if name.lower() not in (b"content-length", b"content-type")
    ]
    headers.append((b"content-type", content_type.encode()))
    headers.append((b"content-length", str(len(new_body)).encode()))
    await send({**start, "headers": headers})
    await send({"type": "http.response.body", "body": new_body})
