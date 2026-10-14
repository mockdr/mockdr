"""Pure-ASGI pieces several middlewares need: a header, a stamp, a replayed body.

Several middlewares put a vendor's tracking ids on every answer -- Graph's
``request-id``/``client-request-id``, ARM's ``x-ms-request-id``/
``x-ms-correlation-request-id``, Falcon's ``X-CS-TRACEID`` -- and several
read one request header to decide what to do. Each wrote the same loop and
the same ``send`` wrapper; these are the one copy. Two Splunk middlewares read
the whole request body and hand the route a ``receive`` that replays it,
with the same loop and the same closure (:func:`buffered_body`).
"""
from __future__ import annotations

from collections.abc import Mapping

from starlette.datastructures import MutableHeaders
from starlette.types import Message, Receive, Scope, Send


def request_header(scope: Scope, wanted: bytes) -> str:
    """The first value of request header *wanted* (lower-case), or the empty string."""
    for name, value in scope.get("headers") or ():
        if name.lower() == wanted:
            return bytes(value).decode("latin-1")
    return ""


def stamping(send: Send, headers: Mapping[str, str], *, replace: bool = True) -> Send:
    """*send*, with *headers* added to the response head it carries.

    Args:
        send:    The ASGI send callable to wrap.
        headers: The headers to stamp.
        replace: Overwrite a header the app set itself; when False, a value
                 the app already set is kept.
    """
    async def stamped(message: Message) -> None:
        if message["type"] == "http.response.start":
            head = MutableHeaders(scope=message)
            for name, value in headers.items():
                if replace or name not in head:
                    head[name] = value
        await send(message)

    return stamped


async def buffered_body(receive: Receive) -> tuple[bytes, Receive]:
    """Read the request body, and a ``receive`` that replays it to the route.

    The replay hands the whole body over once, then defers to the real
    ``receive`` -- which is where a later disconnect arrives.
    """
    chunks: list[bytes] = []
    more = True
    while more:
        message = await receive()
        if message["type"] == "http.disconnect":
            break
        chunks.append(bytes(message.get("body", b"")))
        more = bool(message.get("more_body"))
    body = b"".join(chunks)
    replayed = False

    async def replay() -> Message:
        nonlocal replayed
        if replayed:
            return await receive()
        replayed = True
        return {"type": "http.request", "body": body, "more_body": False}

    return body, replay
