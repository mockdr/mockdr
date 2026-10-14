"""Reading a request header and stamping response headers, in pure ASGI.

Several middlewares put a vendor's tracking ids on every answer -- Graph's
``request-id``/``client-request-id``, ARM's ``x-ms-request-id``/
``x-ms-correlation-request-id``, Falcon's ``X-CS-TRACEID`` -- and several
read one request header to decide what to do. Each wrote the same loop and
the same ``send`` wrapper; these are the one copy.
"""
from __future__ import annotations

from collections.abc import Mapping

from starlette.datastructures import MutableHeaders
from starlette.types import Message, Scope, Send


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
