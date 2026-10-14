"""Answer a request that asked to close the connection with ``Connection: close``.

RFC 9112 §9.6: a server that receives the ``close`` connection option "MUST
initiate closure of the connection after it sends the final response" and
"SHOULD send a "close" connection option in its final response on that
connection". uvicorn's h11 protocol does both; its httptools protocol -- the
one ``uvicorn[standard]`` installs and therefore the one every way this repo
starts the mock uses -- closes the connection but sends no header.

The difference is invisible to most clients and fatal to one: splunklib, the
Splunk SDK, sends ``Connection: Close`` on every request and decides whether
it may still read the body from the answer's ``Connection`` header
(``splunklib/binding.py``, ``handler``: ``is_keepalive = "keep-alive" in
response.getheader("connection", default="close")``, then
``connection.close()`` unless keep-alive). An HTTP/1.1 answer without the
header is, to ``http.client``, a persistent one, so closing the connection
closed the response with it and splunklib read an empty body from every
call -- ``client.connect()`` failed parsing the login answer as XML.

This middleware adds the header the RFC asks for whenever the request carried
the option, whichever protocol implementation serves it.
"""
from __future__ import annotations

from starlette.types import ASGIApp, Message, Receive, Scope, Send


class ConnectionCloseMiddleware:
    """Echo the ``close`` connection option on the response."""

    def __init__(self, app: ASGIApp) -> None:
        """Wrap *app*."""
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Add ``connection: close`` to the answer when the request asked for it."""
        if scope["type"] != "http" or not _asks_to_close(scope):
            await self.app(scope, receive, send)
            return

        async def send_with_close(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                if not any(name.lower() == b"connection" for name, _ in headers):
                    headers.append((b"connection", b"close"))
                    message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, send_with_close)


def _asks_to_close(scope: Scope) -> bool:
    for name, value in scope.get("headers", []):
        if name.lower() == b"connection":
            tokens = {t.strip().lower() for t in value.split(b",")}
            if b"close" in tokens:
                return True
    return False
