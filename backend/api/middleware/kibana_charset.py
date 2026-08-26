"""Say ``charset=utf-8`` on Kibana's JSON, because Kibana does.

Kibana serves through Hapi, which names the charset on every JSON response:
``application/json; charset=utf-8``. Elasticsearch, next door and in the same
distribution, does not — its answers are ``application/json`` alone. Both are
correct JSON either way, and a client that compares the header string, or
that picks a decoder from it, sees two different products where the mock had
one.

Pure ASGI: a request outside ``/kibana`` is passed straight through, and a
response that is not JSON is left as it is.
"""

from __future__ import annotations

from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

_KIBANA_PREFIX = "/kibana"
_JSON = "application/json"
_WITH_CHARSET = "application/json; charset=utf-8"


class KibanaCharsetMiddleware:
    """Append Hapi's charset to Kibana's JSON content type."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Rewrite the content type of a Kibana JSON response."""
        if scope["type"] != "http" or not scope.get("path", "").startswith(_KIBANA_PREFIX):
            await self.app(scope, receive, send)
            return

        async def send_with_charset(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                if headers.get("content-type", "").strip() == _JSON:
                    headers["content-type"] = _WITH_CHARSET
            await send(message)

        await self.app(scope, receive, send_with_charset)
