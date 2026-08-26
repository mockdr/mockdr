"""Name the charset on JSON where the product names it.

`application/json` is UTF-8 by definition, so the parameter changes nothing
about the bytes — and the products disagree about it anyway, which is the
point. A client that compares the header string, logs it, or picks a decoder
from it sees three different products, and mockdr answered the same thing for
all of them:

* **Kibana** serves through Hapi and writes ``application/json; charset=utf-8``;
* **splunkd** writes ``application/json; charset=UTF-8`` — the same parameter,
  the other case — on its JSON *and* on HEC's;
* **Elasticsearch**, in the same distribution as Kibana, writes
  ``application/json`` and nothing else.

All three measured: Kibana 8.15, Elasticsearch 8.15, Splunk 10.4.2. The six
mounts with no runnable product are left alone rather than guessed at.

Pure ASGI: a request outside those prefixes, or a response that is not plain
``application/json``, is passed straight through.
"""

from __future__ import annotations

from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

_JSON = "application/json"

#: Prefix -> the content type that mount's product writes for JSON.
_CHARSETS: tuple[tuple[str, str], ...] = (
    ("/kibana", "application/json; charset=utf-8"),
    ("/splunk", "application/json; charset=UTF-8"),
)


class JsonCharsetMiddleware:
    """Rewrite a plain JSON content type to the one its product writes."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Name the charset on a JSON response from a mount that names it."""
        path = scope.get("path", "") if scope["type"] == "http" else ""
        wanted = next((value for prefix, value in _CHARSETS if path.startswith(prefix)), None)
        if wanted is None:
            await self.app(scope, receive, send)
            return

        async def send_with_charset(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                if headers.get("content-type", "").strip() == _JSON:
                    headers["content-type"] = wanted
            await send(message)

        await self.app(scope, receive, send_with_charset)
