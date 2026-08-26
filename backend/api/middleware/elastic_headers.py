"""The headers the Elastic products put on every answer.

`X-elastic-product: Elasticsearch` is not decoration: every official
Elasticsearch client since 7.14 — Python, JavaScript, Java, Go — reads it off
the first response and refuses to talk to a server that does not send it,
with an `UnsupportedProductError`. mockdr never sent it, so the one client
this mount exists for could not use it at all. Measured on 8.15: it is on
every answer, including a 404, and *not* on the 401 that asks for
credentials — the header goes on once the request has been authenticated.

Kibana names itself the same way on every answer, whatever the status and
whether or not the caller authenticated: `kbn-name`, `kbn-license-sig`, and
a `cache-control` that keeps its API answers out of every cache. mockdr sent
none of the three.

Pure ASGI, and scoped by mount: a request to another product is passed
straight through.
"""

from __future__ import annotations

import hashlib

from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

_ES_PREFIX = "/elastic"
_KBN_PREFIX = "/kibana"

#: What Elasticsearch calls itself to a client that checks.
_PRODUCT = "Elasticsearch"

#: What this install calls itself — the same name `/api/status` answers with,
#: because a client that reads both must not see two Kibanas.
_KBN_NAME = "mockdr-kibana"

#: Kibana publishes a digest of the licence it is running under, and changes
#: it when the licence changes. This one is derived from the licence fixture
#: this mock serves, so it is stable for as long as that licence is.
_KBN_LICENCE_SIG = hashlib.sha256(b"mockdr-basic-licence").hexdigest()

#: Kibana's API answers are never cached, by anyone.
_KBN_CACHE = "private, no-cache, no-store, must-revalidate"


class ElasticHeadersMiddleware:
    """Name the product on the answers that name it."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Add each mount's own identifying headers to its responses."""
        path = scope.get("path", "") if scope["type"] == "http" else ""
        elastic = path.startswith(_ES_PREFIX)
        kibana = path.startswith(_KBN_PREFIX)
        if not (elastic or kibana):
            await self.app(scope, receive, send)
            return

        async def send_named(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                if elastic and message["status"] != 401:
                    headers["x-elastic-product"] = _PRODUCT
                elif kibana:
                    headers["kbn-name"] = _KBN_NAME
                    headers["kbn-license-sig"] = _KBN_LICENCE_SIG
                    headers["cache-control"] = _KBN_CACHE
            await send(message)

        await self.app(scope, receive, send_named)
