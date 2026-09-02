"""The ``Date`` every origin server owes its answers (RFC 9110 §6.6.1).

An origin server MUST send a ``Date`` header field on every response it
generates, in the IMF-fixdate form §5.6.7 fixes -- and mockdr sent none, on
any mount, because uvicorn 0.52.4 no longer adds one and nothing here did.
A client that caches, that computes an age, or that measures clock skew
against the server had nothing to read.

The one mount that stays silent is Elasticsearch's, and by measurement
rather than by choice: 8.15 answers `/_cluster/health` and `/_cat/indices`
without a `Date` at all, on 200 and on 401 alike. Kibana 8.15 and splunkd
10.4.2 both send one on every answer. Simulating Elasticsearch means
reproducing what it does, including where it departs from the RFC -- the
departure belongs in a conformance report, not in an answer no real client
would receive.
"""

from __future__ import annotations

from email.utils import formatdate

from starlette.types import ASGIApp, Message, Receive, Scope, Send

#: The mount whose product sends no `Date`. Measured on Elasticsearch 8.15.
_NO_DATE_PREFIX = "/elastic"

#: 1xx answers are interim and carry no `Date` of their own.
_INTERIM = 200


class DateHeaderMiddleware:
    """Stamp every response with the moment it was generated."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope.get("path", "").startswith(_NO_DATE_PREFIX):
            await self.app(scope, receive, send)
            return

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start" and message.get(
                "status", _INTERIM,
            ) >= _INTERIM:
                headers = message.setdefault("headers", [])
                if not any(name.lower() == b"date" for name, _ in headers):
                    # `usegmt` is what makes it IMF-fixdate: "GMT", never
                    # "-0000", which §5.6.7 does not admit.
                    headers.append(
                        (b"date", formatdate(usegmt=True).encode("latin-1")))
            await send(message)

        await self.app(scope, receive, send_wrapper)
