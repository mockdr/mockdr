"""The `request-id` and `client-request-id` every Microsoft Graph answer carries.

"Microsoft Graph will always return mandatory headers, such as the
request-id header in the response"
(https://learn.microsoft.com/en-us/graph/use-the-api), and its responses
carry `client-request-id` beside it -- equal to `request-id` in the documented
example (https://learn.microsoft.com/en-us/graph/auth-v2-service, "Use a
token") and to the caller's own GUID when one was sent, which is what Graph
asks callers to do: "generate a unique GUID, send it in the client-request-id
HTTP request header, and also log it"
(https://learn.microsoft.com/en-us/graph/best-practices-concept). The error
body repeats both in `innerError`.

The mock sent neither header, and `innerError` held two fresh random GUIDs,
so a client correlating its own `client-request-id` with a failure -- the one
thing the header is for -- found a value it never sent.

The ids are kept in a context variable for the request, which
:func:`utils.graph_response.build_graph_error_response` reads, so the body and
the headers agree. The Entra token and discovery routes under `/graph` are
not Graph and are left alone.
"""
from __future__ import annotations

import uuid

from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from utils.graph_response import graph_request_ids

_NOT_GRAPH = ("/oauth2/", "/.well-known/", "/discovery/")


def _is_graph_api(path: str) -> bool:
    return path.startswith("/graph/") and not any(part in path for part in _NOT_GRAPH)


class GraphRequestIdMiddleware:
    """Stamp Graph answers with `request-id` and `client-request-id`."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Set the ids for the request and add them to the response head."""
        if scope["type"] != "http" or not _is_graph_api(scope.get("path", "")):
            await self.app(scope, receive, send)
            return

        request_id = str(uuid.uuid4())
        sent = ""
        for name, value in scope.get("headers") or ():
            if name.lower() == b"client-request-id":
                sent = value.decode("latin-1").strip()
                break
        client_request_id = sent or request_id
        token = graph_request_ids.set((request_id, client_request_id))

        async def stamped(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                if "request-id" not in headers:
                    headers["request-id"] = request_id
                if "client-request-id" not in headers:
                    headers["client-request-id"] = client_request_id
            await send(message)

        try:
            await self.app(scope, receive, stamped)
        finally:
            graph_request_ids.reset(token)
