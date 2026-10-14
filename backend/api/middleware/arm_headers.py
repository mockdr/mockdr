"""The request-tracking headers Azure Resource Manager puts on every answer.

ARM stamps each response with `x-ms-request-id` — "an opaque value that
uniquely identifies the request", which the Azure REST API guidelines say a
service must return — and `x-ms-correlation-request-id`, the id that ties
together every call one operation makes, echoed when the client sent one.
Azure support asks for them, and the SDKs read them into their exceptions;
a client that logs them found nothing here, on success or on error.

It also tells the response builders which workspace the request addressed,
so a resource's `id` names the subscription, resource group and workspace
the path did (see `utils.sentinel.response.address_workspace`).

Pure ASGI, scoped to the Sentinel ARM routes: the token endpoint belongs to
Entra and the query API to Log Analytics, and neither is ARM.
"""

from __future__ import annotations

import uuid

from starlette.types import ASGIApp, Receive, Scope, Send

from utils.asgi import request_header, stamping
from utils.sentinel.response import address_workspace, release_workspace

#: The Sentinel mount's ARM paths: the workspace resources and the provider's
#: operation list.
_ARM_PREFIXES = ("/sentinel/subscriptions/", "/sentinel/providers/")


class ArmRequestHeadersMiddleware:
    """Stamp ARM's request and correlation ids on every ARM answer."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Add `x-ms-request-id` and `x-ms-correlation-request-id` to ARM responses."""
        path = scope.get("path", "") if scope["type"] == "http" else ""
        if not path.startswith(_ARM_PREFIXES):
            await self.app(scope, receive, send)
            return

        request_id = str(uuid.uuid4())
        correlation_id = (
            request_header(scope, b"x-ms-correlation-request-id") or str(uuid.uuid4())
        )
        stamped = stamping(send, {
            "x-ms-request-id": request_id, "x-ms-correlation-request-id": correlation_id,
        })

        # The ids this request's answers build name the workspace it addressed.
        token = address_workspace(path)
        try:
            await self.app(scope, receive, stamped)
        finally:
            release_workspace(token)
