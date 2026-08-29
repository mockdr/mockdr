"""What each product does with a path that ends in a slash.

A client that builds its URL by joining a base and a path lands on one
constantly, and the three answer differently:

* **Elasticsearch** serves it — `/{index}/_search/` is the search, on every
  shape measured, including `/_cat/indices/` and `/{index}/_doc/{id}/`;
* **splunkd** serves it too, on `/services` and `/servicesNS` alike;
* **Kibana** does not: Hapi answers `302` and points at the path with its
  slashes percent-encoded — `/api/cases/_find/` becomes
  `location: /api%2Fcases%2F_find` — which then answers 404 when followed.
  Odd, and imitated because a client that logs its redirects sees it.

mockdr answered 404 to all three, so a trailing slash worked against two
products and failed against their mock.  Measured on 8.15 and 10.4.2.
"""
from __future__ import annotations

from urllib.parse import quote

from starlette.responses import RedirectResponse
from starlette.types import ASGIApp, Receive, Scope, Send

#: The mounts that serve a trailing slash rather than refusing it.
_TOLERANT = ("/elastic/", "/splunk/")

#: The mount that redirects instead.
_KIBANA = "/kibana/"


class TrailingSlashMiddleware:
    """Serve, redirect or leave alone, as each product does."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        path = scope.get("path", "") if scope["type"] == "http" else ""
        if not path.endswith("/") or path.count("/") < 2:
            await self.app(scope, receive, send)
            return

        if path.startswith(_TOLERANT):
            # The mount root itself — `/elastic/` is Elasticsearch's `/` —
            # keeps its slash; anything below it loses one.
            trimmed = path[:-1]
            if trimmed and trimmed.count("/") >= 2:
                scope = {**scope, "path": trimmed, "raw_path": trimmed.encode()}
            await self.app(scope, receive, send)
            return

        if path.startswith(_KIBANA):
            inner = path[len("/kibana"):].rstrip("/")
            if inner:
                target = "/" + quote(inner.lstrip("/"), safe="")
                await RedirectResponse(target, status_code=302)(scope, receive, send)
                return

        await self.app(scope, receive, send)
