"""Serve Splunk's ``/servicesNS/{owner}/{app}/`` namespace.

``splunklib.binding`` rewrites *every* path to the namespaced form as soon as
the client sets ``owner`` or ``app`` — which XSOAR's SplunkPy and most other
integrations do:

    if owner or app: path = f"/servicesNS/{owner}/{app}/{path}"

mockdr registered only ``/services/...`` outside the KV Store, so an SDK
configured with a namespace 404'd on every call while the same client without
one worked. Rather than duplicating every route, this middleware maps the
namespaced path onto its ``/services`` equivalent before routing.
"""
from __future__ import annotations

import re

from starlette.types import ASGIApp, Receive, Scope, Send

_NAMESPACED = re.compile(
    r"^(?P<prefix>/splunk)/servicesNS/(?P<owner>[^/]+)/(?P<app>[^/]+)(?P<rest>/.*)?$",
)

# The KV Store's routes are declared with the namespace in them already, so
# they must be left alone.
_NATIVE_NAMESPACE_PREFIXES = ("/storage/collections",)


class SplunkNamespaceMiddleware:
    """Rewrite ``/servicesNS/{owner}/{app}/x`` to ``/services/x``."""

    def __init__(self, app: ASGIApp) -> None:
        """Wrap *app*."""
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Rewrite the path when it addresses the namespaced form."""
        if scope["type"] == "http":
            rewritten = _rewrite(scope.get("path", ""))
            if rewritten is not None:
                scope = dict(scope)
                scope["path"] = rewritten
                raw = rewritten.encode()
                scope["raw_path"] = raw
        await self.app(scope, receive, send)


def _rewrite(path: str) -> str | None:
    """Return the ``/services`` equivalent of *path*, or None to leave it."""
    match = _NAMESPACED.match(path)
    if not match:
        return None
    rest = match.group("rest") or "/"
    if any(rest.startswith(p) for p in _NATIVE_NAMESPACE_PREFIXES):
        return None
    return f"{match.group('prefix')}/services{rest}"
