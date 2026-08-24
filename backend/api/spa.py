"""Telling a browser navigation apart from an API call.

The UI routes under the same top-level prefixes as the APIs it mocks —
``/graph/users`` is a page, ``/graph/v1.0/users`` is an endpoint — so the path
alone cannot say which of the two a request wanted. Every place that has to
choose asks here, so the answer cannot drift between them.
"""
from __future__ import annotations

from pathlib import Path

from fastapi import Request
from fastapi.responses import FileResponse

#: Where the built frontend lives, when it is built at all.
DIST = Path(__file__).parent.parent.parent / "frontend" / "dist"
SPA_AVAILABLE = DIST.exists()

#: Only a safe method can be a navigation: a POST carrying a browser's Accept
#: header is still an API call and still wants the vendor's answer.
SAFE_METHODS = ("GET", "HEAD")


def wants_html(request: Request) -> bool:
    """Whether this looks like a browser navigation rather than an API call.

    Browsers name ``text/html`` explicitly when navigating; API clients send
    ``application/json`` or ``*/*``.
    """
    return (
        request.method in SAFE_METHODS
        and "text/html" in request.headers.get("accept", "")
    )


def spa_response(request: Request) -> FileResponse | None:
    """The SPA's entry point when this is a navigation, else ``None``.

    A route that shares its path with a UI route calls this first: without it,
    opening the page in a browser would answer with the vendor's JSON — or
    with the 401 the API route demands.
    """
    if SPA_AVAILABLE and wants_html(request):
        return FileResponse(DIST / "index.html")
    return None
