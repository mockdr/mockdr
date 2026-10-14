"""Read a Splunk request body that names no content type as a form.

splunklib -- Splunk's own Python SDK, and the binding XSOAR's SplunkPy is
built on -- sends almost every POST as ``key=value&...`` with **no**
``Content-Type`` header at all. ``HttpLib.post`` adds
``application/x-www-form-urlencoded`` only when the caller passes an explicit
``body=``; every other call (``login``, ``jobs.create``, ``Entity.update``,
``saved_searches.create`` ...) encodes its keyword arguments into the body and
leaves the header out (``splunklib/binding.py``, ``HttpLib.post``). splunkd
reads such a body as form data -- the SDK could not log in otherwise.

mockdr's routes parse forms through Starlette, which reads a body as a form
only when the header says so. The SDK's very first request, ``POST
/services/auth/login``, therefore arrived with no username and no password and
was refused ``400 Login failed``: ``splunklib.client.connect()`` could not
reach the mock at all, and neither could anything built on it.

This middleware supplies the header splunkd assumes. It touches only a
request that carries a body and names no type; HEC is left alone (it reads
its body raw, as JSON or text, whatever the header says), and so is the KV
Store's data API, whose bodies are JSON -- splunklib sends that one header
explicitly.
"""
from __future__ import annotations

import re

from starlette.types import ASGIApp, Receive, Scope, Send

_FORM = b"application/x-www-form-urlencoded"

_SPLUNK = "/splunk/"

#: Paths whose bodies are not forms whatever the header says.
_NOT_FORMS = re.compile(r"^/splunk/services/collector|/storage/collections/data(?:/|$)")

_BODY_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


class SplunkFormBodyMiddleware:
    """Give a type-less Splunk management body the form type splunkd reads it as."""

    def __init__(self, app: ASGIApp) -> None:
        """Wrap *app*."""
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Add ``Content-Type: application/x-www-form-urlencoded`` where none was sent."""
        if scope["type"] == "http" and _applies(scope):
            scope = dict(scope)
            scope["headers"] = [*scope.get("headers", []), (b"content-type", _FORM)]
        await self.app(scope, receive, send)


def _applies(scope: Scope) -> bool:
    path = scope.get("path", "")
    if not path.startswith(_SPLUNK) or scope.get("method") not in _BODY_METHODS:
        return False
    if _NOT_FORMS.search(path):
        return False
    has_body = False
    for name, value in scope.get("headers", []):
        lowered = name.lower()
        if lowered == b"content-type":
            return False
        if lowered == b"transfer-encoding" or (lowered == b"content-length" and value != b"0"):
            has_body = True
    return has_body
