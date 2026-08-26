"""The headers splunkd puts on its answers, and the caching it publishes.

Measured on 10.4.2, and none of it was here:

* every answer names the server — `Server: Splunkd`, where mockdr said
  `uvicorn`, which is the plainest way there is to tell the two apart. The
  header uvicorn adds is added *after* the app has answered and cannot be
  removed from inside it, so every way this repo starts the mock passes
  `--no-server-header`; started any other way, both names appear.
* every management answer carries `Vary: Cookie, Authorization`, because
  what it returns depends on who asked; HEC varies on `Authorization` alone;
* almost every management answer is explicitly *not* cacheable —
  `no-store, no-cache, must-revalidate, max-age=0` with splunkd's own
  already-expired `Expires` of October 1978 — while the `data/indexes`
  family, and only that family, is served `must-revalidate, private,
  max-age=1800` with a weak `ETag`;
* and that family answers a matching `If-None-Match` with `304 Not
  Modified`, which is the point of publishing a validator at all. mockdr
  answered 200 with the whole collection, so a client revalidating a cached
  read was handed a fresh copy every time and never learnt it was current.

A refusal is its own case: a 401 carries `Cache-Control: private` and no
`Expires` at all.

The ETag names the user it was minted for — splunkd's is
`W/"<base64 user>-<digest>"` — which is why the answer varies on
`Authorization`. mockdr reads that user from a Basic header when the request
carries one; a client cannot see through the validator either way, and what
it can see is that the same body yields the same ETag and a changed body
yields a different one.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import time
from email.utils import formatdate

from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

_SPLUNK_PREFIX = "/splunk"
_HEC_PREFIX = "/splunk/services/collector"

#: The login form is its own case: it names nothing in `Vary`, because it
#: reads neither a cookie nor an Authorization header — the credentials are
#: in the form.
_LOGIN = "/splunk/services/auth/login"

#: The one family splunkd serves as cacheable — `indexes` and the entities
#: under it, and *not* `indexes-extended`, which is a different endpoint and
#: is served like everything else.
_CACHEABLE = "/splunk/services/data/indexes"

#: Half an hour, which is what splunkd publishes for that family.
_MAX_AGE = 1800

#: splunkd's "already expired" sentinel, to the second.
_LONG_EXPIRED = "Thu, 26 Oct 1978 00:00:00 GMT"

_CACHEABLE_CONTROL = f"must-revalidate, private, max-age={_MAX_AGE}"
_UNCACHEABLE_CONTROL = "no-store, no-cache, must-revalidate, max-age=0"


def _user(scope: Scope) -> str:
    """The user an ETag is minted for, from a Basic header if there is one."""
    for name, value in scope.get("headers", []):
        if name == b"authorization" and value.lower().startswith(b"basic "):
            try:
                decoded = base64.b64decode(value[6:]).decode("utf-8", "replace")
            except (binascii.Error, ValueError):
                return "admin"
            return decoded.split(":", 1)[0] or "admin"
    return "admin"


def _etag(user: str, body: bytes) -> str:
    """Splunkd's weak validator: who asked, and what they were given."""
    digest = hashlib.sha256(body).hexdigest().upper()
    return f'W/"{base64.b64encode(user.encode()).decode()}-{digest}"'


class SplunkHeadersMiddleware:
    """Answer as splunkd answers: named, varying, and honest about caching."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Add splunkd's headers, and answer a fresh conditional read 304."""
        path = scope.get("path", "") if scope["type"] == "http" else ""
        if not path.startswith(_SPLUNK_PREFIX):
            await self.app(scope, receive, send)
            return

        in_family = path == _CACHEABLE or path.startswith(f"{_CACHEABLE}/")
        hec = path.startswith(_HEC_PREFIX)
        login = path.startswith(_LOGIN)
        vary = _vary(scope, hec=hec)
        if_none_match = _header(scope, b"if-none-match")
        start: Message | None = None
        body = b""
        cacheable = False

        async def collect(message: Message) -> None:
            nonlocal start, body, cacheable
            if message["type"] == "http.response.start":
                start = message
                # Only a successful read is served as cacheable: a 404 for an
                # index that is not there, or a 400 for a create with no
                # name, is served like everything else and carries no
                # validator.
                cacheable = in_family and message["status"] == 200
                if not cacheable:
                    _stamp(message, vary, cacheable=False, hec=hec, login=login)
                    await send(message)
                return
            if message["type"] != "http.response.body":
                await send(message)
                return
            if not cacheable:
                await send(message)
                return
            body += message.get("body", b"")
            if message.get("more_body"):
                return
            await _send_cacheable(
                send, start, body, _user(scope), if_none_match, vary,
            )

        await self.app(scope, receive, collect)


def _vary(scope: Scope, *, hec: bool) -> str:
    """What splunkd says its answer depends on, for this request.

    Measured on 10.4.2: the management port varies on `Cookie, Authorization`
    whatever was sent — no credentials, a good password, a bad one, a cookie
    — *except* for an unrecognised session token, which is refused before the
    cookie handler is reached and varies on `Authorization` alone. The event
    collector names `Authorization` for a POST that did not put its token in
    the query string, and nothing at all otherwise: a token read from the
    query, or a method refused outright, never reaches the header.
    """
    path = str(scope.get("path", ""))
    if path.startswith(_LOGIN):
        return ""
    if hec:
        # The token in a query string is read before the header is looked
        # for, and a wrong method is refused before either.
        by_query = b"token=" in bytes(scope.get("query_string", b""))
        if by_query or scope.get("method") != "POST":
            return ""
        return "Authorization"
    if _header(scope, b"authorization").lower().startswith("splunk "):
        return "Authorization"
    return "Cookie, Authorization"


def _header(scope: Scope, wanted: bytes) -> str:
    """One request header, or the empty string."""
    for name, value in scope.get("headers", []):
        if name == wanted:
            return str(bytes(value).decode("latin-1"))
    return ""


def _stamp(
    message: Message, vary: str, *, cacheable: bool, hec: bool = False,
    login: bool = False,
) -> None:
    """Put splunkd's identity and caching rules on a response."""
    headers = MutableHeaders(scope=message)
    headers["server"] = "Splunkd"
    if vary:
        headers["vary"] = vary
    if "cache-control" in headers:
        # Whatever refused the request first has already said how its answer
        # may be kept — splunkd's own `private` on a mode it could not read.
        return
    if hec:
        # HEC publishes no caching rules at all, only what it varies on.
        return
    if message["status"] == 401 and not login:
        # A refusal from the auth layer publishes no expiry at all, only that
        # it is not shared. The login form is a handler, and answers a wrong
        # password the way every other handler answers.
        headers["cache-control"] = "private"
        return
    if cacheable:
        headers["cache-control"] = _CACHEABLE_CONTROL
        # The same half hour the `max-age` publishes, as a date.
        headers["expires"] = formatdate(time.time() + _MAX_AGE, usegmt=True)
    else:
        headers["cache-control"] = _UNCACHEABLE_CONTROL
        headers["expires"] = _LONG_EXPIRED


async def _send_cacheable(
    send: Send,
    start: Message | None,
    body: bytes,
    user: str,
    if_none_match: str,
    vary: str,
) -> None:
    """Send a cacheable answer, or the 304 that says it has not changed."""
    if start is None:
        return
    etag = _etag(user, body)
    _stamp(start, vary, cacheable=True)
    headers = MutableHeaders(scope=start)
    headers["etag"] = etag

    if if_none_match.strip() == etag and start["status"] == 200:
        start["status"] = 304
        # A 304 carries the validator and the caching rules, and no body.
        for name in ("content-length", "content-type"):
            del headers[name]
        await send(start)
        await send({"type": "http.response.body", "body": b""})
        return

    headers["content-length"] = str(len(body))
    await send(start)
    await send({"type": "http.response.body", "body": body})
