"""Compress the way each product compresses, and say so the way it says so.

All three runnable products compress when a client offers gzip, and mockdr
compressed nothing — a difference a client sees in every byte on the wire.
They do not agree about the details, and a single compressor for all of them
gets two of the three wrong:

* **Elasticsearch** compresses a 74-byte answer and publishes *no* `Vary` at
  all;
* **Kibana**, in the same distribution, leaves an 828-byte answer alone and
  compresses a 1546-byte one, and publishes `Vary: accept-encoding` when it
  does;
* **splunkd** leaves a 127-byte refusal alone and compresses a 659-byte
  answer, and adds `Accept-Encoding` to the `Vary` it already sends. Its
  event collector never compresses and never varies on the encoding.

The thresholds are the products' own defaults — 1 kB for Hapi, half that for
splunkd — and each is bracketed by a measurement on either side.

The six mounts with no runnable product are left uncompressed rather than
guessed at, which is also what they did before this existed.
"""

from __future__ import annotations

import gzip
from dataclasses import dataclass

from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send


@dataclass(frozen=True)
class Policy:
    """What one mount does when a client offers gzip."""

    #: The smallest body this product bothers to compress.
    threshold: int
    #: Whether it names the encoding among the things its answer varies on.
    vary: bool


#: Prefix -> policy, longest prefix first so HEC is decided before Splunk.
_POLICIES: tuple[tuple[str, Policy | None], ...] = (
    # The event collector never compresses, whatever is offered.
    ("/splunk/services/collector", None),
    ("/elastic", Policy(threshold=1, vary=False)),
    ("/kibana", Policy(threshold=1024, vary=True)),
    ("/splunk", Policy(threshold=512, vary=True)),
)

#: Answers that carry no body to compress.
_BODILESS = frozenset({204, 304})


def _policy(path: str) -> Policy | None:
    """The policy for this path, or None where nothing is compressed."""
    for prefix, policy in _POLICIES:
        if path.startswith(prefix):
            return policy
    return None


class CompressionMiddleware:
    """Compress a response the way its own product would."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Gzip an answer whose product compresses answers that size."""
        path = scope.get("path", "") if scope["type"] == "http" else ""
        policy = _policy(path) if path else None
        if policy is None or not _offers_gzip(scope):
            await self.app(scope, receive, send)
            return

        start: Message | None = None
        body = b""

        async def collect(message: Message) -> None:
            nonlocal start, body
            if message["type"] == "http.response.start":
                start = message
                return
            if message["type"] != "http.response.body":
                await send(message)
                return
            body += message.get("body", b"")
            if message.get("more_body"):
                return
            await _send(send, start, body, policy)

        await self.app(scope, receive, collect)


def _offers_gzip(scope: Scope) -> bool:
    """Whether the client said it takes gzip."""
    for name, value in scope.get("headers", []):
        if name == b"accept-encoding" and b"gzip" in bytes(value).lower():
            return True
    return False


async def _send(
    send: Send, start: Message | None, body: bytes, policy: Policy,
) -> None:
    """Send the answer, compressed if this product would compress it."""
    if start is None:
        return
    headers = MutableHeaders(scope=start)
    small = len(body) < policy.threshold
    already = "content-encoding" in headers
    if small or already or start["status"] in _BODILESS:
        await send(start)
        await send({"type": "http.response.body", "body": body})
        return

    packed = gzip.compress(body)
    headers["content-encoding"] = "gzip"
    headers["content-length"] = str(len(packed))
    if policy.vary:
        existing = headers.get("vary", "")
        names = [p.strip() for p in existing.split(",") if p.strip()]
        if not any(n.lower() == "accept-encoding" for n in names):
            names.append("Accept-Encoding")
        headers["vary"] = ", ".join(names)
    await send(start)
    await send({"type": "http.response.body", "body": packed})
