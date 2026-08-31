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

They disagree about *what is offered*, too, and the header was read as a
substring search for "gzip" — which got three of the four cases below
wrong.  Measured on 8.15 and 10.4.2, one header at a time, against
`/_cluster/health`, `/api/status` and `/services/server/info`:

    header            Elasticsearch   splunkd   Kibana
    gzip              gzip            gzip      gzip
    gzip;q=0          --              --        --
    GZIP              --              gzip      gzip
    deflate           deflate         --        deflate
    *                 deflate         --        --

All three refuse `q=0`, which is the one a client cannot recover from:
`Accept-Encoding: gzip;q=0` says *do not send me gzip*, and mockdr sent it
gzip. The rest is per-product, and the policy says which.
"""

from __future__ import annotations

import gzip
import re
import zlib
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
    #: Whether it reads the encoding name case-insensitively.  splunkd and
    #: Kibana answer `GZIP` with gzip; Elasticsearch answers it with nothing.
    folds_case: bool = False
    #: Whether it also speaks deflate.
    deflate: bool = False
    #: What a bare `*` selects here, if anything — Elasticsearch picks
    #: deflate for it, and the other two pick nothing at all.
    star: str | None = None


#: Prefix -> policy, longest prefix first so HEC is decided before Splunk.
_POLICIES: tuple[tuple[str, Policy | None], ...] = (
    # The event collector never compresses, whatever is offered.
    ("/splunk/services/collector", None),
    ("/elastic", Policy(threshold=1, vary=False, deflate=True, star="deflate")),
    ("/kibana", Policy(threshold=1024, vary=True, folds_case=True, deflate=True)),
    ("/splunk", Policy(threshold=512, vary=True, folds_case=True)),
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
        encoding = _chosen_encoding(scope, policy) if policy else None
        if policy is None or encoding is None:
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
            await _send(send, start, body, policy, encoding)

        await self.app(scope, receive, collect)


#: One `Accept-Encoding` member: a name, then any parameters.  The `q` is
#: read with its own spacing allowed — splunkd honours `gzip ; q=0`.
_MEMBER = re.compile(r"^([^;]+?)\s*(?:;\s*q\s*=\s*([\d.]+))?$", re.IGNORECASE)


def _chosen_encoding(scope: Scope, policy: Policy) -> str | None:
    """The encoding this product would pick, or None to send it plain.

    Read as a substring search for "gzip", the header answered `q=0` with
    gzip — telling a client that said it cannot take gzip that the body is
    gzip.  Nothing downstream recovers from that.
    """
    raw = ""
    for name, value in scope.get("headers", []):
        if name == b"accept-encoding":
            raw = bytes(value).decode("latin-1")
            break
    if not raw:
        return None

    offered: dict[str, float] = {}
    for part in raw.split(","):
        member = _MEMBER.match(part.strip())
        if not member:
            continue
        token = member.group(1).strip()
        if policy.folds_case:
            token = token.lower()
        try:
            weight = float(member.group(2)) if member.group(2) else 1.0
        except ValueError:
            continue
        offered[token] = weight

    # A weight of zero is a refusal of that name, not an offer of it.
    if offered.get("gzip", 0.0) > 0:
        return "gzip"
    if policy.deflate and offered.get("deflate", 0.0) > 0:
        return "deflate"
    if policy.star and offered.get("*", 0.0) > 0:
        return policy.star
    return None


async def _send(
    send: Send, start: Message | None, body: bytes, policy: Policy,
    encoding: str,
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

    packed = zlib.compress(body) if encoding == "deflate" else gzip.compress(body)
    headers["content-encoding"] = encoding
    headers["content-length"] = str(len(packed))
    if policy.vary:
        existing = headers.get("vary", "")
        names = [p.strip() for p in existing.split(",") if p.strip()]
        if not any(n.lower() == "accept-encoding" for n in names):
            names.append("Accept-Encoding")
        headers["vary"] = ", ".join(names)
    await send(start)
    await send({"type": "http.response.body", "body": packed})
