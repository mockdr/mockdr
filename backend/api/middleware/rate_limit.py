"""ASGI middleware that simulates per-token rate limiting.

Falcon's own SDK reads two headers this had never sent. It takes
``X-Ratelimit-Remaining`` off *every* response and keeps it, so a client
paces itself before it is ever throttled; and on a 429 it reads
``X-RateLimit-RetryAfter``, which is a **Unix epoch** and not a number of
seconds — a client given only the standard `Retry-After` gets nothing it
looks for and falls back to its own backoff
(``CrowdStrike/gofalcon``, ``falcon/api_client.go``).

No other mocked vendor's SDK or connector reads a rate-limit header, so no
other mount sends one.

gofalcon declares three headers on every Falcon response — ``X-CS-TRACEID``,
``X-RateLimit-Limit`` and ``X-RateLimit-Remaining`` (each ``*_responses.go``
hydrates them) — and the mount sent only ``Remaining``, and only while the
dev limiter was switched on. Captured Falcon responses carry all three on
every answer: ``X-Ratelimit-Limit: 6000`` on an authenticated API call
(falconpy issue #1209, psfalcon issues #513, #519) and ``300`` where no
token is presented (the token and revoke routes, psfalcon #442; an
unauthorised call, falconpy #1455), with ``X-Cs-Traceid`` equal to the body's
``meta.trace_id`` (psfalcon #442). So the Falcon mount now always counts and
always says so; it only *refuses* when the dev limiter is on, at the rate
configured there.
"""
from __future__ import annotations

import hashlib
import json
import time
import uuid
from collections import deque
from dataclasses import dataclass

from starlette.types import ASGIApp, Receive, Scope, Send

from utils.asgi import stamping
from utils.cs_response import reset_trace_id, set_trace_id
from utils.dev_paths import is_dev_path
from utils.vendor_errors import build_vendor_error, vendor_for_path

#: Seconds a client is told to wait. The window is per-minute, so a full minute
#: is always long enough for the bucket to drain.
_RETRY_AFTER_SECONDS = 60

def _rate_limited_body(scope: Scope) -> bytes:
    """Build the throttling body in the envelope the target vendor uses.

    This middleware writes its response as raw ASGI messages, so it never
    reaches the exception handler that shapes everything else — which is how
    every vendor ended up returning SentinelOne's envelope when throttled.

    Args:
        scope: ASGI scope, read for the request path.

    Returns:
        Encoded JSON body for whichever vendor owns the path.
    """
    vendor = vendor_for_path(scope.get("path", ""))
    return json.dumps(build_vendor_error(vendor, 429, "Rate limit exceeded")).encode()


_UNAUTHENTICATED_EXEMPT_PATHS = {"/web/api/v2.1/system/status"}

#: The one mount whose client reads a rate-limit header.
_CS_PREFIX = "/cs"

#: Falcon's per-minute budget for an authenticated API client, as its
#: responses state it (``X-Ratelimit-Limit: 6000``, falconpy issue #1209).
_CS_API_LIMIT = 6000
#: ...and for a request that carries no token — the token route itself
#: (``X-Ratelimit-Limit=300`` on ``/oauth2/revoke``, psfalcon issue #442).
_CS_UNAUTHENTICATED_LIMIT = 300


@dataclass
class RateLimitConfig:
    """Configuration for the rate-limit middleware.

    Attributes:
        enabled: Whether rate limiting is currently active.
        requests_per_minute: Maximum requests per token per 60-second window.
    """

    enabled: bool = False
    requests_per_minute: int = 60


_config = RateLimitConfig()
_counters: dict[str, deque[float]] = {}


def get_config() -> RateLimitConfig:
    """Return the current rate-limit configuration.

    Returns:
        The active ``RateLimitConfig`` instance.
    """
    return _config


def set_config(enabled: bool, rpm: int) -> None:
    """Update the rate-limit configuration.

    Args:
        enabled: Whether to enable rate limiting.
        rpm: Requests-per-minute limit per token.
    """
    global _config
    _config = RateLimitConfig(enabled=enabled, requests_per_minute=rpm)


def reset_counters() -> None:
    """Clear all per-token request counters.

    Intended for use in tests to ensure isolation between test cases.
    """
    _counters.clear()


class RateLimitMiddleware:
    """ASGI middleware that enforces a sliding-window rate limit per token.

    - ``/_dev/`` paths are always exempt.
    - ``/web/api/v2.1/system/status`` (unauthenticated) is exempt.
    - When disabled, all requests pass through immediately.
    """

    def __init__(self, app: ASGIApp) -> None:
        """Wrap the given ASGI application.

        Args:
            app: The inner ASGI application.
        """
        self.app = app


    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Handle an ASGI request, enforcing the rate limit if enabled.

        Args:
            scope: ASGI connection scope dict.
            receive: ASGI receive callable.
            send: ASGI send callable.
        """
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path: str = scope.get("path", "")

        # Dev paths and status endpoint are always exempt
        if is_dev_path(path) or path in _UNAUTHENTICATED_EXEMPT_PATHS:
            await self.app(scope, receive, send)
            return

        token_hint = _token_hint(scope)
        if path.startswith(_CS_PREFIX):
            await self._falcon(scope, receive, send, token_hint)
            return

        # Unauthenticated requests are not rate-limited
        if not _config.enabled or token_hint is None:
            await self.app(scope, receive, send)
            return

        bucket = _bucket(token_hint)
        if len(bucket) >= _config.requests_per_minute:
            await _refuse(scope, send, [])
            return
        bucket.append(time.monotonic())
        await self.app(scope, receive, send)

    async def _falcon(
        self, scope: Scope, receive: Receive, send: Send, token_hint: str | None,
    ) -> None:
        """Count a Falcon request and state its budget and trace id on the answer.

        Every answer carries ``X-CS-TRACEID`` (the same id as the body's
        ``meta.trace_id``), ``X-RateLimit-Limit`` and
        ``X-RateLimit-Remaining``. The budget is the dev limiter's when it is
        on — and only then is a request over it refused — and Falcon's own
        otherwise.
        """
        path: str = scope.get("path", "")
        unauthenticated = token_hint is None or path.startswith(f"{_CS_PREFIX}/oauth2/")
        if _config.enabled:
            limit = _config.requests_per_minute
        else:
            limit = _CS_UNAUTHENTICATED_LIMIT if unauthenticated else _CS_API_LIMIT
        trace_id = str(uuid.uuid4())
        reset = set_trace_id(trace_id)
        try:
            bucket = _bucket("unauthenticated" if unauthenticated else str(token_hint))
            if _config.enabled and not unauthenticated and len(bucket) >= limit:
                await _refuse(scope, send, [
                    (b"x-cs-traceid", trace_id.encode()),
                    (b"x-ratelimit-limit", str(limit).encode()),
                    # Falcon's is a Unix epoch, and its SDK reads no other.
                    (b"x-ratelimit-remaining", b"0"),
                    (b"x-ratelimit-retryafter",
                     str(int(time.time()) + _RETRY_AFTER_SECONDS).encode()),
                ])
                return
            bucket.append(time.monotonic())
            remaining = str(max(0, limit - len(bucket)))

            await self.app(scope, receive, stamping(send, {
                "x-cs-traceid": trace_id,
                "x-ratelimit-limit": str(limit),
                "x-ratelimit-remaining": remaining,
            }))
        finally:
            reset_trace_id(reset)


def _token_hint(scope: Scope) -> str | None:
    """A hash of the request's ``Authorization`` header, or None without one."""
    for header_name, header_value in scope.get("headers", []):
        if header_name.lower() == b"authorization":
            raw = header_value.decode("utf-8", errors="replace")
            return hashlib.sha256(raw.encode()).hexdigest()
    return None


def _bucket(key: str) -> deque[float]:
    """The request times inside the last minute for *key*, stale ones dropped."""
    window_start = time.monotonic() - 60.0
    # Evict stale buckets to prevent unbounded memory growth
    stale = [k for k, v in _counters.items() if not v or v[-1] < window_start]
    for k in stale:
        del _counters[k]
    bucket = _counters.setdefault(key, deque())
    while bucket and bucket[0] < window_start:
        bucket.popleft()
    return bucket


async def _refuse(scope: Scope, send: Send, extra: list[tuple[bytes, bytes]]) -> None:
    """Answer 429 in the envelope of the vendor that owns the path."""
    headers = [
        (b"content-type", b"application/json"),
        # Every mocked vendor tells a throttled client when to return;
        # without it a client can only guess or spin.
        (b"retry-after", str(_RETRY_AFTER_SECONDS).encode()),
        *extra,
    ]
    await send({"type": "http.response.start", "status": 429, "headers": headers})
    await send({"type": "http.response.body", "body": _rate_limited_body(scope)})
