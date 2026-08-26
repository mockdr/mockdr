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
"""
from __future__ import annotations

import hashlib
import json
import time
from collections import deque
from dataclasses import dataclass

from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

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
        if "/_dev/" in path or path in _UNAUTHENTICATED_EXEMPT_PATHS:
            await self.app(scope, receive, send)
            return

        if not _config.enabled:
            await self.app(scope, receive, send)
            return

        # Determine rate-limit key from a hash of the full auth token
        token_hint = "anonymous"
        for header_name, header_value in scope.get("headers", []):
            if header_name.lower() == b"authorization":
                raw = header_value.decode("utf-8", errors="replace")
                token_hint = hashlib.sha256(raw.encode()).hexdigest()
                break

        # Unauthenticated requests are not rate-limited
        if token_hint == "anonymous":
            await self.app(scope, receive, send)
            return

        now = time.monotonic()
        window_start = now - 60.0

        # Evict stale buckets to prevent unbounded memory growth
        stale = [k for k, v in _counters.items() if not v or v[-1] < window_start]
        for k in stale:
            del _counters[k]

        bucket = _counters.setdefault(token_hint, deque())
        # Evict timestamps outside the sliding window
        while bucket and bucket[0] < window_start:
            bucket.popleft()

        if len(bucket) >= _config.requests_per_minute:
            # Return 429
            headers = [
                (b"content-type", b"application/json"),
                # Every mocked vendor tells a throttled client when to
                # return; without it a client can only guess or spin.
                (b"retry-after", str(_RETRY_AFTER_SECONDS).encode()),
            ]
            if scope.get("path", "").startswith(_CS_PREFIX):
                # Falcon's is a Unix epoch, and its SDK reads no other.
                headers += [
                    (b"x-ratelimit-remaining", b"0"),
                    (b"x-ratelimit-retryafter",
                     str(int(time.time()) + _RETRY_AFTER_SECONDS).encode()),
                ]
            await send({
                "type": "http.response.start",
                "status": 429,
                "headers": headers,
            })
            await send({
                "type": "http.response.body",
                "body": _rate_limited_body(scope),
            })
            return

        bucket.append(now)
        if not scope.get("path", "").startswith(_CS_PREFIX):
            await self.app(scope, receive, send)
            return

        remaining = str(max(0, _config.requests_per_minute - len(bucket))).encode()

        async def send_with_remaining(message: Message) -> None:
            if message["type"] == "http.response.start":
                MutableHeaders(scope=message)["x-ratelimit-remaining"] = remaining.decode()
            await send(message)

        await self.app(scope, receive, send_with_remaining)
