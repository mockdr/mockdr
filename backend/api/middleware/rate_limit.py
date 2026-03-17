"""ASGI middleware that simulates per-token rate limiting."""
from __future__ import annotations

import hashlib
import json
import time
from collections import deque
from dataclasses import dataclass

from starlette.types import ASGIApp, Receive, Scope, Send

_RATE_LIMIT_RESPONSE = json.dumps({
    "errors": [{"code": 4290001, "detail": "Rate limit exceeded", "title": "Too Many Requests"}],
    "data": None,
}).encode()

_UNAUTHENTICATED_EXEMPT_PATHS = {"/web/api/v2.1/system/status"}


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
            await send({
                "type": "http.response.start",
                "status": 429,
                "headers": [(b"content-type", b"application/json")],
            })
            await send({
                "type": "http.response.body",
                "body": _RATE_LIMIT_RESPONSE,
            })
            return

        bucket.append(now)
        await self.app(scope, receive, send)
