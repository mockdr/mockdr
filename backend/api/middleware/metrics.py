"""ASGI middleware that collects Prometheus-compatible request metrics.

No external dependencies — counters and histograms are plain dicts protected
by a threading lock (adequate for the single-process mock server).
"""
from __future__ import annotations

import re
import threading
import time
from collections.abc import MutableMapping
from typing import Any

from starlette.types import ASGIApp, Receive, Scope, Send

# ── Histogram bucket boundaries ──────────────────────────────────────────────
BUCKETS: tuple[float, ...] = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)

# ── UUID / numeric-ID normalisation ──────────────────────────────────────────
_UUID_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)
_NUMERIC_ID_RE = re.compile(r"(?<=/)\d{4,}(?=/|$)")

# ── Storage ──────────────────────────────────────────────────────────────────
_lock = threading.Lock()

# {(method, path, status_code): count}
_counters: dict[tuple[str, str, int], int] = {}

# {(method, path): {"bucket_counts": {le: count}, "sum": float, "count": int}}
_histograms: dict[tuple[str, str], dict[str, Any]] = {}


def _normalize_path(path: str) -> str:
    """Collapse UUIDs and long numeric IDs in *path* to ``{id}``."""
    path = _UUID_RE.sub("{id}", path)
    path = _NUMERIC_ID_RE.sub("{id}", path)
    return path


def _record(method: str, path: str, status_code: int, duration: float) -> None:
    """Thread-safe recording of a single request observation."""
    with _lock:
        # Counter
        key = (method, path, status_code)
        _counters[key] = _counters.get(key, 0) + 1

        # Histogram
        hkey = (method, path)
        hist = _histograms.get(hkey)
        if hist is None:
            hist = {
                "bucket_counts": {b: 0 for b in BUCKETS},
                "sum": 0.0,
                "count": 0,
            }
            _histograms[hkey] = hist
        hist["sum"] += duration
        hist["count"] += 1
        for b in BUCKETS:
            if duration <= b:
                hist["bucket_counts"][b] += 1
                break


def get_metrics_snapshot() -> tuple[
    dict[tuple[str, str, int], int],
    dict[tuple[str, str], dict[str, Any]],
]:
    """Return a consistent copy of (counters, histograms)."""
    with _lock:
        return dict(_counters), {k: {
            "bucket_counts": dict(v["bucket_counts"]),
            "sum": v["sum"],
            "count": v["count"],
        } for k, v in _histograms.items()}


def reset_metrics() -> None:
    """Clear all collected metrics (useful in tests)."""
    with _lock:
        _counters.clear()
        _histograms.clear()


class MetricsMiddleware:
    """ASGI middleware that tracks per-request counters and duration histograms.

    Paths starting with ``/_dev/`` or ``/metrics`` are excluded.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path: str = scope.get("path", "")

        if path == "/metrics" or "/_dev/" in path:
            await self.app(scope, receive, send)
            return

        method = scope.get("method", "GET")
        normalized = _normalize_path(path)
        status_code = 500  # default; overwritten by response start

        async def send_wrapper(message: MutableMapping[str, Any]) -> None:
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = message["status"]
            await send(message)

        start = time.perf_counter()
        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            duration = time.perf_counter() - start
            _record(method, normalized, status_code, duration)
