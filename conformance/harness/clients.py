"""One HTTP client per (endpoint, target), shared across a whole run.

Opening a client per request meant a fresh TCP connect — and for Splunk's
HTTPS management port, a fresh TLS handshake — for every one of ~50 calls in
a run, against a server that may be booting under emulation. Pooling them
lets httpx keep the socket and reuse it.
"""
from __future__ import annotations

from types import TracebackType

import httpx

from harness.spec import Endpoint


class Clients:
    """A lazily-built pool, closed together at the end of the run."""

    def __init__(self, endpoints: dict[str, Endpoint]) -> None:
        """Remember the endpoints; no connection is opened until one is asked for."""
        self._endpoints = endpoints
        self._open: dict[tuple[str, str], httpx.Client] = {}

    def get(self, endpoint: str, target: str) -> httpx.Client:
        """The client for one endpoint on one target, built on first use."""
        key = (endpoint, target)
        if key not in self._open:
            spec = self._endpoints[endpoint]
            base = spec.mock if target == "mock" else spec.real
            self._open[key] = httpx.Client(
                base_url=base, verify=spec.verify_tls, timeout=30.0,
                follow_redirects=False,
            )
        return self._open[key]

    def __enter__(self) -> Clients:
        """Usable as a context manager so every client is closed on exit."""
        return self

    def __exit__(
        self, exc_type: type[BaseException] | None, exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        """Close every client that was opened."""
        for client in self._open.values():
            client.close()
