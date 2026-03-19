"""Public testing utilities for mockdr.

Provides a typed HTTP client and a pytest session fixture that starts a live
mockdr server in a background thread.  Intended for use in **external** test
suites that need to exercise code that calls mockdr-compatible endpoints.

Usage::

    # conftest.py
    from mockdr.testing import mockdr_server, MockdrClient

    @pytest.fixture(scope="session")
    def server(mockdr_server: MockdrClient) -> MockdrClient:
        return mockdr_server

    # test_my_integration.py
    def test_agent_list(server: MockdrClient) -> None:
        agents = server.get("/agents")
        assert agents["pagination"]["totalItems"] > 0

    def test_mass_infection(server: MockdrClient) -> None:
        server.scenario("mass_infection")
        agents = server.get("/agents", params={"infected": True})
        assert len(agents["data"]) > 0
        server.reset()  # restore clean state
"""
from __future__ import annotations

import socket
import threading
import time
from collections.abc import Generator
from typing import Any

import httpx
import pytest
import uvicorn


def _find_free_port() -> int:
    """Return an available TCP port on localhost.

    Binds an ephemeral socket to port 0 so the OS assigns a free port,
    reads that port, and immediately releases the socket.  The port is not
    reserved after this function returns; callers must use it promptly.

    Returns:
        A free TCP port number in the range 1–65535.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


class MockdrClient:
    """HTTP client wrapper for a running mockdr instance.

    Provides typed convenience methods for API calls, scenario triggers, and
    state management.  Authentication headers are baked in at construction
    time so individual call sites stay free of auth boilerplate.

    Args:
        base_url: Root URL of the SentinelOne-compatible API surface,
            e.g. ``http://localhost:5001/web/api/v2.1``.
        token: SentinelOne API token used for every request.
        _transport: Optional httpx transport override.  Pass a
            ``httpx.MockTransport`` (or any ``httpx.BaseTransport``) to
            intercept HTTP traffic in unit tests without a real server.
            Production callers should omit this parameter.
    """

    def __init__(
        self,
        base_url: str,
        token: str = "admin-token-0000-0000-000000000001",
        _transport: httpx.BaseTransport | None = None,
    ) -> None:
        """Initialise the client with a base URL, API token, and optional transport."""
        self.base_url = base_url
        self.token = token
        self._client = httpx.Client(
            base_url=base_url,
            headers={"Authorization": f"ApiToken {token}"},
            timeout=10.0,
            transport=_transport,
        )

    def get(self, path: str, **kwargs: Any) -> dict[str, Any]:
        """Send a GET request and return the parsed JSON body.

        Args:
            path: API path relative to *base_url* (e.g. ``/agents``).
            **kwargs: Extra keyword arguments forwarded to
                ``httpx.Client.get()``.

        Returns:
            Parsed JSON response as a plain ``dict``.

        Raises:
            httpx.HTTPStatusError: When the server returns a 4xx or 5xx
                status code.
        """
        resp = self._client.get(path, **kwargs)
        resp.raise_for_status()
        return resp.json()  # type: ignore[no-any-return]

    def post(self, path: str, **kwargs: Any) -> dict[str, Any]:
        """Send a POST request and return the parsed JSON body.

        Args:
            path: API path relative to *base_url*.
            **kwargs: Extra keyword arguments forwarded to
                ``httpx.Client.post()``.

        Returns:
            Parsed JSON response as a plain ``dict``.

        Raises:
            httpx.HTTPStatusError: When the server returns a 4xx or 5xx
                status code.
        """
        resp = self._client.post(path, **kwargs)
        resp.raise_for_status()
        return resp.json()  # type: ignore[no-any-return]

    def put(self, path: str, **kwargs: Any) -> dict[str, Any]:
        """Send a PUT request and return the parsed JSON body.

        Args:
            path: API path relative to *base_url*.
            **kwargs: Extra keyword arguments forwarded to
                ``httpx.Client.put()``.

        Returns:
            Parsed JSON response as a plain ``dict``.

        Raises:
            httpx.HTTPStatusError: When the server returns a 4xx or 5xx
                status code.
        """
        resp = self._client.put(path, **kwargs)
        resp.raise_for_status()
        return resp.json()  # type: ignore[no-any-return]

    def delete(self, path: str, **kwargs: Any) -> dict[str, Any]:
        """Send a DELETE request and return the parsed JSON body.

        Args:
            path: API path relative to *base_url*.
            **kwargs: Extra keyword arguments forwarded to
                ``httpx.Client.delete()``.

        Returns:
            Parsed JSON response as a plain ``dict``.

        Raises:
            httpx.HTTPStatusError: When the server returns a 4xx or 5xx
                status code.
        """
        resp = self._client.delete(path, **kwargs)
        resp.raise_for_status()
        return resp.json()  # type: ignore[no-any-return]

    def scenario(self, name: str) -> dict[str, Any]:
        """Trigger a named DEV scenario.

        Args:
            name: Scenario key.  One of: ``mass_infection``,
                ``agent_offline``, ``quiet_day``, ``apt_campaign``.

        Returns:
            Scenario result dict from the ``/_dev/scenario`` endpoint.

        Raises:
            httpx.HTTPStatusError: When the server returns a 4xx or 5xx
                status code.
        """
        return self.post("/_dev/scenario", json={"scenario": name})

    def reset(self) -> dict[str, Any]:
        """Reset all data to the initial deterministic seed state.

        Returns:
            Reset confirmation dict from the ``/_dev/reset`` endpoint.

        Raises:
            httpx.HTTPStatusError: When the server returns a 4xx or 5xx
                status code.
        """
        return self.post("/_dev/reset")

    def export_state(self) -> dict[str, Any]:
        """Export a full snapshot of the in-memory store.

        Returns:
            Complete store state as a dict (as returned by ``/_dev/export``).

        Raises:
            httpx.HTTPStatusError: When the server returns a 4xx or 5xx
                status code.
        """
        return self.get("/_dev/export")

    def import_state(self, snapshot: dict[str, Any]) -> dict[str, Any]:
        """Replace all in-memory data with *snapshot*.

        Args:
            snapshot: State dict as returned by :meth:`export_state`.

        Returns:
            Import result with record count from ``/_dev/import``.

        Raises:
            httpx.HTTPStatusError: When the server returns a 4xx or 5xx
                status code.
        """
        return self.post("/_dev/import", json=snapshot)

    def close(self) -> None:
        """Close the underlying httpx client and release its connections."""
        self._client.close()


class _UvicornServer:
    """Runs a uvicorn ASGI server in a daemon background thread.

    Not part of the public API.  Use the :func:`mockdr_server` pytest
    fixture instead.
    """

    def __init__(self, host: str, port: int) -> None:
        config = uvicorn.Config(
            "main:app",
            host=host,
            port=port,
            log_level="warning",
        )
        self.server = uvicorn.Server(config)
        self._thread = threading.Thread(target=self.server.run, daemon=True)

    def start(self) -> None:
        """Start the server in a background daemon thread."""
        self._thread.start()

    def stop(self) -> None:
        """Signal the server to shut down and wait for the thread to exit."""
        self.server.should_exit = True
        self._thread.join(timeout=5)


@pytest.fixture(scope="session")
def mockdr_server() -> Generator[MockdrClient, None, None]:
    """Pytest session fixture that starts a live mockdr server and yields a client.

    The server runs on a random free port in a background daemon thread and is
    shut down automatically after the test session completes.  The fixture is
    ``scope="session"`` so the server starts once and is reused across all
    tests that depend on it.

    Yields:
        :class:`MockdrClient` configured to talk to the running server.

    Raises:
        RuntimeError: If the server does not become healthy within 30 seconds.

    Example::

        @pytest.fixture(scope="session")
        def s1(mockdr_server: MockdrClient) -> MockdrClient:
            return mockdr_server

        def test_agents(s1: MockdrClient) -> None:
            data = s1.get("/agents")
            assert data["pagination"]["totalItems"] == 60
    """
    import os
    import sys

    # Ensure the backend directory is on sys.path so uvicorn can resolve
    # "main:app" without an installed package.
    backend_dir = os.path.join(os.path.dirname(__file__), "..")
    backend_dir_abs = os.path.abspath(backend_dir)
    if backend_dir_abs not in sys.path:
        sys.path.insert(0, backend_dir_abs)

    port = _find_free_port()
    server = _UvicornServer("127.0.0.1", port)
    server.start()

    deadline = 60  # half-second ticks × 60 = 30 s
    for _ in range(deadline):
        try:
            resp = httpx.get(
                f"http://127.0.0.1:{port}/web/api/v2.1/system/status",
                timeout=1.0,
            )
            if resp.status_code == 200:
                break
        except httpx.ConnectError:
            pass
        time.sleep(0.5)
    else:
        server.stop()
        raise RuntimeError("mockdr server failed to become healthy within 30 seconds")

    client = MockdrClient(f"http://127.0.0.1:{port}/web/api/v2.1")
    yield client
    client.close()
    server.stop()
