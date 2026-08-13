"""Sentinel test fixtures.

Azure Resource Manager requires ``?api-version=`` on every management-plane
request, and the Azure SDKs append it for you. These tests exercise the
endpoints, not that plumbing, so the client fixture appends it the same way —
leaving the enforcement itself to be tested explicitly in
``test_sentinel_api_version.py``.
"""
import pytest
from fastapi.testclient import TestClient

import main

DEFAULT_API_VERSION = "2024-03-01"

# Paths outside the ARM management plane, which take no api-version.
_NON_ARM = ("/sentinel/oauth2/", "/sentinel/v1/workspaces")


class _ArmTestClient(TestClient):
    """TestClient that appends ``api-version`` to ARM requests, as the SDK does."""

    def request(self, method: str, url: str, **kwargs: object):  # type: ignore[no-untyped-def, override]
        """Append the default api-version unless the caller set one."""
        target = str(url)
        params = kwargs.get("params")
        already_set = "api-version=" in target or (
            isinstance(params, dict) and "api-version" in params
        )
        if not target.startswith("/sentinel") or target.startswith(_NON_ARM) or already_set:
            return super().request(method, target, **kwargs)  # type: ignore[arg-type]

        # httpx replaces the URL query string when params is given, so the
        # version has to go wherever the caller put the rest of the query.
        if isinstance(params, dict):
            kwargs["params"] = {**params, "api-version": DEFAULT_API_VERSION}
        else:
            separator = "&" if "?" in target else "?"
            target = f"{target}{separator}api-version={DEFAULT_API_VERSION}"
        return super().request(method, target, **kwargs)  # type: ignore[arg-type]


@pytest.fixture()
def client(fresh_seed: None) -> TestClient:
    """Test client that behaves like an ARM SDK caller."""
    return _ArmTestClient(main.app)
