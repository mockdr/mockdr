"""Integration tests for the Swagger spec / docs endpoints."""

from fastapi.testclient import TestClient

BASE = "/web/api/v2.1"


def test_swagger_ui_returns_html(client: TestClient) -> None:
    """GET /doc returns 200 with HTML containing swagger references."""
    resp = client.get(f"{BASE}/doc")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    body = resp.text.lower()
    assert "swagger" in body


def test_spec_json_returns_valid_spec(client: TestClient) -> None:
    """GET /doc/spec.json returns 200 with JSON containing 'paths'."""
    resp = client.get(f"{BASE}/doc/spec.json")
    assert resp.status_code == 200
    data = resp.json()
    assert "paths" in data


def test_default_docs_disabled(client: TestClient) -> None:
    """FastAPI default /docs should be disabled (no Swagger UI at /docs)."""
    resp = client.get("/docs")
    # If SPA fallback is active it returns 200 with the Vue app HTML,
    # otherwise it returns 404.  Either way, it must NOT be FastAPI's
    # auto-generated Swagger UI page.
    if resp.status_code == 200:
        assert "swagger-ui" not in resp.text.lower()
    else:
        assert resp.status_code == 404


def test_default_openapi_json_disabled(client: TestClient) -> None:
    """FastAPI default /openapi.json should be disabled."""
    resp = client.get("/openapi.json")
    # Should not return a valid OpenAPI spec at the default path.
    if resp.status_code == 200:
        # SPA fallback returns HTML, not JSON
        assert "text/html" in resp.headers.get("content-type", "")
    else:
        assert resp.status_code == 404
