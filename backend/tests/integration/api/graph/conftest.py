"""Shared fixtures for Graph API integration tests."""
import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def graph_admin_token(client: TestClient) -> str:
    """Obtain a Graph API admin token (Plan 2 + E5)."""
    resp = client.post(
        "/graph/oauth2/v2.0/token",
        data={
            "client_id": "graph-mock-admin-client",
            "client_secret": "graph-mock-admin-secret",
            "grant_type": "client_credentials",
            "scope": "https://graph.microsoft.com/.default",
        },
    )
    assert resp.status_code == 200
    return resp.json()["access_token"]


@pytest.fixture()
def graph_admin_headers(graph_admin_token: str) -> dict[str, str]:
    """Authorization headers for Graph API admin requests."""
    return {"Authorization": f"Bearer {graph_admin_token}"}


@pytest.fixture()
def graph_p1_token(client: TestClient) -> str:
    """Obtain a Graph API Plan 1 token (limited features)."""
    resp = client.post(
        "/graph/oauth2/v2.0/token",
        data={
            "client_id": "graph-mock-p1-client",
            "client_secret": "graph-mock-p1-secret",
            "grant_type": "client_credentials",
        },
    )
    assert resp.status_code == 200
    return resp.json()["access_token"]


@pytest.fixture()
def graph_p1_headers(graph_p1_token: str) -> dict[str, str]:
    """Authorization headers for Graph API Plan 1 requests."""
    return {"Authorization": f"Bearer {graph_p1_token}"}
