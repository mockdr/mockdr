"""Graph answers carry `request-id` and `client-request-id`, and errors repeat them.

"Microsoft Graph will always return mandatory headers, such as the
request-id header in the response" (https://learn.microsoft.com/en-us/graph/use-the-api);
the documented response carries `client-request-id` beside it, equal to
`request-id` when the caller sent none
(https://learn.microsoft.com/en-us/graph/auth-v2-service), and Graph asks
callers to send their own GUID in `client-request-id` and log it
(https://learn.microsoft.com/en-us/graph/best-practices-concept). The error
body's `innerError` names both.

The mock sent neither header and filled `innerError` with two fresh random
GUIDs, so the id a caller logged for a failed request never appeared in it.
"""
from __future__ import annotations

from fastapi.testclient import TestClient


class TestGraphRequestIds:
    """Headers on every Graph answer, and the error body agreeing with them."""

    def test_a_success_carries_both_headers(
        self, client: TestClient, graph_admin_headers: dict[str, str],
    ) -> None:
        response = client.get("/graph/v1.0/users", headers=graph_admin_headers,
                              params={"$top": 1})
        assert response.status_code == 200
        assert response.headers["request-id"]
        assert response.headers["client-request-id"] == response.headers["request-id"]

    def test_the_callers_client_request_id_is_echoed(
        self, client: TestClient, graph_admin_headers: dict[str, str],
    ) -> None:
        mine = "0b8a3f5e-3c1d-4a8e-9f2b-6d7c8e9f0a1b"
        response = client.get("/graph/v1.0/users/no-such-user",
                              headers={**graph_admin_headers, "client-request-id": mine})
        assert response.status_code == 404
        assert response.headers["client-request-id"] == mine
        inner = response.json()["error"]["innerError"]
        assert inner["client-request-id"] == mine
        assert inner["request-id"] == response.headers["request-id"]

    def test_a_401_carries_them_too(self, client: TestClient) -> None:
        response = client.get("/graph/v1.0/users")
        assert response.status_code == 401
        assert response.json()["error"]["innerError"]["request-id"] == \
            response.headers["request-id"]

    def test_the_token_endpoint_is_not_graph(self, client: TestClient) -> None:
        response = client.post("/graph/oauth2/v2.0/token", data={
            "client_id": "graph-mock-admin-client",
            "client_secret": "graph-mock-admin-secret",
            "grant_type": "client_credentials",
            "scope": "https://graph.microsoft.com/.default",
        })
        assert "request-id" not in response.headers
