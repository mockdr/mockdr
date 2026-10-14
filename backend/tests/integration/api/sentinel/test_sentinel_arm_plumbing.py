"""What Azure Resource Manager does on every request, whatever the resource."""
from __future__ import annotations

from fastapi.testclient import TestClient

SENTINEL_PREFIX = "/sentinel"
_WS = (
    "/subscriptions/00000000-0000-0000-0000-000000000000"
    "/resourceGroups/mockdr-rg"
    "/providers/Microsoft.OperationalInsights/workspaces/mockdr-workspace"
    "/providers/Microsoft.SecurityInsights"
)


def _auth(client: TestClient) -> dict[str, str]:
    resp = client.post(
        f"{SENTINEL_PREFIX}/oauth2/v2.0/token",
        data={"client_id": "sentinel-mock-client-id",
              "client_secret": "sentinel-mock-client-secret",
              "grant_type": "client_credentials",
              "scope": "https://management.azure.com/.default"},
    )
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


class TestEveryAnswerCarriesItsRequestIds:
    """ARM stamps `x-ms-request-id` and `x-ms-correlation-request-id` on every answer.

    The Azure REST API guidelines: "DO create an opaque value that uniquely
    identifies the request and return this value in the `x-ms-request-id`
    response header"; ARM adds the correlation id, echoing the client's when
    it sent one. Azure support asks for both and the SDKs put them in their
    exceptions; the mock sent neither, on success or on error.
    """

    def test_on_success_and_on_error(self, client: TestClient) -> None:
        headers = _auth(client)
        ok = client.get(f"{SENTINEL_PREFIX}{_WS}/incidents", headers=headers)
        missing = client.get(f"{SENTINEL_PREFIX}{_WS}/incidents/no-such", headers=headers)
        refused = client.get(f"{SENTINEL_PREFIX}{_WS}/incidents")
        ids = set()
        for resp in (ok, missing, refused):
            assert resp.headers.get("x-ms-request-id"), resp.status_code
            assert resp.headers.get("x-ms-correlation-request-id"), resp.status_code
            ids.add(resp.headers["x-ms-request-id"])
        assert len(ids) == 3, "a request id must identify one request"

    def test_the_callers_correlation_id_is_echoed(self, client: TestClient) -> None:
        resp = client.get(
            f"{SENTINEL_PREFIX}{_WS}/incidents",
            headers={**_auth(client), "x-ms-correlation-request-id": "corr-1234"},
        )
        assert resp.headers["x-ms-correlation-request-id"] == "corr-1234"

    def test_not_on_the_token_endpoint(self, client: TestClient) -> None:
        """The token endpoint is Entra's, not ARM's."""
        resp = client.post(f"{SENTINEL_PREFIX}/oauth2/v2.0/token", data={})
        assert "x-ms-correlation-request-id" not in resp.headers
