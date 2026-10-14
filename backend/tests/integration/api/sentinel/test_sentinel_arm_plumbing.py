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


class TestAnIdNamesTheWorkspaceTheRequestAddressed:
    """A resource's `id` is under the subscription, group and workspace of the path.

    ARM answers `id` as the resource's full path — the reference examples
    answer `/subscriptions/d0cfe6b2-…/resourceGroups/myRg/…/workspaces/
    myWorkspace/…` to a request for exactly that. The mock answered every id
    under its own default workspace whatever the path said, so a client
    following an `id` back went somewhere it had never been. ADR-012 keeps
    serving the one workspace under any name; the id now echoes the name.
    """

    OTHER = (
        "/subscriptions/d0cfe6b2-9ac0-4464-9919-dccaee2e48c0/resourceGroups/myRg"
        "/providers/Microsoft.OperationalInsights/workspaces/myWorkspace"
        "/providers/Microsoft.SecurityInsights"
    )

    def test_a_listing_and_a_write(self, client: TestClient) -> None:
        headers = _auth(client)
        listed = client.get(f"{SENTINEL_PREFIX}{self.OTHER}/incidents", headers=headers).json()
        first = listed["value"][0]
        assert first["id"] == f"{self.OTHER}/incidents/{first['name']}"

        written = client.put(
            f"{SENTINEL_PREFIX}{self.OTHER}/incidents/{first['name']}/comments/where",
            json={"properties": {"message": "m"}}, headers=headers,
        ).json()
        # A comment is a child of its incident (Incident Comments - Create Or
        # Update: `.../incidents/{incidentId}/comments/{commentId}`, type
        # `Microsoft.SecurityInsights/incidents/comments`); it was answered
        # as `.../incidentComments/{commentId}`.
        assert written["id"] == f"{self.OTHER}/incidents/{first['name']}/comments/where"
        assert written["type"] == "Microsoft.SecurityInsights/incidents/comments"

    def test_the_default_workspace_is_unchanged(self, client: TestClient) -> None:
        listed = client.get(f"{SENTINEL_PREFIX}{_WS}/alertRules", headers=_auth(client)).json()
        assert all(r["id"].startswith(f"{_WS}/alertRules/") for r in listed["value"])


class TestANameIsMatchedWithoutRegardToCase:
    """ARM resource names are case-insensitive; the mock matched them exactly.

    The reference pages say it of the resource group ("The name is case
    insensitive") and it is ARM's rule for every name in the path. A client
    that wrote an incident back under a differently cased name got a 404 on
    read and a second incident on write.
    """

    def test_an_incident_answers_to_any_case(self, client: TestClient) -> None:
        headers = _auth(client)
        name = client.get(f"{SENTINEL_PREFIX}{_WS}/incidents",
                          headers=headers).json()["value"][0]["name"]
        shouted = name.upper() if name != name.upper() else name.lower()
        got = client.get(f"{SENTINEL_PREFIX}{_WS}/incidents/{shouted}", headers=headers)
        assert got.status_code == 200
        assert got.json()["name"] == name

    def test_a_put_in_another_case_replaces_rather_than_adds(
        self, client: TestClient,
    ) -> None:
        headers = _auth(client)
        body = {"properties": {"title": "t", "severity": "Low", "status": "New"}}
        first = client.put(f"{SENTINEL_PREFIX}{_WS}/incidents/Case-Test", json=body,
                           headers=headers)
        assert first.status_code == 201
        before = len(client.get(f"{SENTINEL_PREFIX}{_WS}/incidents",
                                params={"$top": 1000}, headers=headers).json()["value"])
        again = client.put(f"{SENTINEL_PREFIX}{_WS}/incidents/case-test", json=body,
                           headers=headers)
        assert again.status_code == 200
        assert again.json()["name"] == "Case-Test"
        after = len(client.get(f"{SENTINEL_PREFIX}{_WS}/incidents",
                               params={"$top": 1000}, headers=headers).json()["value"])
        assert after == before

    def test_a_comment_under_a_differently_cased_incident(self, client: TestClient) -> None:
        headers = _auth(client)
        name = client.get(f"{SENTINEL_PREFIX}{_WS}/incidents",
                          headers=headers).json()["value"][0]["name"]
        resp = client.put(
            f"{SENTINEL_PREFIX}{_WS}/incidents/{name.upper()}/comments/Note-1",
            json={"properties": {"message": "m"}}, headers=headers,
        )
        assert resp.status_code == 201
        listed = client.get(f"{SENTINEL_PREFIX}{_WS}/incidents/{name}/comments",
                            headers=headers).json()["value"]
        assert [c["name"] for c in listed].count("Note-1") == 1
        got = client.get(f"{SENTINEL_PREFIX}{_WS}/incidents/{name}/comments/note-1",
                         headers=headers)
        assert got.status_code == 200

    def test_an_alert_rule_deletes_in_any_case(self, client: TestClient) -> None:
        headers = _auth(client)
        client.put(
            f"{SENTINEL_PREFIX}{_WS}/alertRules/Rule-Case",
            json={"kind": "Scheduled", "properties": {
                "displayName": "r", "severity": "Low", "query": "SecurityAlert",
                "enabled": True}},
            headers=headers,
        )
        assert client.get(f"{SENTINEL_PREFIX}{_WS}/alertRules/RULE-CASE",
                          headers=headers).status_code == 200
        assert client.delete(f"{SENTINEL_PREFIX}{_WS}/alertRules/rule-case",
                             headers=headers).status_code == 200
        assert client.get(f"{SENTINEL_PREFIX}{_WS}/alertRules/Rule-Case",
                          headers=headers).status_code == 404
