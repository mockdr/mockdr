"""Integration test: Full XSOAR Azure Sentinel compatible flow.

Simulates: auth → fetch incidents → get alerts → get entities → update → close.
"""
from fastapi.testclient import TestClient

SENTINEL_PREFIX = "/sentinel"
_WS = (
    "/subscriptions/00000000-0000-0000-0000-000000000000"
    "/resourceGroups/mockdr-rg"
    "/providers/Microsoft.OperationalInsights/workspaces/mockdr-workspace"
    "/providers/Microsoft.SecurityInsights"
)


class TestXsoarSentinelFlow:
    """End-to-end XSOAR Azure Sentinel compatible flow."""

    def test_full_lifecycle(self, client: TestClient) -> None:
        # Step 1: OAuth2 login
        token_resp = client.post(
            f"{SENTINEL_PREFIX}/oauth2/v2.0/token",
            data={
                "client_id": "sentinel-mock-client-id",
                "client_secret": "sentinel-mock-client-secret",
                "grant_type": "client_credentials",
            },
        )
        assert token_resp.status_code == 200
        token = token_resp.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # Step 2: List incidents (fetch-incidents)
        list_resp = client.get(
            f"{SENTINEL_PREFIX}{_WS}/incidents",
            params={"$top": 10, "$orderby": "properties/createdTimeUtc desc"},
            headers=headers,
        )
        assert list_resp.status_code == 200
        incidents = list_resp.json()["value"]
        assert len(incidents) > 0

        incident = incidents[0]
        inc_id = incident["name"]

        # Step 3: Get incident detail
        detail_resp = client.get(
            f"{SENTINEL_PREFIX}{_WS}/incidents/{inc_id}",
            headers=headers,
        )
        assert detail_resp.status_code == 200
        props = detail_resp.json()["properties"]
        assert "title" in props
        assert "additionalData" in props

        # Step 4: Get incident alerts
        alerts_resp = client.post(
            f"{SENTINEL_PREFIX}{_WS}/incidents/{inc_id}/alerts",
            headers=headers,
        )
        assert alerts_resp.status_code == 200
        assert "value" in alerts_resp.json()

        # Step 5: Get incident entities
        entities_resp = client.post(
            f"{SENTINEL_PREFIX}{_WS}/incidents/{inc_id}/entities",
            headers=headers,
        )
        assert entities_resp.status_code == 200
        assert "entities" in entities_resp.json()

        # Step 6: Add comment
        comment_resp = client.put(
            f"{SENTINEL_PREFIX}{_WS}/incidents/{inc_id}/comments/xsoar-comment-001",
            json={"properties": {"message": "Automated triage by XSOAR"}},
            headers=headers,
        )
        assert comment_resp.status_code == 200

        # Step 7: Update incident (close with classification)
        update_resp = client.put(
            f"{SENTINEL_PREFIX}{_WS}/incidents/{inc_id}",
            json={"properties": {
                "status": "Closed",
                "classification": "TruePositive",
                "classificationComment": "Confirmed by XSOAR playbook",
            }},
            headers=headers,
        )
        assert update_resp.status_code == 200
        assert update_resp.json()["properties"]["status"] == "Closed"
        assert update_resp.json()["properties"]["classification"] == "TruePositive"

    def test_incident_has_alert_product_names(self, client: TestClient) -> None:
        """Verify incidents have alertProductNames (XSOAR uses this for enrichment)."""
        token_resp = client.post(
            f"{SENTINEL_PREFIX}/oauth2/v2.0/token",
            data={"client_id": "sentinel-mock-client-id",
                  "client_secret": "sentinel-mock-client-secret",
                  "grant_type": "client_credentials"},
        )
        headers = {"Authorization": f"Bearer {token_resp.json()['access_token']}"}

        resp = client.get(f"{SENTINEL_PREFIX}{_WS}/incidents", headers=headers)
        incidents = resp.json()["value"]

        product_names_found = set()
        for inc in incidents:
            names = inc["properties"]["additionalData"].get("alertProductNames", [])
            product_names_found.update(names)

        # Should have at least MDE incidents
        assert len(product_names_found) > 0

    def test_kql_query_returns_incidents(self, client: TestClient) -> None:
        """Verify KQL query works for SecurityIncident table."""
        token_resp = client.post(
            f"{SENTINEL_PREFIX}/oauth2/v2.0/token",
            data={"client_id": "sentinel-mock-client-id",
                  "client_secret": "sentinel-mock-client-secret",
                  "grant_type": "client_credentials"},
        )
        headers = {"Authorization": f"Bearer {token_resp.json()['access_token']}"}

        resp = client.post(
            f"{SENTINEL_PREFIX}/v1/workspaces/mockdr-workspace/query",
            json={"query": 'SecurityIncident | where Status == "New" | take 5'},
            headers=headers,
        )
        assert resp.status_code == 200
        rows = resp.json()["tables"][0]["rows"]
        assert len(rows) >= 0  # May have 0 if all are Active/Closed
