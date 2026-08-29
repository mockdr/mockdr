"""Integration tests for Sentinel threat intelligence endpoints."""
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


class TestThreatIndicators:
    """Tests for TI indicator CRUD."""

    def test_list_indicators(self, client: TestClient) -> None:
        resp = client.get(
            f"{SENTINEL_PREFIX}{_WS}/threatIntelligence/main/indicators",
            headers=_auth(client),
        )
        assert resp.status_code == 200
        assert "value" in resp.json()
        assert len(resp.json()["value"]) >= 3

    def test_create_indicator(self, client: TestClient) -> None:
        resp = client.post(
            f"{SENTINEL_PREFIX}{_WS}/threatIntelligence/main/createIndicator",
            json={"properties": {
                "displayName": "Test Indicator",
                "pattern": "[ipv4-addr:value = '10.0.0.1']",
                "patternType": "ipv4-addr",
                "source": "Test",
                "confidence": 80,
            }},
            headers=_auth(client),
        )
        assert resp.status_code == 200
        assert resp.json()["properties"]["displayName"] == "Test Indicator"

    def test_query_indicators(self, client: TestClient) -> None:
        resp = client.post(
            f"{SENTINEL_PREFIX}{_WS}/threatIntelligence/main/queryIndicators",
            json={"keywords": "C2"},
            headers=_auth(client),
        )
        assert resp.status_code == 200
        assert "value" in resp.json()

    def test_get_metrics(self, client: TestClient) -> None:
        """A GET, and a *list* — every level of it measured against the swagger.

        `ThreatIntelligenceMetricsList` wraps the properties object in
        `value`, and every metric entry is `{metricName, metricValue}`.
        mockdr answered the properties object alone and named the entries
        `patternType`/`source` and `value`, so a client reading
        `value[0].properties.patternTypeMetrics[0].metricName` found nothing
        at any level.
        """
        resp = client.get(
            f"{SENTINEL_PREFIX}{_WS}/threatIntelligence/main/metrics",
            headers=_auth(client),
        )
        assert resp.status_code == 200
        body = resp.json()
        assert list(body) == ["value"]
        assert len(body["value"]) == 1
        properties = body["value"][0]["properties"]
        assert set(properties) == {
            "lastUpdatedTimeUtc", "threatTypeMetrics",
            "patternTypeMetrics", "sourceMetrics",
        }
        for group in ("threatTypeMetrics", "patternTypeMetrics", "sourceMetrics"):
            assert properties[group], f"{group} is empty"
            for entry in properties[group]:
                assert set(entry) == {"metricName", "metricValue"}, group
                assert isinstance(entry["metricValue"], int), group

    def _an_indicator(self, client: TestClient, headers: dict) -> str:
        listed = client.get(
            f"{SENTINEL_PREFIX}{_WS}/threatIntelligence/main/indicators",
            headers=headers,
        )
        return str(listed.json()["value"][0]["name"])

    def test_append_tags_acts_on_the_indicator_in_the_path(
        self, client: TestClient,
    ) -> None:
        """`_AppendTags` names one indicator and answers with nothing.

        mockdr had invented a bulk pair on the collection, reading
        `indicatorNames` and `tags` — a path the vendor does not have and a
        body no client generated from the swagger would send.
        """
        headers = _auth(client)
        name = self._an_indicator(client, headers)

        resp = client.post(
            f"{SENTINEL_PREFIX}{_WS}/threatIntelligence/main/indicators/"
            f"{name}/appendTags",
            json={"threatIntelligenceTags": ["test-tag"]},
            headers=headers,
        )
        assert resp.status_code == 200
        assert resp.content == b"", "append answers 200 with no body"

        after = client.get(
            f"{SENTINEL_PREFIX}{_WS}/threatIntelligence/main/indicators/{name}",
            headers=headers,
        ).json()
        assert "test-tag" in after["properties"]["threatIntelligenceTags"]

    def test_replace_tags_answers_with_the_indicator(
        self, client: TestClient,
    ) -> None:
        """The asymmetry is the vendor's: append returns nothing, replace
        returns `ThreatIntelligenceInformation`."""
        headers = _auth(client)
        name = self._an_indicator(client, headers)

        resp = client.post(
            f"{SENTINEL_PREFIX}{_WS}/threatIntelligence/main/indicators/"
            f"{name}/replaceTags",
            json={"threatIntelligenceTags": ["only-this"]},
            headers=headers,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["name"] == name
        assert body["properties"]["threatIntelligenceTags"] == ["only-this"]

    def test_tagging_an_indicator_that_is_not_there_is_404(
        self, client: TestClient,
    ) -> None:
        resp = client.post(
            f"{SENTINEL_PREFIX}{_WS}/threatIntelligence/main/indicators/"
            f"zzz-no-such/appendTags",
            json={"threatIntelligenceTags": ["t"]},
            headers=_auth(client),
        )
        assert resp.status_code == 404

    def test_delete_indicator(self, client: TestClient) -> None:
        headers = _auth(client)
        # Create one first
        create_resp = client.post(
            f"{SENTINEL_PREFIX}{_WS}/threatIntelligence/main/createIndicator",
            json={"properties": {
                "displayName": "To Delete",
                "pattern": "[domain-name:value = 'delete.me']",
                "patternType": "domain-name",
            }},
            headers=headers,
        )
        name = create_resp.json()["name"]

        resp = client.delete(
            f"{SENTINEL_PREFIX}{_WS}/threatIntelligence/main/indicators/{name}",
            headers=headers,
        )
        assert resp.status_code == 200
