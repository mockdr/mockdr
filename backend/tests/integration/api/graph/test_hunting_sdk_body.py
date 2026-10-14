"""runHuntingQuery takes its parameters the way the official SDK sends them.

The reference page writes the body ``{"Query": ..., "Timespan": ...}``; the
CSDL declares the action's parameters ``query`` and ``timespan``, and
msgraph-sdk-python -- generated from it -- serialises exactly those names
(``RunHuntingQueryPostRequestBody.serialize``: ``write_str_value("query",
...)``, ``write_str_value("timespan", ...)``, and a null ``workspaceId``),
posting to the namespace-qualified segment. Graph binds action parameters
without regard to case, so both spellings run against the product. The mock
read only ``Query``: every hunt sent through the SDK was refused ``400 A
recognized query is expected`` and its ``timespan`` was never seen.

The bodies below are the SDK's, byte for byte as its JSON writer emits them.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient

SDK_URL = "/graph/v1.0/security/microsoft.graph.security.runHuntingQuery"


class TestTheSdkBodyRuns:
    """Lower-case parameter names are the SDK's, and they are read."""

    def test_the_sdk_query_runs(
        self, client: TestClient, graph_admin_headers: dict[str, str],
    ) -> None:
        response = client.post(SDK_URL, headers=graph_admin_headers, json={
            "query": "DeviceInfo | summarize c=count() by OSPlatform",
            "timespan": None,
            "workspaceId": None,
        })
        assert response.status_code == 200, response.text
        body = response.json()
        assert [c["name"] for c in body["schema"]] == ["OSPlatform", "c"]
        assert body["results"]

    def test_the_sdk_timespan_narrows_the_hunt(
        self, client: TestClient, graph_admin_headers: dict[str, str],
    ) -> None:
        def stamps(timespan: str) -> list[datetime]:
            response = client.post(SDK_URL, headers=graph_admin_headers, json={
                "query": "DeviceNetworkEvents", "timespan": timespan, "workspaceId": None,
            })
            assert response.status_code == 200, response.text
            return [datetime.fromisoformat(r["Timestamp"].replace("Z", "+00:00"))
                    for r in response.json()["results"]]

        everything, recent = stamps("P90D"), stamps("P3D")
        cutoff = datetime.now(UTC) - timedelta(days=3, minutes=1)
        assert 0 < len(recent) < len(everything)
        assert all(stamp >= cutoff for stamp in recent)

    def test_a_bad_sdk_timespan_is_still_refused(
        self, client: TestClient, graph_admin_headers: dict[str, str],
    ) -> None:
        response = client.post(SDK_URL, headers=graph_admin_headers, json={
            "query": "DeviceInfo", "timespan": "last week", "workspaceId": None,
        })
        assert response.status_code == 400

    def test_the_documented_spelling_still_runs(
        self, client: TestClient, graph_admin_headers: dict[str, str],
    ) -> None:
        response = client.post(SDK_URL, headers=graph_admin_headers,
                               json={"Query": "DeviceInfo | take 1"})
        assert response.status_code == 200, response.text
        assert len(response.json()["results"]) == 1
