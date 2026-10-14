"""Alert updates take the values the update pages list, and batchUpdate answers empty.

Defender's update-alert and batch-update-alerts pages
(https://learn.microsoft.com/en-us/defender-endpoint/api/update-alert,
.../batch-update-alerts) list what `status` ('New', 'InProgress',
'Resolved'), `classification` and `determination` may be set to; Graph's
alerts_v2 update page lists its lowerCamel enums
(https://learn.microsoft.com/en-us/graph/api/security-alert-update?view=graph-rest-1.0).
Both mounts stored any string, so a Sentinel `Closed` or a PascalCase
`Resolved` on Graph became the alert's state and was served to every later
read.

batchUpdate: `alertIds` is "Required", and success is "200 OK, with an empty
response body". The mock defaulted the IDs to none and answered a collection.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def mde_headers(client: TestClient) -> dict[str, str]:
    token = client.post("/mde/oauth2/v2.0/token", data={
        "client_id": "mde-mock-admin-client",
        "client_secret": "mde-mock-admin-secret",
        "grant_type": "client_credentials",
        "scope": "https://api.securitycenter.microsoft.com/.default",
    }).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def _alert_ids(client: TestClient, headers: dict[str, str], n: int) -> list[str]:
    return [a["id"] for a in client.get("/mde/api/alerts", headers=headers,
                                        params={"$top": n}).json()["value"]]


class TestDefenderAlertUpdate:
    """PATCH /api/alerts/{id} refuses a value the page does not list."""

    @pytest.mark.parametrize(("field", "value"), [
        ("status", "Closed"), ("classification", "BenignPositive"), ("determination", "Apt"),
    ])
    def test_unlisted_value_is_invalid_request_body(
        self, client: TestClient, mde_headers: dict[str, str], field: str, value: str,
    ) -> None:
        alert_id = _alert_ids(client, mde_headers, 1)[0]
        before = client.get(f"/mde/api/alerts/{alert_id}", headers=mde_headers).json()
        response = client.patch(f"/mde/api/alerts/{alert_id}", headers=mde_headers,
                                json={field: value})
        assert response.status_code == 400
        assert response.json()["error"]["code"] == "InvalidRequestBody"
        after = client.get(f"/mde/api/alerts/{alert_id}", headers=mde_headers).json()
        assert after[field] == before[field]

    def test_listed_values_update(self, client: TestClient, mde_headers: dict[str, str]) -> None:
        alert_id = _alert_ids(client, mde_headers, 1)[0]
        response = client.patch(f"/mde/api/alerts/{alert_id}", headers=mde_headers, json={
            "status": "Resolved", "classification": "FalsePositive", "determination": "Malware",
        })
        assert response.status_code == 200
        assert response.json()["determination"] == "Malware"


class TestDefenderBatchUpdate:
    """batchUpdate needs alertIds and answers an empty 200."""

    def test_success_has_an_empty_body(
        self, client: TestClient, mde_headers: dict[str, str],
    ) -> None:
        ids = _alert_ids(client, mde_headers, 2)
        response = client.post("/mde/api/alerts/batchUpdate", headers=mde_headers,
                               json={"alertIds": ids, "status": "InProgress"})
        assert response.status_code == 200
        assert response.content == b""
        for alert_id in ids:
            assert client.get(f"/mde/api/alerts/{alert_id}",
                              headers=mde_headers).json()["status"] == "InProgress"

    def test_alert_ids_are_required(
        self, client: TestClient, mde_headers: dict[str, str],
    ) -> None:
        response = client.post("/mde/api/alerts/batchUpdate", headers=mde_headers,
                               json={"status": "Resolved"})
        assert response.status_code == 400
        assert response.json()["error"]["code"] == "MissingRequiredParameter"

    def test_a_refused_batch_changes_nothing(
        self, client: TestClient, mde_headers: dict[str, str],
    ) -> None:
        ids = _alert_ids(client, mde_headers, 2)
        before = [client.get(f"/mde/api/alerts/{i}", headers=mde_headers).json()["status"]
                  for i in ids]
        response = client.post("/mde/api/alerts/batchUpdate", headers=mde_headers,
                               json={"alertIds": ids, "status": "Closed"})
        assert response.status_code == 400
        after = [client.get(f"/mde/api/alerts/{i}", headers=mde_headers).json()["status"]
                 for i in ids]
        assert after == before


class TestGraphAlertUpdate:
    """PATCH alerts_v2 takes Graph's lowerCamel members only."""

    def test_pascal_case_status_is_refused(
        self, client: TestClient, graph_admin_headers: dict[str, str],
    ) -> None:
        alert = client.get("/graph/v1.0/security/alerts_v2", headers=graph_admin_headers,
                           params={"$top": 1}).json()["value"][0]
        response = client.patch(f"/graph/v1.0/security/alerts_v2/{alert['id']}",
                                headers=graph_admin_headers, json={"status": "Resolved"})
        assert response.status_code == 400
        assert response.json()["error"]["code"] == "badRequest"
        again = client.get(f"/graph/v1.0/security/alerts_v2/{alert['id']}",
                           headers=graph_admin_headers).json()
        assert again["status"] == alert["status"]

    def test_documented_values_update(
        self, client: TestClient, graph_admin_headers: dict[str, str],
    ) -> None:
        alert = client.get("/graph/v1.0/security/alerts_v2", headers=graph_admin_headers,
                           params={"$top": 1}).json()["value"][0]
        response = client.patch(
            f"/graph/v1.0/security/alerts_v2/{alert['id']}", headers=graph_admin_headers,
            json={"status": "resolved", "classification": "truePositive",
                  "determination": "compromisedUser"},
        )
        assert response.status_code == 200, response.text
        assert response.json()["status"] == "resolved"


class TestSecurityCollectionsCount:
    """alerts_v2 and incidents document `$count`; it reports the filtered total.

    https://learn.microsoft.com/en-us/graph/api/security-list-alerts_v2?view=graph-rest-1.0
    ("$count, $filter, $skip, $top") and security-list-incidents ("$count,
    $filter, $skip, $top, $expand"). Neither route took it, so the count a
    client asked for never came back. No ConsistencyLevel: these are not
    directory objects.
    """

    @pytest.mark.parametrize("path", ["/graph/v1.0/security/alerts_v2",
                                      "/graph/v1.0/security/incidents"])
    def test_count_is_the_filtered_total(
        self, client: TestClient, graph_admin_headers: dict[str, str], path: str,
    ) -> None:
        whole = client.get(path, headers=graph_admin_headers,
                           params={"$top": 999}).json()["value"]
        severity = whole[0]["severity"]
        expected = sum(1 for r in whole if r["severity"] == severity)
        body = client.get(path, headers=graph_admin_headers, params={
            "$count": "true", "$top": 1, "$filter": f"severity eq '{severity}'",
        }).json()
        assert body["@odata.count"] == expected
        assert len(body["value"]) == 1
