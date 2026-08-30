"""A record that names a machine must name it the way the machine does.

Defender's own property tables record `computerDnsName` beside `machineId`
on an alert, an investigation and a machine action. This mock set it on none
of them, so all three answered an empty string while `/api/machines` had the
name all along — a client reading an alert to find the affected host found
nothing, and one correlating on the name found nothing either.

`rbacGroupName` was the same on an alert: the group is the machine's, and
the alert reported none.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def mde_headers(client: TestClient) -> dict:
    response = client.post("/mde/oauth2/v2.0/token", data={
        "client_id": "mde-mock-admin-client",
        "client_secret": "mde-mock-admin-secret",
        "grant_type": "client_credentials",
        "scope": "https://api.securitycenter.microsoft.com/.default",
    })
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


@pytest.fixture
def machines(client: TestClient, mde_headers: dict) -> dict:
    response = client.get("/mde/api/machines", headers=mde_headers, params={"$top": "1000"})
    assert response.status_code == 200, response.text
    found = {m["id"]: m for m in response.json()["value"]}
    assert len(found) > 1, "one machine cannot show a mismatch"
    return found


class TestEveryRecordNamesItsMachine:
    @pytest.mark.parametrize(
        "route",
        ["/mde/api/alerts", "/mde/api/investigations", "/mde/api/machineactions"],
    )
    def test_the_name_matches_the_machine_record(
        self, client: TestClient, mde_headers: dict, machines: dict, route: str,
    ) -> None:
        rows = client.get(route, headers=mde_headers, params={"$top": "1000"}).json()["value"]
        assert rows, f"{route} answered nothing"
        checked = 0
        for row in rows:
            if "computerDnsName" not in row or not row.get("machineId"):
                continue
            machine = machines.get(row["machineId"])
            assert machine is not None, f"{route} names a machine that is not served"
            checked += 1
            assert row["computerDnsName"] == machine["computerDnsName"], row["machineId"]
            assert row["computerDnsName"], "an empty name is a name nothing matches"
        assert checked, f"{route} carried no machine name to check"

    def test_an_alert_reports_its_machines_group(
        self, client: TestClient, mde_headers: dict, machines: dict,
    ) -> None:
        alerts = client.get(
            "/mde/api/alerts", headers=mde_headers, params={"$top": "1000"},
        ).json()["value"]
        for alert in alerts:
            machine = machines.get(alert.get("machineId"))
            if machine is None:
                continue
            assert alert.get("rbacGroupName") == machine.get("rbacGroupName")

    def test_an_action_made_now_carries_the_name_too(
        self, client: TestClient, mde_headers: dict, machines: dict,
    ) -> None:
        machine_id, machine = next(iter(machines.items()))
        response = client.post(
            f"/mde/api/machines/{machine_id}/isolate", headers=mde_headers,
            json={"Comment": "zzz probe", "IsolationType": "Full"},
        )
        assert response.status_code == 200, response.text
        assert response.json()["computerDnsName"] == machine["computerDnsName"]
