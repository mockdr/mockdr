"""Integration tests for Microsoft Defender for Endpoint Machines endpoints.

Verifies machine listing, OData query parameters, sub-resources,
machine actions, and response envelope structure.
"""
from fastapi.testclient import TestClient


def _mde_auth(client: TestClient) -> dict[str, str]:
    """Authenticate and return MDE Bearer headers."""
    resp = client.post("/mde/oauth2/v2.0/token", data={
        "client_id": "mde-mock-admin-client",
        "client_secret": "mde-mock-admin-secret",
        "grant_type": "client_credentials",
    })
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


def _get_first_machine_id(client: TestClient, headers: dict) -> str:
    """Return the first machine ID from the listing."""
    resp = client.get("/mde/api/machines", headers=headers, params={"$top": 1})
    return resp.json()["value"][0]["machineId"]


class TestListMachines:
    """Tests for GET /mde/api/machines."""

    def test_list_machines_returns_200(self, client: TestClient) -> None:
        headers = _mde_auth(client)
        resp = client.get("/mde/api/machines", headers=headers)
        assert resp.status_code == 200

    def test_odata_response_format(self, client: TestClient) -> None:
        """Response must have @odata.context and value array."""
        headers = _mde_auth(client)
        resp = client.get("/mde/api/machines", headers=headers)
        body = resp.json()
        assert "@odata.context" in body
        assert "value" in body
        assert isinstance(body["value"], list)

    def test_machines_have_required_fields(self, client: TestClient) -> None:
        headers = _mde_auth(client)
        resp = client.get("/mde/api/machines", headers=headers, params={"$top": 1})
        machine = resp.json()["value"][0]
        required_fields = [
            "machineId", "computerDnsName", "osPlatform", "healthStatus",
            "riskScore", "exposureLevel", "lastSeen", "firstSeen",
            "machineTags", "lastIpAddress", "agentVersion",
        ]
        for field in required_fields:
            assert field in machine, f"Required field '{field}' missing from machine"

    def test_top_pagination(self, client: TestClient) -> None:
        """$top limits the number of returned machines."""
        headers = _mde_auth(client)
        resp = client.get("/mde/api/machines", headers=headers, params={"$top": 3})
        assert len(resp.json()["value"]) == 3

    def test_skip_pagination(self, client: TestClient) -> None:
        """$skip offsets the results — pages should be disjoint."""
        headers = _mde_auth(client)
        r1 = client.get("/mde/api/machines", headers=headers, params={"$top": 5, "$skip": 0})
        r2 = client.get("/mde/api/machines", headers=headers, params={"$top": 5, "$skip": 5})
        ids1 = {m["machineId"] for m in r1.json()["value"]}
        ids2 = {m["machineId"] for m in r2.json()["value"]}
        assert ids1.isdisjoint(ids2), "Paginated pages should not overlap"

    def test_filter_health_status(self, client: TestClient) -> None:
        """$filter with eq operator filters by healthStatus."""
        headers = _mde_auth(client)
        resp = client.get(
            "/mde/api/machines",
            headers=headers,
            params={"$filter": "healthStatus eq 'Active'", "$top": 100},
        )
        body = resp.json()
        assert resp.status_code == 200
        for machine in body["value"]:
            assert machine["healthStatus"] == "Active"

    def test_orderby_sorting(self, client: TestClient) -> None:
        """$orderby sorts the results."""
        headers = _mde_auth(client)
        resp = client.get(
            "/mde/api/machines",
            headers=headers,
            params={"$orderby": "computerDnsName asc", "$top": 50},
        )
        assert resp.status_code == 200
        names = [m["computerDnsName"] for m in resp.json()["value"]]
        assert names == sorted(names)

    def test_select_field_projection(self, client: TestClient) -> None:
        """$select limits fields returned on each machine."""
        headers = _mde_auth(client)
        resp = client.get(
            "/mde/api/machines",
            headers=headers,
            params={"$select": "machineId,computerDnsName", "$top": 3},
        )
        assert resp.status_code == 200
        for machine in resp.json()["value"]:
            assert "machineId" in machine
            assert "computerDnsName" in machine
            # Other fields should be absent
            assert "healthStatus" not in machine


class TestGetMachine:
    """Tests for GET /mde/api/machines/{machine_id}."""

    def test_get_single_machine(self, client: TestClient) -> None:
        headers = _mde_auth(client)
        machine_id = _get_first_machine_id(client, headers)
        resp = client.get(f"/mde/api/machines/{machine_id}", headers=headers)
        assert resp.status_code == 200
        assert resp.json()["machineId"] == machine_id

    def test_nonexistent_machine_returns_404(self, client: TestClient) -> None:
        headers = _mde_auth(client)
        resp = client.get("/mde/api/machines/nonexistent-id-12345", headers=headers)
        assert resp.status_code == 404


class TestMachineSubResources:
    """Tests for machine sub-resource endpoints."""

    def test_get_logon_users(self, client: TestClient) -> None:
        headers = _mde_auth(client)
        machine_id = _get_first_machine_id(client, headers)
        resp = client.get(f"/mde/api/machines/{machine_id}/logonusers", headers=headers)
        assert resp.status_code == 200
        body = resp.json()
        assert "@odata.context" in body
        assert "value" in body

    def test_get_machine_alerts(self, client: TestClient) -> None:
        headers = _mde_auth(client)
        machine_id = _get_first_machine_id(client, headers)
        resp = client.get(f"/mde/api/machines/{machine_id}/alerts", headers=headers)
        assert resp.status_code == 200
        body = resp.json()
        assert "@odata.context" in body
        assert "value" in body

    def test_get_machine_software(self, client: TestClient) -> None:
        headers = _mde_auth(client)
        machine_id = _get_first_machine_id(client, headers)
        resp = client.get(f"/mde/api/machines/{machine_id}/software", headers=headers)
        assert resp.status_code == 200
        body = resp.json()
        assert "@odata.context" in body
        assert "value" in body

    def test_get_machine_vulnerabilities(self, client: TestClient) -> None:
        headers = _mde_auth(client)
        machine_id = _get_first_machine_id(client, headers)
        resp = client.get(
            f"/mde/api/machines/{machine_id}/vulnerabilities",
            headers=headers,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "@odata.context" in body
        assert "value" in body

    def test_nonexistent_machine_sub_resource_returns_404(self, client: TestClient) -> None:
        headers = _mde_auth(client)
        resp = client.get("/mde/api/machines/nonexistent-id/logonusers", headers=headers)
        assert resp.status_code == 404


class TestMachineActions:
    """Tests for machine action endpoints (isolate, scan, etc.)."""

    def test_isolate_machine(self, client: TestClient) -> None:
        headers = _mde_auth(client)
        machine_id = _get_first_machine_id(client, headers)
        resp = client.post(
            f"/mde/api/machines/{machine_id}/isolate",
            headers=headers,
            json={"Comment": "Test isolation", "IsolationType": "Full"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["type"] == "Isolate"
        assert body["machineId"] == machine_id
        assert "actionId" in body

    def test_unisolate_machine(self, client: TestClient) -> None:
        headers = _mde_auth(client)
        machine_id = _get_first_machine_id(client, headers)
        resp = client.post(
            f"/mde/api/machines/{machine_id}/unisolate",
            headers=headers,
            json={"Comment": "Test release from isolation"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["type"] == "Unisolate"

    def test_run_av_scan(self, client: TestClient) -> None:
        headers = _mde_auth(client)
        machine_id = _get_first_machine_id(client, headers)
        resp = client.post(
            f"/mde/api/machines/{machine_id}/runAntiVirusScan",
            headers=headers,
            json={"Comment": "Test AV scan", "ScanType": "Quick"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["type"] == "RunAntiVirusScan"

    def test_restrict_code_execution(self, client: TestClient) -> None:
        headers = _mde_auth(client)
        machine_id = _get_first_machine_id(client, headers)
        resp = client.post(
            f"/mde/api/machines/{machine_id}/restrictCodeExecution",
            headers=headers,
            json={"Comment": "Test restrict code execution"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["type"] == "RestrictCodeExecution"

    def test_unrestrict_code_execution(self, client: TestClient) -> None:
        headers = _mde_auth(client)
        machine_id = _get_first_machine_id(client, headers)
        resp = client.post(
            f"/mde/api/machines/{machine_id}/unrestrictCodeExecution",
            headers=headers,
            json={"Comment": "Test unrestrict code execution"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["type"] == "UnrestrictCodeExecution"

    def test_collect_investigation_package(self, client: TestClient) -> None:
        headers = _mde_auth(client)
        machine_id = _get_first_machine_id(client, headers)
        resp = client.post(
            f"/mde/api/machines/{machine_id}/collectInvestigationPackage",
            headers=headers,
            json={"Comment": "Test collect investigation package"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["type"] == "CollectInvestigationPackage"

    def test_action_on_nonexistent_machine_returns_404(self, client: TestClient) -> None:
        headers = _mde_auth(client)
        resp = client.post(
            "/mde/api/machines/nonexistent-id/isolate",
            headers=headers,
            json={"Comment": "Test", "IsolationType": "Full"},
        )
        assert resp.status_code == 404
