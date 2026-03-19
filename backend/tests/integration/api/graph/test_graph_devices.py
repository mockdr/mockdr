"""Integration tests for Microsoft Graph Device Management (Intune) endpoints."""
from fastapi.testclient import TestClient


class TestGraphManagedDevices:
    """Tests for GET /graph/v1.0/deviceManagement/managedDevices."""

    def test_list_managed_devices_returns_odata(
        self, client: TestClient, graph_admin_headers: dict,
    ) -> None:
        """GET should return an OData envelope with @odata.context and value."""
        resp = client.get(
            "/graph/v1.0/deviceManagement/managedDevices",
            headers=graph_admin_headers,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "@odata.context" in body
        assert "value" in body
        assert isinstance(body["value"], list)

    def test_list_managed_devices_count_matches_agents(
        self, client: TestClient, graph_admin_headers: dict,
    ) -> None:
        """Seed data should contain 66 managed devices (60 fleet + 6 mobile)."""
        resp = client.get(
            "/graph/v1.0/deviceManagement/managedDevices",
            headers=graph_admin_headers,
        )
        assert resp.status_code == 200
        assert len(resp.json()["value"]) == 66

    def test_list_managed_devices_with_select(
        self, client: TestClient, graph_admin_headers: dict,
    ) -> None:
        """$select=id,deviceName should return only those fields."""
        resp = client.get(
            "/graph/v1.0/deviceManagement/managedDevices",
            params={"$select": "id,deviceName"},
            headers=graph_admin_headers,
        )
        assert resp.status_code == 200
        for device in resp.json()["value"]:
            assert "id" in device
            assert "deviceName" in device
            assert "operatingSystem" not in device

    def test_list_managed_devices_with_filter_compliance(
        self, client: TestClient, graph_admin_headers: dict,
    ) -> None:
        """$filter=complianceState eq 'noncompliant' should return only noncompliant devices."""
        resp = client.get(
            "/graph/v1.0/deviceManagement/managedDevices",
            params={"$filter": "complianceState eq 'noncompliant'"},
            headers=graph_admin_headers,
        )
        assert resp.status_code == 200
        devices = resp.json()["value"]
        assert len(devices) >= 1
        for device in devices:
            assert device["complianceState"] == "noncompliant"

    def test_list_managed_devices_count_with_consistency_level(
        self, client: TestClient, graph_admin_headers: dict,
    ) -> None:
        """$count=true with ConsistencyLevel should include @odata.count."""
        headers = {**graph_admin_headers, "ConsistencyLevel": "eventual"}
        resp = client.get(
            "/graph/v1.0/deviceManagement/managedDevices",
            params={"$count": "true"},
            headers=headers,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "@odata.count" in body
        assert body["@odata.count"] == 66

    def test_get_managed_device_returns_device(
        self, client: TestClient, graph_admin_headers: dict,
    ) -> None:
        """GET /v1.0/deviceManagement/managedDevices/{id} should return a single device."""
        list_resp = client.get(
            "/graph/v1.0/deviceManagement/managedDevices",
            params={"$top": 1},
            headers=graph_admin_headers,
        )
        device_id = list_resp.json()["value"][0]["id"]

        resp = client.get(
            f"/graph/v1.0/deviceManagement/managedDevices/{device_id}",
            headers=graph_admin_headers,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["id"] == device_id
        assert "deviceName" in body
        assert "operatingSystem" in body

    def test_get_managed_device_not_found_returns_404(
        self, client: TestClient, graph_admin_headers: dict,
    ) -> None:
        """GET with a nonexistent device ID should return 404."""
        resp = client.get(
            "/graph/v1.0/deviceManagement/managedDevices/00000000-0000-0000-0000-000000000000",
            headers=graph_admin_headers,
        )
        assert resp.status_code == 404

    def test_eol_os_devices_exist(
        self, client: TestClient, graph_admin_headers: dict,
    ) -> None:
        """Seed data should contain at least one device with an EOL OS version."""
        resp = client.get(
            "/graph/v1.0/deviceManagement/managedDevices",
            headers=graph_admin_headers,
        )
        devices = resp.json()["value"]
        eol_markers = ("8.1", "Big Sur", "1809", "CentOS 7")
        eol_devices = [
            d for d in devices
            if any(m in d.get("osVersion", "") for m in eol_markers)
        ]
        assert len(eol_devices) >= 1, "Expected at least one EOL OS device"

    def test_byod_personal_devices_exist(
        self, client: TestClient, graph_admin_headers: dict,
    ) -> None:
        """Seed data should contain personal (BYOD) devices."""
        resp = client.get(
            "/graph/v1.0/deviceManagement/managedDevices",
            headers=graph_admin_headers,
        )
        devices = resp.json()["value"]
        personal = [d for d in devices if d.get("managedDeviceOwnerType") == "personal"]
        assert len(personal) >= 1, "Expected at least one personal/BYOD device"

    def test_noncompliant_devices_exist(
        self, client: TestClient, graph_admin_headers: dict,
    ) -> None:
        """Seed data should contain noncompliant devices."""
        resp = client.get(
            "/graph/v1.0/deviceManagement/managedDevices",
            headers=graph_admin_headers,
        )
        devices = resp.json()["value"]
        noncompliant = [d for d in devices if d["complianceState"] == "noncompliant"]
        assert len(noncompliant) >= 1

    def test_plan1_cannot_access_devices(
        self, client: TestClient, graph_p1_headers: dict,
    ) -> None:
        """Plan 1 token should receive 403 for device management endpoints."""
        resp = client.get(
            "/graph/v1.0/deviceManagement/managedDevices",
            headers=graph_p1_headers,
        )
        assert resp.status_code == 403


class TestGraphDeviceActions:
    """Tests for device action endpoints (wipe, retire, sync, reboot, scan)."""

    def _get_device_id(self, client: TestClient, headers: dict) -> str:
        """Helper to get a valid device ID."""
        resp = client.get(
            "/graph/v1.0/deviceManagement/managedDevices",
            params={"$top": 1},
            headers=headers,
        )
        return resp.json()["value"][0]["id"]

    def test_wipe_device_returns_204(
        self, client: TestClient, graph_admin_headers: dict,
    ) -> None:
        """POST .../wipe should return 204 No Content."""
        device_id = self._get_device_id(client, graph_admin_headers)
        resp = client.post(
            f"/graph/v1.0/deviceManagement/managedDevices/{device_id}/wipe",
            headers=graph_admin_headers,
        )
        assert resp.status_code == 204

    def test_retire_device_returns_204(
        self, client: TestClient, graph_admin_headers: dict,
    ) -> None:
        """POST .../retire should return 204 No Content."""
        device_id = self._get_device_id(client, graph_admin_headers)
        resp = client.post(
            f"/graph/v1.0/deviceManagement/managedDevices/{device_id}/retire",
            headers=graph_admin_headers,
        )
        assert resp.status_code == 204

    def test_sync_device_returns_204(
        self, client: TestClient, graph_admin_headers: dict,
    ) -> None:
        """POST .../syncDevice should return 204 No Content."""
        device_id = self._get_device_id(client, graph_admin_headers)
        resp = client.post(
            f"/graph/v1.0/deviceManagement/managedDevices/{device_id}/syncDevice",
            headers=graph_admin_headers,
        )
        assert resp.status_code == 204

    def test_reboot_device_returns_204(
        self, client: TestClient, graph_admin_headers: dict,
    ) -> None:
        """POST .../rebootNow should return 204 No Content."""
        device_id = self._get_device_id(client, graph_admin_headers)
        resp = client.post(
            f"/graph/v1.0/deviceManagement/managedDevices/{device_id}/rebootNow",
            headers=graph_admin_headers,
        )
        assert resp.status_code == 204

    def test_defender_scan_returns_204(
        self, client: TestClient, graph_admin_headers: dict,
    ) -> None:
        """POST .../windowsDefenderScan should return 204 No Content."""
        device_id = self._get_device_id(client, graph_admin_headers)
        resp = client.post(
            f"/graph/v1.0/deviceManagement/managedDevices/{device_id}/windowsDefenderScan",
            headers=graph_admin_headers,
        )
        assert resp.status_code == 204

    def test_action_on_nonexistent_device_returns_404(
        self, client: TestClient, graph_admin_headers: dict,
    ) -> None:
        """Device action on a nonexistent ID should return 404."""
        resp = client.post(
            "/graph/v1.0/deviceManagement/managedDevices/00000000-0000-0000-0000-000000000000/wipe",
            headers=graph_admin_headers,
        )
        assert resp.status_code == 404

    def test_plan1_cannot_wipe_device(
        self, client: TestClient, graph_p1_headers: dict,
    ) -> None:
        """Plan 1 token should receive 403 for device wipe action."""
        resp = client.post(
            "/graph/v1.0/deviceManagement/managedDevices/any-id/wipe",
            headers=graph_p1_headers,
        )
        assert resp.status_code == 403


class TestGraphDetectedApps:
    """Tests for detected apps endpoints."""

    def test_list_detected_apps_returns_odata(
        self, client: TestClient, graph_admin_headers: dict,
    ) -> None:
        """GET /v1.0/deviceManagement/detectedApps should return OData envelope."""
        resp = client.get(
            "/graph/v1.0/deviceManagement/detectedApps",
            headers=graph_admin_headers,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "@odata.context" in body
        assert "value" in body
        assert len(body["value"]) >= 1
        app = body["value"][0]
        assert "displayName" in app
        assert "deviceCount" in app

    def test_get_detected_app_devices_returns_devices(
        self, client: TestClient, graph_admin_headers: dict,
    ) -> None:
        """GET .../detectedApps/{id}/managedDevices should return devices list."""
        apps_resp = client.get(
            "/graph/v1.0/deviceManagement/detectedApps",
            params={"$top": 1},
            headers=graph_admin_headers,
        )
        app_id = apps_resp.json()["value"][0]["id"]

        resp = client.get(
            f"/graph/v1.0/deviceManagement/detectedApps/{app_id}/managedDevices",
            headers=graph_admin_headers,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "@odata.context" in body
        assert "value" in body
        assert len(body["value"]) >= 1
