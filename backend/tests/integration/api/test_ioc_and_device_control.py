"""Integration tests for IOC and Device Control endpoints."""
import json as _json

from fastapi.testclient import TestClient


class TestIOCEndpoints:
    def test_list_iocs_returns_data(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.get("/web/api/v2.1/threat-intelligence/iocs", headers=auth_headers)
        assert resp.status_code == 200
        body = resp.json()
        assert "data" in body
        assert isinstance(body["data"], list)

    def test_list_iocs_requires_auth(self, client: TestClient) -> None:
        assert client.get("/web/api/v2.1/threat-intelligence/iocs").status_code == 401

    def test_create_ioc_returns_created(self, client: TestClient, auth_headers: dict) -> None:
        payload = {
            "type": "IPV4",
            "value": "10.0.0.99",
            "source": "user",
            "description": "Integration test IOC",
        }
        resp = client.post("/web/api/v2.1/threat-intelligence/iocs",
                           headers=auth_headers, json=payload)
        assert resp.status_code == 200
        body = resp.json()
        assert "data" in body

    def test_create_ioc_appears_in_list(self, client: TestClient, auth_headers: dict) -> None:
        unique_ip = "192.168.222.111"
        payload = {"type": "IPV4", "value": unique_ip, "source": "user", "description": "test"}
        client.post("/web/api/v2.1/threat-intelligence/iocs",
                    headers=auth_headers, json=payload)
        iocs = client.get("/web/api/v2.1/threat-intelligence/iocs",
                          headers=auth_headers).json()["data"]
        values = [i.get("value") for i in iocs]
        assert unique_ip in values

    def test_delete_iocs_removes_items(self, client: TestClient, auth_headers: dict) -> None:
        payload = {"type": "IPV4", "value": "10.0.0.200", "source": "user", "description": "test"}
        created = client.post("/web/api/v2.1/threat-intelligence/iocs",
                              headers=auth_headers, json=payload)
        ioc_id = created.json()["data"]["uuid"]

        import json as _json
        del_resp = client.request(
            "DELETE",
            "/web/api/v2.1/threat-intelligence/iocs",
            headers={**auth_headers, "Content-Type": "application/json"},
            content=_json.dumps({"filter": {"ids": [ioc_id]}}),
        )
        assert del_resp.status_code == 200

    def test_filter_by_type(self, client: TestClient, auth_headers: dict) -> None:
        # types (plural) is the correct filter param per the IOC router
        resp = client.get("/web/api/v2.1/threat-intelligence/iocs", headers=auth_headers,
                          params={"types": "SHA1"})
        assert resp.status_code == 200
        for ioc in resp.json()["data"]:
            assert ioc["type"] == "SHA1"

    def test_limit_parameter(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.get("/web/api/v2.1/threat-intelligence/iocs", headers=auth_headers,
                          params={"limit": 3})
        assert len(resp.json()["data"]) <= 3


_DC_BASE = "/web/api/v2.1/device-control"

_DC_CREATE = {
    "ruleName": "Block USB storage",
    "action": "Block",
    "status": "Enabled",
    "interface": "USB",
    "ruleType": "class",
    "deviceClass": "Mass Storage",
}


class TestDeviceControlEndpoints:
    def test_list_returns_data(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.get(_DC_BASE, headers=auth_headers)
        assert resp.status_code == 200
        body = resp.json()
        assert "data" in body
        assert isinstance(body["data"], list)

    def test_requires_auth(self, client: TestClient) -> None:
        assert client.get(_DC_BASE).status_code == 401

    def test_limit_parameter(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.get(_DC_BASE, headers=auth_headers, params={"limit": 3})
        assert len(resp.json()["data"]) <= 3


class TestCreateDeviceControlRule:
    def test_returns_200(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.post(_DC_BASE, headers=auth_headers, json={"data": _DC_CREATE})
        assert resp.status_code == 200

    def test_returns_data_envelope_with_id(self, client: TestClient, auth_headers: dict) -> None:
        body = client.post(_DC_BASE, headers=auth_headers, json={"data": _DC_CREATE}).json()
        assert "data" in body
        assert "id" in body["data"]

    def test_created_rule_appears_in_list(self, client: TestClient, auth_headers: dict) -> None:
        rule_id = client.post(_DC_BASE, headers=auth_headers, json={"data": _DC_CREATE}).json()["data"]["id"]
        ids = [r["id"] for r in client.get(_DC_BASE, headers=auth_headers).json()["data"]]
        assert rule_id in ids

    def test_rule_name_stored(self, client: TestClient, auth_headers: dict) -> None:
        rule = client.post(_DC_BASE, headers=auth_headers, json={"data": _DC_CREATE}).json()["data"]
        assert rule["ruleName"] == _DC_CREATE["ruleName"]


class TestUpdateDeviceControlRule:
    def _create(self, client: TestClient, auth_headers: dict) -> str:
        return client.post(_DC_BASE, headers=auth_headers, json={"data": _DC_CREATE}).json()["data"]["id"]

    def test_returns_200(self, client: TestClient, auth_headers: dict) -> None:
        rule_id = self._create(client, auth_headers)
        resp = client.put(f"{_DC_BASE}/{rule_id}", headers=auth_headers,
                          json={"data": {"ruleName": "Updated"}})
        assert resp.status_code == 200

    def test_updates_rule_name(self, client: TestClient, auth_headers: dict) -> None:
        rule_id = self._create(client, auth_headers)
        body = client.put(f"{_DC_BASE}/{rule_id}", headers=auth_headers,
                          json={"data": {"ruleName": "Renamed"}}).json()["data"]
        assert body["ruleName"] == "Renamed"

    def test_unknown_id_returns_404(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.put(f"{_DC_BASE}/999999999999999999", headers=auth_headers,
                          json={"data": {"ruleName": "x"}})
        assert resp.status_code == 404


def _dc_delete(client: TestClient, auth_headers: dict, body: dict) -> "TestClient":
    """Issue a DELETE with a JSON body (TestClient.delete() does not support json=)."""
    return client.request(
        "DELETE", _DC_BASE,
        headers={**auth_headers, "Content-Type": "application/json"},
        content=_json.dumps(body),
    )


class TestDeleteDeviceControlRules:
    def _create(self, client: TestClient, auth_headers: dict) -> str:
        return client.post(_DC_BASE, headers=auth_headers, json={"data": _DC_CREATE}).json()["data"]["id"]

    def test_returns_affected_count(self, client: TestClient, auth_headers: dict) -> None:
        rule_id = self._create(client, auth_headers)
        body = _dc_delete(client, auth_headers, {"filter": {"ids": [rule_id]}}).json()
        assert body["data"]["affected"] == 1

    def test_deleted_rule_absent_from_list(self, client: TestClient, auth_headers: dict) -> None:
        rule_id = self._create(client, auth_headers)
        _dc_delete(client, auth_headers, {"filter": {"ids": [rule_id]}})
        ids = [r["id"] for r in client.get(_DC_BASE, headers=auth_headers).json()["data"]]
        assert rule_id not in ids

    def test_unknown_id_returns_affected_zero(self, client: TestClient, auth_headers: dict) -> None:
        body = _dc_delete(client, auth_headers, {"filter": {"ids": ["999999999999999999"]}}).json()
        assert body["data"]["affected"] == 0

    def test_missing_filter_ids_returns_400(self, client: TestClient, auth_headers: dict) -> None:
        resp = _dc_delete(client, auth_headers, {})
        assert resp.status_code == 400


class TestAccountsEndpoints:
    def test_list_accounts_returns_data(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.get("/web/api/v2.1/accounts", headers=auth_headers)
        assert resp.status_code == 200
        body = resp.json()
        assert "data" in body
        assert isinstance(body["data"], list)

    def test_get_single_account(self, client: TestClient, auth_headers: dict) -> None:
        accounts = client.get("/web/api/v2.1/accounts", headers=auth_headers).json()["data"]
        if accounts:
            aid = accounts[0]["id"]
            resp = client.get(f"/web/api/v2.1/accounts/{aid}", headers=auth_headers)
            assert resp.status_code == 200
            assert resp.json()["data"]["id"] == aid

    def test_requires_auth(self, client: TestClient) -> None:
        assert client.get("/web/api/v2.1/accounts").status_code == 401
