"""Integration tests for /firewall-control endpoints (GET, POST, PUT, DELETE).

Verifies response shape, required fields, S1 port/host object format,
and internal field exclusion.
"""
import json as _json

from fastapi.testclient import TestClient

from utils.internal_fields import FIREWALL_INTERNAL_FIELDS

_INTERNAL = FIREWALL_INTERNAL_FIELDS
_REQUIRED = {"id", "name", "status", "action", "direction", "order", "osType",
             "createdAt", "updatedAt", "localPort", "remotePort", "remoteHost"}


class TestListFirewallRules:
    def test_requires_auth(self, client: TestClient) -> None:
        assert client.get("/web/api/v2.1/firewall-control").status_code == 401

    def test_returns_data_and_pagination(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.get("/web/api/v2.1/firewall-control", headers=auth_headers)
        assert resp.status_code == 200
        body = resp.json()
        assert "data" in body
        assert "pagination" in body
        assert isinstance(body["data"], list)

    def test_required_fields_present(self, client: TestClient, auth_headers: dict) -> None:
        rule = client.get("/web/api/v2.1/firewall-control", headers=auth_headers).json()["data"][0]
        for field in _REQUIRED:
            assert field in rule, f"Required field '{field}' missing from firewall rule"

    def test_no_internal_fields(self, client: TestClient, auth_headers: dict) -> None:
        for rule in client.get("/web/api/v2.1/firewall-control", headers=auth_headers).json()["data"]:
            for field in _INTERNAL:
                assert field not in rule, f"Internal field '{field}' leaked in firewall rule"

    def test_port_fields_are_objects(self, client: TestClient, auth_headers: dict) -> None:
        """Port and host fields use the S1 object format: {type: str, values: list}."""
        rule = client.get("/web/api/v2.1/firewall-control", headers=auth_headers).json()["data"][0]
        for field in ("localPort", "remotePort", "remoteHost"):
            assert isinstance(rule[field], dict), f"'{field}' should be a dict"
            assert "type" in rule[field]
            assert "values" in rule[field]

    def test_action_is_valid(self, client: TestClient, auth_headers: dict) -> None:
        rule = client.get("/web/api/v2.1/firewall-control", headers=auth_headers).json()["data"][0]
        assert rule["action"] in ("Allow", "Block")

    def test_direction_is_valid(self, client: TestClient, auth_headers: dict) -> None:
        rule = client.get("/web/api/v2.1/firewall-control", headers=auth_headers).json()["data"][0]
        assert rule["direction"] in ("inbound", "outbound", "both", "any")

    def test_filter_by_status(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.get("/web/api/v2.1/firewall-control", headers=auth_headers,
                          params={"statuses": "Enabled"})
        assert resp.status_code == 200
        for rule in resp.json()["data"]:
            assert rule["status"] == "Enabled"

    def test_filter_by_action(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.get("/web/api/v2.1/firewall-control", headers=auth_headers,
                          params={"actions": "Allow"})
        assert resp.status_code == 200
        for rule in resp.json()["data"]:
            assert rule["action"] == "Allow"

    def test_limit_parameter(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.get("/web/api/v2.1/firewall-control", headers=auth_headers, params={"limit": 2})
        assert len(resp.json()["data"]) <= 2


BASE = "/web/api/v2.1/firewall-control"

_CREATE_BODY = {
    "name": "Block outbound 4444",
    "action": "Block",
    "direction": "outbound",
    "status": "Enabled",
    "osType": "windows",
}


class TestCreateFirewallRule:
    def test_returns_200(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.post(BASE, headers=auth_headers, json={"data": _CREATE_BODY})
        assert resp.status_code == 200

    def test_returns_data_envelope(self, client: TestClient, auth_headers: dict) -> None:
        body = client.post(BASE, headers=auth_headers, json={"data": _CREATE_BODY}).json()
        assert "data" in body
        assert "id" in body["data"]

    def test_created_rule_appears_in_list(self, client: TestClient, auth_headers: dict) -> None:
        rule_id = client.post(
            BASE, headers=auth_headers, json={"data": _CREATE_BODY}
        ).json()["data"]["id"]
        ids = [r["id"] for r in client.get(BASE, headers=auth_headers).json()["data"]]
        assert rule_id in ids

    def test_no_internal_fields_in_response(self, client: TestClient, auth_headers: dict) -> None:
        rule = client.post(BASE, headers=auth_headers, json={"data": _CREATE_BODY}).json()["data"]
        for field in _INTERNAL:
            assert field not in rule

    def test_site_id_propagated_from_filter(self, client: TestClient, auth_headers: dict) -> None:
        site_id = client.get("/web/api/v2.1/sites", headers=auth_headers).json()["data"]["sites"][0]["id"]
        body = client.post(
            BASE,
            headers=auth_headers,
            json={"data": _CREATE_BODY, "filter": {"siteIds": [site_id]}},
        ).json()["data"]
        # siteId is an internal field and must not appear in the response
        assert "siteId" not in body


class TestUpdateFirewallRule:
    def _create(self, client: TestClient, auth_headers: dict) -> str:
        return client.post(BASE, headers=auth_headers, json={"data": _CREATE_BODY}).json()["data"]["id"]

    def test_returns_200(self, client: TestClient, auth_headers: dict) -> None:
        rule_id = self._create(client, auth_headers)
        resp = client.put(
            BASE, headers=auth_headers,
            json={"data": {"name": "Updated"}, "filter": {"ids": [rule_id]}},
        )
        assert resp.status_code == 200

    def test_updates_name(self, client: TestClient, auth_headers: dict) -> None:
        rule_id = self._create(client, auth_headers)
        body = client.put(
            BASE, headers=auth_headers,
            json={"data": {"name": "Renamed rule"}, "filter": {"ids": [rule_id]}},
        ).json()["data"]
        assert body["affected"] == 1
        # Verify actual update via GET
        rules = client.get(BASE, headers=auth_headers).json()["data"]
        updated = [r for r in rules if r["id"] == rule_id]
        assert updated[0]["name"] == "Renamed rule"

    def test_missing_filter_ids_returns_400(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.put(BASE, headers=auth_headers, json={"data": {"name": "x"}})
        assert resp.status_code == 400

    def test_unknown_id_returns_404(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.put(
            BASE, headers=auth_headers,
            json={"data": {"name": "x"}, "filter": {"ids": ["999999999999999999"]}},
        )
        assert resp.status_code == 404


def _delete(client: TestClient, auth_headers: dict, body: dict) -> "TestClient":
    """Issue a DELETE with a JSON body (TestClient.delete() does not support json=)."""
    return client.request(
        "DELETE", BASE,
        headers={**auth_headers, "Content-Type": "application/json"},
        content=_json.dumps(body),
    )


class TestDeleteFirewallRules:
    def _create(self, client: TestClient, auth_headers: dict) -> str:
        return client.post(BASE, headers=auth_headers, json={"data": _CREATE_BODY}).json()["data"]["id"]

    def test_returns_affected_count(self, client: TestClient, auth_headers: dict) -> None:
        rule_id = self._create(client, auth_headers)
        body = _delete(client, auth_headers, {"filter": {"ids": [rule_id]}}).json()
        assert body["data"]["affected"] == 1

    def test_deleted_rule_absent_from_list(self, client: TestClient, auth_headers: dict) -> None:
        rule_id = self._create(client, auth_headers)
        _delete(client, auth_headers, {"filter": {"ids": [rule_id]}})
        ids = [r["id"] for r in client.get(BASE, headers=auth_headers).json()["data"]]
        assert rule_id not in ids

    def test_unknown_id_returns_affected_zero(self, client: TestClient, auth_headers: dict) -> None:
        body = _delete(client, auth_headers, {"filter": {"ids": ["999999999999999999"]}}).json()
        assert body["data"]["affected"] == 0

    def test_missing_filter_ids_returns_400(self, client: TestClient, auth_headers: dict) -> None:
        resp = _delete(client, auth_headers, {})
        assert resp.status_code == 400
