"""Every SentinelOne write whose swagger body carries ``filter`` applies it.

Two kinds of ``filter`` arrive on a 2.1 write body. On a create it is the
scope the new record is created at (``accountIds``, ``siteIds``,
``groupIds``, ``tenant`` -- the ``*_FilterScopeSchema`` bodies); on a bulk
write it selects the records to act on, with the members the collection's
GET takes. Several routes read neither: the device-control and STAR-rule
DTOs did not declare ``filter`` at all, the exclusions, restrictions and IOC
creates ignored it, and the bulk deletes and ``move-agents`` read ``ids``
alone. Each answered 200 with the scope or the selection silently dropped.
"""
from __future__ import annotations

from fastapi.testclient import TestClient

BASE = "/web/api/v2.1"


def _a_site(client: TestClient, headers: dict) -> dict:
    return client.get(f"{BASE}/sites", headers=headers).json()["data"]["sites"][0]


def _a_group(client: TestClient, headers: dict) -> dict:
    return client.get(f"{BASE}/groups", headers=headers).json()["data"][0]


class TestACreateIsMadeAtTheScopeItsFilterNames:
    def test_device_control(self, client: TestClient, auth_headers: dict) -> None:
        site = _a_site(client, auth_headers)
        resp = client.post(f"{BASE}/device-control", headers=auth_headers, json={
            "data": {"ruleName": "usb-ro", "action": "Block", "interface": "USB",
                     "ruleType": "class", "deviceClass": "08h", "status": "Enabled"},
            "filter": {"siteIds": [site["id"]]},
        })
        assert resp.status_code == 200, resp.text
        rule = resp.json()["data"]
        assert (rule["scope"], rule["scopeId"]) == ("site", site["id"])
        listed = client.get(f"{BASE}/device-control", headers=auth_headers,
                            params={"siteIds": site["id"]}).json()["data"]
        assert rule["id"] in {r["id"] for r in listed}

    def test_star_rule(self, client: TestClient, auth_headers: dict) -> None:
        group = _a_group(client, auth_headers)
        resp = client.post(f"{BASE}/cloud-detection/rules", headers=auth_headers, json={
            "data": {"name": "r1", "s1ql": "EventType = \"Process Creation\"",
                     "queryType": "events", "severity": "Low", "expirationMode": "Permanent",
                     "status": "Active"},
            "filter": {"groupIds": [group["id"]]},
        })
        assert resp.status_code == 200, resp.text
        rule = resp.json()["data"]
        assert rule["scopeLevel"] == "group"
        assert rule["scopeId"] == group["id"]

    def test_firewall_at_an_account(self, client: TestClient, auth_headers: dict) -> None:
        account = client.get(f"{BASE}/accounts", headers=auth_headers).json()["data"][0]
        resp = client.post(f"{BASE}/firewall-control", headers=auth_headers, json={
            "data": {"name": "fw1", "action": "Block", "direction": "inbound",
                     "status": "Enabled"},
            "filter": {"accountIds": [account["id"]]},
        })
        assert resp.status_code == 200, resp.text
        rule = resp.json()["data"]
        assert (rule["scope"], rule["scopeId"]) == ("account", account["id"])

    def test_exclusion(self, client: TestClient, auth_headers: dict) -> None:
        site = _a_site(client, auth_headers)
        resp = client.post(f"{BASE}/exclusions", headers=auth_headers, json={
            "data": {"type": "path", "value": "C:\\\\tools\\\\x.exe", "osType": "windows"},
            "filter": {"siteIds": [site["id"]]},
        })
        assert resp.status_code == 200, resp.text
        assert resp.json()["data"][0]["scope"] == {"siteIds": [site["id"]]}

    def test_restriction(self, client: TestClient, auth_headers: dict) -> None:
        group = _a_group(client, auth_headers)
        resp = client.post(f"{BASE}/restrictions", headers=auth_headers, json={
            "data": {"type": "black_hash", "value": "a" * 40, "osType": "windows"},
            "filter": {"groupIds": [group["id"]]},
        })
        assert resp.status_code == 200, resp.text
        assert resp.json()["data"]["scope"]["groupIds"] == [group["id"]]

    def test_ioc(self, client: TestClient, auth_headers: dict) -> None:
        site = _a_site(client, auth_headers)
        resp = client.post(f"{BASE}/threat-intelligence/iocs", headers=auth_headers, json={
            "data": [{"type": "IPV4", "value": "192.0.2.77", "source": "test"}],
            "filter": {"siteIds": [site["id"]]},
        })
        assert resp.status_code == 200, resp.text
        found = client.get(f"{BASE}/threat-intelligence/iocs", headers=auth_headers,
                           params={"value": "192.0.2.77"}).json()["data"]
        assert [(i["scope"], i["scopeId"]) for i in found] == [("site", site["id"])]


class TestABulkWriteSelectsWhatTheGetWould:
    def test_delete_device_control_by_site(self, client: TestClient, auth_headers: dict) -> None:
        site_id = next(
            site["id"] for site in client.get(f"{BASE}/sites", headers=auth_headers)
            .json()["data"]["sites"]
            if client.get(f"{BASE}/device-control", headers=auth_headers,
                          params={"siteIds": site["id"]}).json()["data"]
        )
        on_site = {r["id"] for r in client.get(f"{BASE}/device-control", headers=auth_headers,
                                                params={"siteIds": site_id}).json()["data"]}
        resp = client.request("DELETE", f"{BASE}/device-control", headers=auth_headers,
                              json={"filter": {"siteIds": [site_id]}})
        assert resp.status_code == 200, resp.text
        assert resp.json()["data"]["affected"] == len(on_site) > 0
        left = {r["id"] for r in client.get(f"{BASE}/device-control",
                                            headers=auth_headers).json()["data"]}
        assert not on_site & left

    def test_move_agents_by_filter(self, client: TestClient, auth_headers: dict) -> None:
        group = _a_group(client, auth_headers)
        agent = client.get(f"{BASE}/agents", headers=auth_headers,
                           params={"limit": 1}).json()["data"][0]
        resp = client.put(f"{BASE}/groups/{group['id']}/move-agents", headers=auth_headers,
                          json={"filter": {"computerName__contains": agent["computerName"]}})
        assert resp.status_code == 200, resp.text
        assert resp.json()["data"]["affected"] >= 1
        (moved,) = client.get(f"{BASE}/agents", headers=auth_headers,
                              params={"ids": agent["id"]}).json()["data"]
        assert moved["groupId"] == group["id"]

    def test_a_member_the_route_cannot_select_on_is_refused(
        self, client: TestClient, auth_headers: dict,
    ) -> None:
        before = len(client.get(f"{BASE}/threat-intelligence/iocs",
                                headers=auth_headers).json()["data"])
        resp = client.request("DELETE", f"{BASE}/threat-intelligence/iocs", headers=auth_headers,
                              json={"filter": {"noSuchMember": "x"}})
        assert resp.status_code == 400
        after = len(client.get(f"{BASE}/threat-intelligence/iocs",
                               headers=auth_headers).json()["data"])
        assert after == before

    def test_a_filter_of_nulls_deletes_nothing(
        self, client: TestClient, auth_headers: dict,
    ) -> None:
        before = len(client.get(f"{BASE}/users", headers=auth_headers).json()["data"])
        resp = client.post(f"{BASE}/users/delete-users", headers=auth_headers,
                           json={"filter": {"ids": None}})
        assert resp.status_code == 400
        assert len(client.get(f"{BASE}/users", headers=auth_headers).json()["data"]) == before
