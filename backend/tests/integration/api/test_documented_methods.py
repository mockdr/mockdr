"""The methods the 2.1 swagger documents on paths this mock already served.

`scripts/param_drift.py` compared the parameters of operations both sides
describe, and could not see an operation only one side has: six documented
calls landed on a path mockdr serves with other verbs and were answered 405.
Five of them are how a real client writes — SentinelOne updates an exclusion
and a blocklist entry by body, not by a path of its own, and deletes rules
and tags by filter — so a SOAR integration doing the ordinary thing got a
405 from a route that was, on paper, implemented.

Each case here is the swagger's own contract: what `data` must carry, what a
missing member does, and what the answer looks like.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

BASE = "/web/api/v2.1"


def _first(client: TestClient, headers: dict, path: str) -> dict:
    body = client.get(f"{BASE}{path}", headers=headers).json()
    assert body["data"], f"nothing seeded at {path}"
    return dict(body["data"][0])


class TestExclusionsAreUpdatedByBody:
    """`PUT /exclusions`: `data.id` names the record, and the reply is a list."""

    def test_the_change_is_kept(self, client: TestClient, auth_headers: dict) -> None:
        existing = _first(client, auth_headers, "/exclusions")
        resp = client.put(
            f"{BASE}/exclusions",
            headers=auth_headers,
            json={"data": {
                "id": existing["id"],
                "osType": existing["osType"],
                "type": existing["type"],
                "description": "changed by the documented call",
            }},
        )
        assert resp.status_code == 200
        # exclusions.schemas_ExclusionSchema_many_200 — a list, not a single.
        assert resp.json()["data"][0]["description"] == "changed by the documented call"

        after = client.get(
            f"{BASE}/exclusions", headers=auth_headers, params={"ids": existing["id"]},
        ).json()["data"][0]
        assert after["description"] == "changed by the documented call"

    def test_an_id_nobody_has_is_a_404(
        self, client: TestClient, auth_headers: dict,
    ) -> None:
        resp = client.put(
            f"{BASE}/exclusions",
            headers=auth_headers,
            json={"data": {"id": "1", "osType": "windows", "type": "path"}},
        )
        assert resp.status_code == 404

    def test_a_body_missing_a_required_member_is_a_400(
        self, client: TestClient, auth_headers: dict,
    ) -> None:
        """The swagger requires `id`, `osType` and `type` inside `data`."""
        resp = client.put(
            f"{BASE}/exclusions",
            headers=auth_headers,
            json={"data": {"osType": "windows", "type": "path"}},
        )
        assert resp.status_code == 400


class TestRestrictionsAreUpdatedByBody:
    """`PUT /restrictions`, the same contract over the hash blocklist."""

    def test_the_change_is_kept(self, client: TestClient, auth_headers: dict) -> None:
        existing = _first(client, auth_headers, "/restrictions")
        resp = client.put(
            f"{BASE}/restrictions",
            headers=auth_headers,
            json={"data": {
                "id": existing["id"],
                "osType": existing["osType"],
                "type": existing["type"],
                "description": "blocked for a stated reason",
            }},
        )
        assert resp.status_code == 200
        assert resp.json()["data"][0]["description"] == "blocked for a stated reason"

        after = client.get(f"{BASE}/restrictions", headers=auth_headers).json()["data"]
        changed = [r for r in after if r["id"] == existing["id"]][0]
        assert changed["description"] == "blocked for a stated reason"

    def test_an_id_nobody_has_is_a_404(
        self, client: TestClient, auth_headers: dict,
    ) -> None:
        resp = client.put(
            f"{BASE}/restrictions",
            headers=auth_headers,
            json={"data": {"id": "1", "osType": "windows", "type": "black_hash"}},
        )
        assert resp.status_code == 404


class TestRulesAreDeletedByFilter:
    """`DELETE /cloud-detection/rules`: the body describes which rules."""

    def test_only_the_described_rules_go(
        self, client: TestClient, auth_headers: dict,
    ) -> None:
        rules = client.get(f"{BASE}/cloud-detection/rules", headers=auth_headers).json()["data"]
        severity = rules[0]["severity"]
        doomed = [r for r in rules if r["severity"] == severity]

        resp = client.request(
            "DELETE", f"{BASE}/cloud-detection/rules",
            headers=auth_headers, json={"filter": {"severities": [severity]}},
        )
        assert resp.status_code == 200
        assert resp.json()["data"]["affected"] == len(doomed)

        left = client.get(f"{BASE}/cloud-detection/rules", headers=auth_headers).json()["data"]
        assert len(left) == len(rules) - len(doomed)
        assert all(r["severity"] != severity for r in left)

    def test_an_empty_filter_deletes_nothing(
        self, client: TestClient, auth_headers: dict,
    ) -> None:
        """An empty filter describes every rule there is — refused, not obeyed."""
        before = client.get(f"{BASE}/cloud-detection/rules", headers=auth_headers).json()["data"]
        resp = client.request(
            "DELETE", f"{BASE}/cloud-detection/rules", headers=auth_headers, json={"filter": {}},
        )
        assert resp.status_code == 400
        after = client.get(f"{BASE}/cloud-detection/rules", headers=auth_headers).json()["data"]
        assert len(after) == len(before)

    def test_a_filter_this_install_cannot_answer_is_refused(
        self, client: TestClient, auth_headers: dict,
    ) -> None:
        """Deleting a wider set than the one asked for is the failure to avoid."""
        resp = client.request(
            "DELETE", f"{BASE}/cloud-detection/rules",
            headers=auth_headers, json={"filter": {"reachedLimit": True}},
        )
        assert resp.status_code == 400


class TestTagsAreDeletedByFilter:
    """`DELETE /tag-manager`: by id, by free text, or by scope."""

    @staticmethod
    def _tags(client: TestClient, headers: dict) -> list[dict]:
        created = client.post(
            f"{BASE}/tag-manager", headers=headers,
            json={"data": {
                "key": "Retire", "value": "Now", "type": "agents",
                "description": "for the delete test",
            }},
        )
        assert created.status_code == 200
        return [created.json()["data"]]

    def test_a_named_tag_goes(self, client: TestClient, auth_headers: dict) -> None:
        tag = self._tags(client, auth_headers)[0]
        resp = client.request(
            "DELETE", f"{BASE}/tag-manager",
            headers=auth_headers, json={"filter": {"tagIds": [tag["id"]]}},
        )
        assert resp.status_code == 200
        assert resp.json()["data"]["affected"] == 1

    def test_free_text_selects_by_key_value_and_description(
        self, client: TestClient, auth_headers: dict,
    ) -> None:
        self._tags(client, auth_headers)
        resp = client.request(
            "DELETE", f"{BASE}/tag-manager",
            headers=auth_headers, json={"filter": {"query": "for the delete test"}},
        )
        assert resp.status_code == 200
        assert resp.json()["data"]["affected"] == 1

    def test_an_empty_filter_deletes_nothing(
        self, client: TestClient, auth_headers: dict,
    ) -> None:
        resp = client.request(
            "DELETE", f"{BASE}/tag-manager", headers=auth_headers, json={"filter": {}},
        )
        assert resp.status_code == 400


class TestTheAccountPolicyIsSetWhereItIsRead:
    """`PUT /accounts/{id}/policy`, beside the GET that was already there."""

    def test_the_change_is_answered_back(
        self, client: TestClient, auth_headers: dict,
    ) -> None:
        account = client.get(f"{BASE}/accounts", headers=auth_headers).json()["data"][0]["id"]
        resp = client.put(
            f"{BASE}/accounts/{account}/policy",
            headers=auth_headers, json={"data": {"mitigationMode": "protect"}},
        )
        assert resp.status_code == 200
        assert resp.json()["data"]["mitigationMode"] == "protect"

    def test_an_account_nobody_has_is_a_404(
        self, client: TestClient, auth_headers: dict,
    ) -> None:
        """As on the GET: confirming a change against an account that does
        not exist is the worst way to say no."""
        resp = client.put(
            f"{BASE}/accounts/999999999999999999/policy",
            headers=auth_headers, json={"data": {"mitigationMode": "protect"}},
        )
        assert resp.status_code == 404


class TestTheConsoleConfigurationIsSettable:
    """`PUT /system/configuration`, whose GET answered blanks nothing could set."""

    def test_a_setting_survives_to_the_next_read(
        self, client: TestClient, auth_headers: dict,
    ) -> None:
        resp = client.put(
            f"{BASE}/system/configuration",
            headers=auth_headers,
            json={
                "data": {"advancedMode": True, "accessibleUrl": "https://console.acmecorp"},
                "filter": {"tenant": True},
            },
        )
        assert resp.status_code == 200
        assert resp.json()["data"]["advancedMode"] is True

        after = client.get(f"{BASE}/system/configuration", headers=auth_headers).json()["data"]
        assert after["advancedMode"] is True
        assert after["accessibleUrl"] == "https://console.acmecorp"

    def test_the_scope_is_required(self, client: TestClient, auth_headers: dict) -> None:
        """The swagger requires `data` and `filter` both: a change with no
        scope is a malformed request, not a change applied everywhere."""
        resp = client.put(
            f"{BASE}/system/configuration",
            headers=auth_headers, json={"data": {"advancedMode": True}},
        )
        assert resp.status_code == 400

    def test_a_setting_this_console_does_not_have_is_refused(
        self, client: TestClient, auth_headers: dict,
    ) -> None:
        resp = client.put(
            f"{BASE}/system/configuration",
            headers=auth_headers,
            json={"data": {"logLevel": "debug"}, "filter": {"tenant": True}},
        )
        assert resp.status_code == 400

    def test_a_read_only_caller_cannot_set_it(
        self, client: TestClient, viewer_headers: dict,
    ) -> None:
        resp = client.put(
            f"{BASE}/system/configuration",
            headers=viewer_headers,
            json={"data": {"advancedMode": True}, "filter": {"tenant": True}},
        )
        assert resp.status_code == 403


class TestAMachineIsChangedWhereItIsRead:
    """`PATCH /api/machines/{id}`, the MDE call beside the GET and the actions.

    The same sweep over the Defender documentation found one method answered
    405 on a path this mock already serves: the one that changes the machine
    itself. MDE documents `machineTags` and `deviceValue` on it and answers
    the updated machine back.
    """

    @staticmethod
    def _auth(client: TestClient) -> dict:
        token = client.post("/mde/oauth2/v2.0/token", data={
            "client_id": "mde-mock-admin-client",
            "client_secret": "mde-mock-admin-secret",
            "grant_type": "client_credentials",
            "scope": "https://api.securitycenter.microsoft.com/.default",
        }).json()["access_token"]
        return {"Authorization": f"Bearer {token}"}

    def _machine(self, client: TestClient, headers: dict) -> str:
        return str(client.get("/mde/api/machines", headers=headers).json()["value"][0]["id"])

    def test_the_change_is_there_on_the_next_read(self, client: TestClient) -> None:
        headers = self._auth(client)
        machine = self._machine(client, headers)
        resp = client.patch(
            f"/mde/api/machines/{machine}",
            headers=headers,
            json={"machineTags": ["crown-jewel"], "deviceValue": "High"},
        )
        assert resp.status_code == 200
        assert resp.json()["machineTags"] == ["crown-jewel"]
        assert resp.json()["deviceValue"] == "High"

        after = client.get(f"/mde/api/machines/{machine}", headers=headers).json()
        assert after["machineTags"] == ["crown-jewel"]
        assert after["deviceValue"] == "High"

    def test_a_device_value_mde_does_not_have_is_refused(
        self, client: TestClient,
    ) -> None:
        headers = self._auth(client)
        machine = self._machine(client, headers)
        resp = client.patch(
            f"/mde/api/machines/{machine}", headers=headers, json={"deviceValue": "Critical"},
        )
        assert resp.status_code == 400

    def test_tags_have_to_be_a_list(self, client: TestClient) -> None:
        headers = self._auth(client)
        machine = self._machine(client, headers)
        resp = client.patch(
            f"/mde/api/machines/{machine}", headers=headers, json={"machineTags": "one"},
        )
        assert resp.status_code == 400

    def test_a_machine_nobody_has_is_a_404(self, client: TestClient) -> None:
        headers = self._auth(client)
        resp = client.patch(
            "/mde/api/machines/00000000-0000-0000-0000-000000000000",
            headers=headers, json={"deviceValue": "Low"},
        )
        assert resp.status_code == 404
