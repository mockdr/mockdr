"""A documented body member a route accepts must change the record.

`body_audit.py` asks whether a write route *reads* its body — whether it
refuses `{}` and an undeclared member. It does not ask whether the members
it accepts are applied, and those are different questions: every route here
refused an empty body and then dropped what it was sent.

`PUT /tenant/policy` was the widest. The swagger documents 51 members and
the record carried 8, and `update_policy` sets what the record has, so a
client turning on anti-tampering — or any of 43 other settings — was
answered `200`, and read back the value it had before. Three creates dropped
eight more between them: `inject` and `pathExclusionType` on an exclusion,
`rank` and `isDefault` on a group, `allowRemoteShell` and the scoped roles
on a user.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

BASE = "/web/api/v2.1"


def _policy(client: TestClient, headers: dict) -> dict:
    response = client.get(f"{BASE}/tenant/policy", headers=headers)
    assert response.status_code == 200, response.text
    return response.json()["data"]


class TestAPolicySettingSticks:
    @pytest.mark.parametrize(
        ("member", "value"),
        [
            ("antiTamperingOn", True),
            ("snapshotsOn", True),
            ("networkQuarantineOn", True),
            ("autoDecommissionDays", 42),
            ("autoMitigationAction", "quarantine"),
            ("identityEndpointReporting", "enabled"),
        ],
    )
    def test_a_documented_setting_reads_back_changed(
        self, client: TestClient, auth_headers: dict, member: str, value: object,
    ) -> None:
        before = _policy(client, auth_headers)[member]
        assert before != value, f"{member} already equals {value!r}; the test proves nothing"
        response = client.put(
            f"{BASE}/tenant/policy", headers=auth_headers, json={"data": {member: value}},
        )
        assert response.status_code == 200, response.text
        assert response.json()["data"][member] == value
        assert _policy(client, auth_headers)[member] == value

    def test_a_nested_setting_still_completes(
        self, client: TestClient, auth_headers: dict,
    ) -> None:
        """An empty object is filled from the fixture, as `engines` always was."""
        assert len(_policy(client, auth_headers)["iocAttributes"]) > 1

    @pytest.mark.parametrize("member", ["createdAt", "updatedAt", "userId", "userFullName"])
    def test_the_server_owned_members_refuse_the_body(
        self, client: TestClient, auth_headers: dict, member: str,
    ) -> None:
        """The swagger lists them beside the settings; they are not the caller's."""
        before = _policy(client, auth_headers)[member]
        client.put(
            f"{BASE}/tenant/policy", headers=auth_headers,
            json={"data": {member: "zzz-not-yours"}},
        )
        assert _policy(client, auth_headers)[member] != "zzz-not-yours"
        if member != "updatedAt":  # the update moves it, by design
            assert _policy(client, auth_headers)[member] == before

    def test_the_policy_names_an_author_a_client_can_look_up(
        self, client: TestClient, auth_headers: dict,
    ) -> None:
        users = {
            u["id"] for u in
            client.get(f"{BASE}/users", headers=auth_headers,
                       params={"limit": "100"}).json()["data"]
        }
        assert _policy(client, auth_headers)["userId"] in users

    def test_the_policy_was_not_made_in_2018(
        self, client: TestClient, auth_headers: dict,
    ) -> None:
        assert _policy(client, auth_headers)["createdAt"] != "2018-02-27T04:49:26.257525Z"


class TestACreateKeepsWhatItWasSent:
    @pytest.mark.parametrize(
        ("path", "body", "members"),
        [
            (
                "/exclusions",
                {"type": "path", "value": "/zzz/probe", "osType": "windows",
                 "inject": True, "pathExclusionType": "subfolders", "actions": ["detect"]},
                ("inject", "pathExclusionType", "actions"),
            ),
            (
                "/groups",
                {"name": "zzz-probe-group", "rank": 7, "isDefault": True},
                ("rank", "isDefault"),
            ),
            (
                "/users",
                {"fullName": "zzz Probe", "email": "zzz-probe@example.test",
                 "allowRemoteShell": True, "siteRoles": [{"id": "1"}]},
                ("allowRemoteShell", "siteRoles"),
            ),
        ],
    )
    def test_each_documented_member_comes_back_as_sent(
        self, client: TestClient, auth_headers: dict,
        path: str, body: dict, members: tuple[str, ...],
    ) -> None:
        response = client.post(f"{BASE}{path}", headers=auth_headers, json={"data": body})
        assert response.status_code in (200, 201), response.text
        record = response.json()["data"]
        if isinstance(record, list):
            record = record[0]
        for member in members:
            assert record[member] == body[member], (
                f"{path} answered {member}={record[member]!r} for {body[member]!r}"
            )


class TestAnUpdateKeepsWhatItWasSent:
    """The creates were fixed first; the updates dropped the same members."""

    def _one(self, client: TestClient, headers: dict, path: str, key: str = "data") -> dict:
        body = client.get(f"{BASE}{path}", headers=headers, params={"limit": "1"}).json()[key]
        if isinstance(body, dict):
            body = next(v for v in body.values() if isinstance(v, list))
        return body[0]

    def test_a_group_can_be_reranked(self, client: TestClient, auth_headers: dict) -> None:
        group = self._one(client, auth_headers, "/groups")
        response = client.put(
            f"{BASE}/groups/{group['id']}", headers=auth_headers,
            json={"data": {"rank": 9, "isDefault": True}},
        )
        assert response.status_code == 200, response.text
        after = client.get(
            f"{BASE}/groups", headers=auth_headers, params={"ids": group["id"]},
        ).json()["data"][0]
        assert after["rank"] == 9
        assert after["isDefault"] is True

    def test_a_users_remote_shell_can_be_granted(
        self, client: TestClient, auth_headers: dict,
    ) -> None:
        user = self._one(client, auth_headers, "/users")
        response = client.put(
            f"{BASE}/users/{user['id']}", headers=auth_headers,
            json={"data": {"allowRemoteShell": True}},
        )
        assert response.status_code == 200, response.text
        assert response.json()["data"]["allowRemoteShell"] is True

    def test_an_accounts_billing_can_be_changed(
        self, client: TestClient, auth_headers: dict,
    ) -> None:
        account = self._one(client, auth_headers, "/accounts")
        response = client.put(
            f"{BASE}/accounts/{account['id']}", headers=auth_headers,
            json={"data": {"billingMode": "consumption", "usageType": "mssp"}},
        )
        assert response.status_code == 200, response.text
        after = response.json()["data"]
        assert after["billingMode"] == "consumption"
        assert after["usageType"] == "mssp"


class TestReactivateHonoursTheExpirationItIsGiven:
    """`unlimited` and `expiration` are the two members this body documents.

    The route took no body at all and always cleared the expiration — the
    opposite of what the members are for. `unlimited`'s own description reads
    "if false an expiration should be supplied".
    """

    def _site(self, client: TestClient, headers: dict) -> dict:
        return client.get(
            f"{BASE}/sites", headers=headers, params={"limit": "1"},
        ).json()["data"]["sites"][0]

    def test_an_expiration_is_kept(self, client: TestClient, auth_headers: dict) -> None:
        site = self._site(client, auth_headers)
        response = client.put(
            f"{BASE}/sites/{site['id']}/reactivate", headers=auth_headers,
            json={"data": {"unlimited": False, "expiration": "2027-06-01T00:00:00.000000Z"}},
        )
        assert response.status_code == 200, response.text
        after = response.json()["data"]
        assert after["state"] == "active"
        assert after["expiration"] == "2027-06-01T00:00:00.000000Z"

    def test_unlimited_clears_it(self, client: TestClient, auth_headers: dict) -> None:
        site = self._site(client, auth_headers)
        response = client.put(
            f"{BASE}/sites/{site['id']}/reactivate", headers=auth_headers,
            json={"data": {"unlimited": True}},
        )
        assert response.status_code == 200, response.text
        assert response.json()["data"]["expiration"] is None

    def test_a_bodyless_call_still_works(self, client: TestClient, auth_headers: dict) -> None:
        """Every client here has always called it that way, and the swagger
        does not mark the body required — only `data` inside one that is sent."""
        site = self._site(client, auth_headers)
        response = client.put(f"{BASE}/sites/{site['id']}/reactivate", headers=auth_headers)
        assert response.status_code == 200, response.text
        assert response.json()["data"]["state"] == "active"
