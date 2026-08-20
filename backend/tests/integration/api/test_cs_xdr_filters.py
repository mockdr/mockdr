"""CrowdStrike and Cortex XDR request-body handling.

Three defects of the same kind: a request whose meaning the mock did not read
still came back 200. CrowdStrike carries alert changes in ``action_parameters``
and the mock only read a flat shape no real client sends, so a genuine update
changed nothing. XDR's ``filters`` block was read for three fields and
``operator`` was ignored entirely. And FQL stringified array fields, so a query
on ``tags`` could never match.
"""
import hashlib
import secrets
import time

import pytest
from fastapi.testclient import TestClient

CS_PREFIX = "/cs"
XDR_PREFIX = "/xdr/public_api/v1"


@pytest.fixture
def cs_headers(client: TestClient) -> dict[str, str]:
    """Bearer headers for the CrowdStrike mount."""
    resp = client.post(f"{CS_PREFIX}/oauth2/token", data={
        "client_id": "cs-mock-admin-client",
        "client_secret": "cs-mock-admin-secret",
    })
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


def _xdr_headers() -> dict[str, str]:
    nonce = secrets.token_hex(32)
    timestamp = str(int(time.time() * 1000))
    digest = hashlib.sha256(
        ("xdr-admin-secret" + nonce + timestamp).encode(),
    ).hexdigest()
    return {
        "x-xdr-auth-id": "1",
        "x-xdr-nonce": nonce,
        "x-xdr-timestamp": timestamp,
        "Authorization": digest,
    }


class TestCrowdStrikeAlertActions:
    """PATCH /alerts/entities/alerts/v3 reads ``action_parameters``."""

    @staticmethod
    def _first_alert(client: TestClient, headers: dict) -> str:
        return str(client.get(
            f"{CS_PREFIX}/alerts/queries/alerts/v2?limit=1", headers=headers,
        ).json()["resources"][0])

    @staticmethod
    def _detail(client: TestClient, headers: dict, composite_id: str) -> dict:
        return dict(client.post(
            f"{CS_PREFIX}/alerts/entities/alerts/v2",
            json={"composite_ids": [composite_id]}, headers=headers,
        ).json()["resources"][0])

    def _patch(self, client: TestClient, headers: dict, cid: str, *params: dict) -> object:
        return client.patch(
            f"{CS_PREFIX}/alerts/entities/alerts/v3",
            json={"composite_ids": [cid], "action_parameters": list(params)},
            headers=headers,
        )

    def test_update_status_takes_effect(
        self, client: TestClient, cs_headers: dict,
    ) -> None:
        cid = self._first_alert(client, cs_headers)
        resp = self._patch(
            client, cs_headers, cid,
            {"name": "update_status", "value": "in_progress"},
        )

        assert resp.status_code == 200
        assert self._detail(client, cs_headers, cid)["status"] == "in_progress"

    def test_add_and_remove_tag(self, client: TestClient, cs_headers: dict) -> None:
        cid = self._first_alert(client, cs_headers)

        self._patch(client, cs_headers, cid, {"name": "add_tag", "value": "triage"})
        assert "triage" in self._detail(client, cs_headers, cid)["tags"]

        self._patch(client, cs_headers, cid, {"name": "remove_tag", "value": "triage"})
        assert "triage" not in self._detail(client, cs_headers, cid)["tags"]

    def test_assign_and_unassign(self, client: TestClient, cs_headers: dict) -> None:
        cid = self._first_alert(client, cs_headers)

        self._patch(
            client, cs_headers, cid,
            {"name": "assign_to_uuid", "value": "analyst-uuid"},
        )
        assert self._detail(client, cs_headers, cid)["assigned_to_uid"] == "analyst-uuid"

        self._patch(client, cs_headers, cid, {"name": "unassign", "value": ""})
        assert self._detail(client, cs_headers, cid)["assigned_to_uid"] == ""

    def test_unknown_action_is_rejected(
        self, client: TestClient, cs_headers: dict,
    ) -> None:
        cid = self._first_alert(client, cs_headers)
        resp = self._patch(client, cs_headers, cid, {"name": "bogus", "value": "x"})

        # A typo used to be accepted with a 200 that changed nothing.
        assert resp.status_code == 400


class TestCrowdStrikeFqlArrays:
    """FQL matches any member of an array field."""

    def test_tag_query_matches_a_member(
        self, client: TestClient, cs_headers: dict,
    ) -> None:
        cid = str(client.get(
            f"{CS_PREFIX}/alerts/queries/alerts/v2?limit=1", headers=cs_headers,
        ).json()["resources"][0])
        client.patch(
            f"{CS_PREFIX}/alerts/entities/alerts/v3",
            json={
                "composite_ids": [cid],
                "action_parameters": [{"name": "add_tag", "value": "fqlprobe"}],
            },
            headers=cs_headers,
        )

        found = client.get(
            f"{CS_PREFIX}/alerts/queries/alerts/v2",
            params={"filter": "tags:'fqlprobe'", "limit": 100},
            headers=cs_headers,
        ).json()["resources"]

        assert cid in found, "an array field could never match before"

    def test_unmatched_tag_returns_nothing(
        self, client: TestClient, cs_headers: dict,
    ) -> None:
        found = client.get(
            f"{CS_PREFIX}/alerts/queries/alerts/v2",
            params={"filter": "tags:'definitely-not-a-tag'", "limit": 100},
            headers=cs_headers,
        ).json()["resources"]
        assert found == []


class TestXdrAlertFilters:
    """``filters`` honours every documented field and the operator."""

    URL = f"{XDR_PREFIX}/alerts/get_alerts_by_filter_data/"

    def _count(self, client: TestClient, filters: list[dict]) -> int:
        resp = client.post(
            self.URL,
            json={"request_data": {"filters": filters, "search_to": 500}},
            headers=_xdr_headers(),
        )
        assert resp.status_code == 200, resp.text
        return int(resp.json()["reply"]["total_count"])

    def test_unfiltered_returns_everything(self, client: TestClient) -> None:
        assert self._count(client, []) > 0

    @pytest.mark.parametrize(
        "field", ["category", "action", "hostname", "alert_name", "username"],
    )
    def test_previously_ignored_fields_now_filter(
        self, client: TestClient, field: str,
    ) -> None:
        total = self._count(client, [])
        filtered = self._count(
            client, [{"field": field, "operator": "in", "value": ["NO_SUCH_VALUE"]}],
        )

        assert filtered == 0, f"{field} was ignored — it returned all {total}"

    def test_severity_filter_narrows(self, client: TestClient) -> None:
        total = self._count(client, [])
        high = self._count(
            client, [{"field": "severity", "operator": "in", "value": ["high"]}],
        )
        assert 0 < high < total

    def test_neq_is_not_treated_as_equality(self, client: TestClient) -> None:
        total = self._count(client, [])
        equal = self._count(
            client, [{"field": "severity", "operator": "eq", "value": "high"}],
        )
        not_equal = self._count(
            client, [{"field": "severity", "operator": "neq", "value": "high"}],
        )

        assert equal + not_equal == total

    def test_contains_operator(self, client: TestClient) -> None:
        assert self._count(
            client,
            [{"field": "hostname", "operator": "contains", "value": "NO_SUCH_HOST"}],
        ) == 0

    def test_unknown_field_is_rejected(self, client: TestClient) -> None:
        resp = client.post(
            self.URL,
            json={"request_data": {"filters": [
                {"field": "no_such_field", "operator": "in", "value": ["x"]},
            ]}},
            headers=_xdr_headers(),
        )
        assert resp.status_code == 400


class TestXdrScriptIdentifier:
    """Scripts are identified by ``script_uid``."""

    def test_listing_reports_script_uid(self, client: TestClient) -> None:
        scripts = client.post(
            f"{XDR_PREFIX}/scripts/get_scripts/",
            json={"request_data": {}}, headers=_xdr_headers(),
        ).json()["reply"]["scripts"]

        assert scripts
        assert "script_uid" in scripts[0]
        assert "script_id" not in scripts[0]

    def test_metadata_is_addressable_by_script_uid(self, client: TestClient) -> None:
        uid = client.post(
            f"{XDR_PREFIX}/scripts/get_scripts/",
            json={"request_data": {}}, headers=_xdr_headers(),
        ).json()["reply"]["scripts"][0]["script_uid"]

        resp = client.post(
            f"{XDR_PREFIX}/scripts/get_script_metadata/",
            json={"request_data": {"script_uid": uid}}, headers=_xdr_headers(),
        )
        assert resp.status_code == 200
        assert resp.json()["reply"]["script_uid"] == uid
