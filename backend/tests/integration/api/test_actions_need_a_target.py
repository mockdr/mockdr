"""An action acts on what it was told to, or on nothing.

Both of these answered success and acted on the whole estate.

`POST /agents/actions/{name}` requires a filter, and then applied only the
seventeen hand-written specs rather than the set the `GET` uses — and
`apply_filters` answers with every record when nothing matches a spec. So an
action scoped by a documented parameter the command did not know, or by a
typo, selected all sixty agents: `approve-uninstall` for sixteen servers
uninstalled everything and answered `{"affected": 60}`.

Cortex's `update_agent_name` and `endpoint_tags/add` called
`select_endpoints` with no guard at all, and that answers with every endpoint
when it is handed no filters — right for a listing, catastrophic for a write.
`endpoints_named_by` beside them has the guard both were missing.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

BASE = "/web/api/v2.1"
XDR = "/xdr/public_api/v1"


def _xdr(client: TestClient) -> dict:
    return {"x-xdr-auth-id": "1", "Authorization": "xdr-admin-secret"}


class TestASentinelOneActionSelectsWhatTheListWouldSelect:
    def test_a_documented_filter_selects_the_same_set(
        self, client: TestClient, auth_headers: dict,
    ) -> None:
        listed = client.get(
            f"{BASE}/agents", headers=auth_headers,
            params={"machineTypes": "server", "limit": "200"},
        ).json()["data"]
        assert 0 < len(listed) < 60, "the seed cannot tell a subset from the whole"

        response = client.post(
            f"{BASE}/agents/actions/disconnect", headers=auth_headers,
            json={"filter": {"machineTypes": ["server"]}},
        )
        assert response.status_code == 200, response.text
        assert response.json()["data"]["affected"] == len(listed)

    @pytest.mark.parametrize("member", ["zzzTypo", "computerNameZ"])
    def test_a_filter_it_cannot_apply_is_refused(
        self, client: TestClient, auth_headers: dict, member: str,
    ) -> None:
        """Not ignored — ignoring it selected every agent there is."""
        response = client.post(
            f"{BASE}/agents/actions/disconnect", headers=auth_headers,
            json={"filter": {member: ["anything"]}},
        )
        assert response.status_code == 400, response.text
        assert member in response.json()["errors"][0]["detail"]


class TestACortexWriteNeedsATarget:
    def test_a_rename_with_no_target_renames_nothing(self, client: TestClient) -> None:
        before = client.post(
            f"{XDR}/endpoints/get_endpoint/", headers=_xdr(client),
            json={"request_data": {}},
        )
        assert before.status_code == 200, before.text

        client.post(
            f"{XDR}/endpoints/update_agent_name/", headers=_xdr(client),
            json={"request_data": {"alias": "zzz-should-not-happen"}},
        )
        after = client.post(
            f"{XDR}/endpoints/get_endpoint/", headers=_xdr(client),
            json={"request_data": {}},
        ).json()
        assert "zzz-should-not-happen" not in str(after)

    def test_a_rename_that_names_one_still_works(self, client: TestClient) -> None:
        listing = client.post(
            f"{XDR}/endpoints/get_endpoint/", headers=_xdr(client),
            json={"request_data": {}},
        ).json()["reply"]
        rows = listing if isinstance(listing, list) else listing.get("endpoints", [])
        assert rows, "no endpoint to rename"
        target = rows[0]["endpoint_id"]
        assert target

        response = client.post(
            f"{XDR}/endpoints/update_agent_name/", headers=_xdr(client),
            json={"request_data": {"endpoint_id_list": [target], "alias": "zzz-renamed"}},
        )
        assert response.status_code == 200, response.text

    def test_tagging_with_no_target_tags_nothing(self, client: TestClient) -> None:
        client.post(
            f"{XDR}/endpoints/endpoint_tags/add/", headers=_xdr(client),
            json={"request_data": {"tag": "zzz-should-not-happen"}},
        )
        listing = client.post(
            f"{XDR}/endpoints/get_endpoint/", headers=_xdr(client),
            json={"request_data": {}},
        ).json()
        assert "zzz-should-not-happen" not in str(listing)
