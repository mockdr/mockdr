"""What the vendor marks required inside `data`, this mock requires.

`documented_body.py` demanded that a write body carry *something* the route
takes, and stopped there — deliberately, because the top-level `required` is
`data, filter` on almost every SentinelOne action while this mock accepts
the flat form too, and which combination the product wants is not something
the swagger states.

Inside `data` it states it exactly, and fifty-one such members were
documented and unenforced. `POST /threats/analyst-verdict` requires
`data.analystVerdict`; without it the mock answered `{"affected": 1}` and
left every verdict where it was — reporting work it had not done. A user was
created with no e-mail address, a note with no text, a site with no name,
each answering with an id as though the record it described had been made.

Fifty-three are enforced now. The twelve left are the top-level `filter`,
which the guard still leaves loose for the reason above — and those routes
answer `affected: 0`, so they act on nothing rather than on everything.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

BASE = "/web/api/v2.1"
ADMIN = {"Authorization": "ApiToken admin-token-0000-0000-000000000001"}
SOC = {"Authorization": "ApiToken soc-analyst-token-000-000000000003"}
VIEWER = {"Authorization": "ApiToken viewer-token-0000-0000-000000000002"}


def _a_threat(client: TestClient) -> str:
    return str(client.get(f"{BASE}/threats", headers=ADMIN,
                          params={"limit": 1}).json()["data"][0]["id"])


#: (route, the complete `data`, the member to leave out)
INCOMPLETE = [
    ("/threats/analyst-verdict", {"analystVerdict": "true_positive"}, "analystVerdict"),
    ("/threats/incident", {"incidentStatus": "resolved"}, "incidentStatus"),
    ("/threats/notes", {"text": "a note"}, "text"),
    ("/threats/add-to-blacklist", {"targetScope": "site"}, "targetScope"),
]


class TestAMissingMemberIsRefused:
    @pytest.mark.parametrize(("route", "data", "missing"), INCOMPLETE)
    def test_it_is_a_400_naming_the_member(
        self, client: TestClient, route: str, data: dict, missing: str,
    ) -> None:
        without = {k: v for k, v in data.items() if k != missing}
        resp = client.post(f"{BASE}{route}", headers=ADMIN,
                           json={"filter": {"ids": [_a_threat(client)]},
                                 "data": without})
        assert resp.status_code == 400, resp.text
        assert resp.json()["errors"][0]["detail"] == f"data.{missing} is required"

    @pytest.mark.parametrize(("route", "data", "missing"), INCOMPLETE)
    def test_the_complete_body_still_works(
        self, client: TestClient, route: str, data: dict, missing: str,
    ) -> None:
        resp = client.post(f"{BASE}{route}", headers=ADMIN,
                           json={"filter": {"ids": [_a_threat(client)]}, "data": data})
        assert resp.status_code == 200, resp.text


class TestItReportsNoWorkItDidNotDo:
    def test_a_verdict_with_no_verdict_no_longer_claims_one(
        self, client: TestClient,
    ) -> None:
        """It answered `affected: 1` and changed nothing at all."""
        tid = _a_threat(client)
        before = client.get(f"{BASE}/threats", headers=ADMIN, params={"ids": tid}
                            ).json()["data"][0]["threatInfo"]["analystVerdict"]
        resp = client.post(f"{BASE}/threats/analyst-verdict", headers=ADMIN,
                           json={"filter": {"ids": [tid]}, "data": {}})
        assert resp.status_code == 400
        after = client.get(f"{BASE}/threats", headers=ADMIN, params={"ids": tid}
                           ).json()["data"][0]["threatInfo"]["analystVerdict"]
        assert after == before

    def test_the_member_is_the_one_the_swagger_names(
        self, client: TestClient,
    ) -> None:
        """`verdict` is not `analystVerdict`, and used to be accepted."""
        tid = _a_threat(client)
        resp = client.post(f"{BASE}/threats/analyst-verdict", headers=ADMIN,
                           json={"filter": {"ids": [tid]},
                                 "data": {"verdict": "true_positive"}})
        assert resp.status_code == 400
        assert resp.json()["errors"][0]["detail"] == "data.analystVerdict is required"


class TestAuthorisationStillComesFirst:
    """A caller who may not write must not learn what the body wanted.

    The roles come off each route's own permission dependency, because they
    differ: `POST /users` admits an Admin alone, `POST
    /threats/analyst-verdict` admits a SOC Analyst as well. A single guess
    for both refused one of them in the wrong words.
    """

    def test_a_viewer_hears_403_not_400(self, client: TestClient) -> None:
        resp = client.post(f"{BASE}/threats/analyst-verdict", headers=VIEWER,
                           json={"filter": {"ids": [_a_threat(client)]}, "data": {}})
        assert resp.status_code == 403

    def test_a_soc_analyst_hears_403_from_an_admin_only_route(
        self, client: TestClient,
    ) -> None:
        resp = client.post(f"{BASE}/users", headers=SOC,
                           json={"data": {"email": "x@x.test"}})
        assert resp.status_code == 403

    def test_a_soc_analyst_hears_400_where_it_may_write(
        self, client: TestClient,
    ) -> None:
        resp = client.post(f"{BASE}/threats/analyst-verdict", headers=SOC,
                           json={"filter": {"ids": [_a_threat(client)]}, "data": {}})
        assert resp.status_code == 400
        assert resp.json()["errors"][0]["detail"] == "data.analystVerdict is required"


class TestTheLoosenessThatStays:
    def test_the_top_level_filter_is_still_not_demanded(
        self, client: TestClient,
    ) -> None:
        """It acts on nothing rather than on everything, which is the point."""
        resp = client.post(f"{BASE}/threats/analyst-verdict", headers=ADMIN,
                           json={"data": {"analystVerdict": "false_positive"}})
        assert resp.status_code == 200
        assert resp.json()["data"]["affected"] == 0

    def test_a_route_with_no_documented_payload_is_left_alone(
        self, client: TestClient,
    ) -> None:
        site_id = client.get(f"{BASE}/sites", headers=ADMIN
                             ).json()["data"]["sites"][0]["id"]
        assert client.put(f"{BASE}/sites/{site_id}/reactivate",
                          headers=ADMIN).status_code == 200
