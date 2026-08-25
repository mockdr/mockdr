"""Parameters the routes declared and then ignored.

A parameter a route *declares*, answers 200 for, and does nothing with is
the quietest defect a mock can have: the client sees a plausible page,
believes it filtered, and gets something else in production. Twelve of them
were found by asking every route, for every parameter, whether the answer
changes when the parameter cannot match — `scripts/param_effect.py`.

Graph took `$select` on eleven routes and `$filter` on three and dropped
both; SentinelOne declared two filters it never applied; Sentinel's threat
intelligence query read three of eight documented criteria; and the Splunk
KV store's delete ignored its query and emptied the whole collection.
"""
import base64
import json

import pytest
from fastapi.testclient import TestClient

WEB_AUTH = {"Authorization": "ApiToken admin-token-0000-0000-000000000001"}
SPLUNK_AUTH = {"Authorization": "Basic " + base64.b64encode(b"admin:mockdr-admin").decode()}


@pytest.fixture
def graph_headers(client: TestClient) -> dict:
    """An application token for the Graph mount."""
    token = client.post("/graph/oauth2/v2.0/token", data={
        "grant_type": "client_credentials",
        "client_id": "graph-mock-admin-client",
        "client_secret": "graph-mock-admin-secret",
        "scope": "https://graph.microsoft.com/.default",
    }).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def cs_headers(client: TestClient) -> dict:
    """An OAuth token for the Falcon mount."""
    token = client.post("/cs/oauth2/token", data={
        "grant_type": "client_credentials",
        "client_id": "cs-mock-admin-client",
        "client_secret": "cs-mock-admin-secret",
    }).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def sentinel_headers(client: TestClient) -> dict:
    """An ARM token for the Sentinel mount."""
    token = client.post("/sentinel/oauth2/v2.0/token", data={
        "grant_type": "client_credentials",
        "client_id": "sentinel-mock-client-id",
        "client_secret": "sentinel-mock-client-secret",
        "scope": "https://management.azure.com/.default",
    }).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


class TestGraphSelect:
    """``$select`` projects; it did nothing on eleven routes."""

    @pytest.mark.parametrize("path", [
        "/graph/v1.0/security/alerts_v2",
        "/graph/v1.0/security/incidents",
        "/graph/v1.0/deviceManagement/detectedApps",
        "/graph/v1.0/identity/conditionalAccess/policies",
        "/graph/beta/reports/authenticationMethods/userRegistrationDetails",
    ])
    def test_a_collection_returns_only_what_was_asked_for(
        self, client: TestClient, graph_headers: dict, path: str,
    ) -> None:
        body = client.get(path, headers=graph_headers, params={"$select": "id"}).json()
        assert body["value"], "nothing to project"
        for item in body["value"]:
            assert set(item) - {"id"} == set(), f"{path} returned {sorted(item)}"

    def test_a_single_resource_is_projected_too(
        self, client: TestClient, graph_headers: dict,
    ) -> None:
        listing = client.get("/graph/v1.0/deviceManagement/managedDevices",
                             headers=graph_headers).json()["value"]
        device_id = listing[0]["id"]
        body = client.get(f"/graph/v1.0/deviceManagement/managedDevices/{device_id}",
                          headers=graph_headers,
                          params={"$select": "id,deviceName"}).json()
        assert set(body) <= {"id", "deviceName"}

    def test_the_odata_annotations_survive_the_projection(
        self, client: TestClient, graph_headers: dict,
    ) -> None:
        # They describe the answer, not the resource.
        body = client.get("/graph/v1.0/security/alerts_v2", headers=graph_headers,
                          params={"$select": "id"}).json()
        assert "@odata.context" in body


class TestGraphFilterAndOrder:
    """The three routes that took ``$filter`` and dropped it."""

    @pytest.mark.parametrize("path", [
        "/graph/v1.0/deviceManagement/detectedApps",
        "/graph/v1.0/identity/conditionalAccess/policies",
    ])
    def test_a_filter_that_cannot_match_returns_nothing(
        self, client: TestClient, graph_headers: dict, path: str,
    ) -> None:
        body = client.get(path, headers=graph_headers,
                          params={"$filter": "id eq 'zzz-no-such-id'"}).json()
        assert body["value"] == []

    def test_a_filter_that_matches_returns_that_one(
        self, client: TestClient, graph_headers: dict,
    ) -> None:
        apps = client.get("/graph/v1.0/deviceManagement/detectedApps",
                          headers=graph_headers).json()["value"]
        wanted = apps[0]["id"]
        body = client.get("/graph/v1.0/deviceManagement/detectedApps",
                          headers=graph_headers,
                          params={"$filter": f"id eq '{wanted}'"}).json()
        assert [a["id"] for a in body["value"]] == [wanted]

    def test_orderby_sorts_the_alerts(
        self, client: TestClient, graph_headers: dict,
    ) -> None:
        ascending = client.get("/graph/v1.0/security/alerts_v2", headers=graph_headers,
                               params={"$orderby": "createdDateTime"}).json()["value"]
        descending = client.get("/graph/v1.0/security/alerts_v2", headers=graph_headers,
                                params={"$orderby": "createdDateTime desc"}).json()["value"]
        stamps = [a["createdDateTime"] for a in ascending]
        assert stamps == sorted(stamps)
        assert [a["createdDateTime"] for a in descending] == sorted(stamps, reverse=True)

    def test_member_of_pages_and_projects(
        self, client: TestClient, graph_headers: dict,
    ) -> None:
        users = client.get("/graph/v1.0/users", headers=graph_headers).json()["value"]
        user_id = users[0]["id"]
        body = client.get(f"/graph/v1.0/users/{user_id}/memberOf", headers=graph_headers,
                          params={"$top": 1}).json()
        assert len(body["value"]) <= 1


class TestFalconFilters:
    """An expression that is not FQL is a 400, not the whole collection."""

    @pytest.mark.parametrize("path", [
        "/cs/devices/combined/host-groups/v1",
        "/cs/discover/combined/applications/v1",
        "/cs/iocs/combined/indicator/v1",
    ])
    def test_a_filter_that_is_not_fql_is_refused(
        self, client: TestClient, cs_headers: dict, path: str,
    ) -> None:
        response = client.get(path, headers=cs_headers, params={"filter": "zzz"})
        assert response.status_code == 400
        error = response.json()["errors"][0]
        assert error["code"] == 400
        assert "invalid filter expression" in error["message"]

    def test_a_filter_that_is_fql_still_filters(
        self, client: TestClient, cs_headers: dict,
    ) -> None:
        response = client.get("/cs/devices/combined/host-groups/v1", headers=cs_headers,
                              params={"filter": "name:'zzz-no-such-group'"})
        assert response.status_code == 200
        assert response.json()["resources"] == []


class TestSentinelOneFilters:
    """Two filters declared on the route and matched against nothing."""

    def test_installed_applications_filters_by_id(self, client: TestClient) -> None:
        listing = client.get("/web/api/v2.1/installed-applications",
                             headers=WEB_AUTH).json()["data"]
        wanted = listing[0]["id"]
        body = client.get("/web/api/v2.1/installed-applications", headers=WEB_AUTH,
                          params={"ids": wanted}).json()
        assert [a["id"] for a in body["data"]] == [wanted]

    def test_device_control_filters_by_account(self, client: TestClient) -> None:
        body = client.get("/web/api/v2.1/device-control", headers=WEB_AUTH,
                          params={"accountIds": "zzz-no-such-account"}).json()
        assert body["data"] == []


class TestSentinelIndicatorQuery:
    """Five of the eight documented criteria were read and dropped."""

    def query(self, client: TestClient, headers: dict, body: dict) -> list[dict]:
        url = ("/sentinel/subscriptions/00000000-0000-0000-0000-000000000000"
               "/resourceGroups/mockdr-rg/providers/Microsoft.OperationalInsights"
               "/workspaces/mockdr-workspace/providers/Microsoft.SecurityInsights"
               "/threatIntelligence/main/queryIndicators")
        return client.post(url, headers=headers, params={"api-version": "2024-03-01"},
                           json=body).json()["value"]

    def test_page_size_limits(self, client: TestClient, sentinel_headers: dict) -> None:
        assert len(self.query(client, sentinel_headers, {"pageSize": 1})) == 1

    def test_confidence_bounds_narrow(
        self, client: TestClient, sentinel_headers: dict,
    ) -> None:
        assert self.query(client, sentinel_headers,
                          {"minConfidence": 101, "maxConfidence": 200}) == []

    def test_ids_select_one(self, client: TestClient, sentinel_headers: dict) -> None:
        every = self.query(client, sentinel_headers, {})
        wanted = every[0]["name"]
        assert [i["name"] for i in self.query(
            client, sentinel_headers, {"ids": [wanted]},
        )] == [wanted]

    def test_sort_by_orders(self, client: TestClient, sentinel_headers: dict) -> None:
        ascending = self.query(client, sentinel_headers, {
            "sortBy": [{"itemKey": "confidence", "sortOrder": "ascending"}],
        })
        descending = self.query(client, sentinel_headers, {
            "sortBy": [{"itemKey": "confidence", "sortOrder": "descending"}],
        })
        values = [i["properties"]["confidence"] for i in ascending]
        assert values == sorted(values)
        assert [i["properties"]["confidence"] for i in descending] == sorted(
            values, reverse=True,
        )

    def test_unsorted_leaves_the_order_alone(
        self, client: TestClient, sentinel_headers: dict,
    ) -> None:
        plain = self.query(client, sentinel_headers, {})
        unsorted = self.query(client, sentinel_headers, {
            "sortBy": [{"itemKey": "confidence", "sortOrder": "unsorted"}],
        })
        assert [i["name"] for i in unsorted] == [i["name"] for i in plain]


class TestKvStoreDeleteQuery:
    """The delete that emptied the collection whatever it was asked."""

    def collection(self, client: TestClient, name: str) -> str:
        base = "/splunk/servicesNS/nobody/search/storage/collections"
        client.post(f"{base}/config", headers=SPLUNK_AUTH, data={"name": name})
        for i in range(4):
            client.post(f"{base}/data/{name}", headers=SPLUNK_AUTH,
                        json={"_key": f"k{i}", "n": i})
        return f"{base}/data/{name}"

    def test_a_query_deletes_only_what_it_matches(self, client: TestClient) -> None:
        url = self.collection(client, "param_probe_one")
        response = client.delete(url, headers=SPLUNK_AUTH,
                                 params={"query": json.dumps({"n": {"$lt": 2}})})
        assert response.status_code == 200
        left = client.get(url, headers=SPLUNK_AUTH).json()
        assert sorted(r["n"] for r in left) == [2, 3]

    def test_no_query_still_deletes_everything(self, client: TestClient) -> None:
        url = self.collection(client, "param_probe_two")
        client.delete(url, headers=SPLUNK_AUTH)
        assert client.get(url, headers=SPLUNK_AUTH).json() == []

    def test_a_query_that_matches_nothing_deletes_nothing(
        self, client: TestClient,
    ) -> None:
        url = self.collection(client, "param_probe_three")
        client.delete(url, headers=SPLUNK_AUTH,
                      params={"query": json.dumps({"n": 99})})
        assert len(client.get(url, headers=SPLUNK_AUTH).json()) == 4


class TestPagingWalks:
    """Paging a collection has to return it exactly once.

    A mock that pages wrongly looks right in each single answer — the shape
    is fine and the count is plausible — and only a client that reads to the
    end sees a record twice, or never at all. `scripts/paging_audit.py`
    walks every collection two pages at a time and checks the whole set came
    back; these pin what it found.
    """

    def test_installed_applications_hands_back_a_cursor(
        self, client: TestClient,
    ) -> None:
        first = client.get("/web/api/v2.1/installed-applications", headers=WEB_AUTH,
                           params={"limit": 2}).json()
        # The swagger declares both members; mockdr answered with the page's
        # own length as the total and no cursor at all, so a client saw one
        # page and was told that was everything.
        assert first["pagination"]["totalItems"] > 2
        assert first["pagination"]["nextCursor"]

    def test_and_the_cursor_leads_to_the_next_page(self, client: TestClient) -> None:
        first = client.get("/web/api/v2.1/installed-applications", headers=WEB_AUTH,
                           params={"limit": 2}).json()
        second = client.get(
            "/web/api/v2.1/installed-applications", headers=WEB_AUTH,
            params={"limit": 2, "cursor": first["pagination"]["nextCursor"]},
        ).json()
        assert {a["id"] for a in first["data"]} & {a["id"] for a in second["data"]} == set()

    def test_the_whole_collection_comes_back_exactly_once(
        self, client: TestClient,
    ) -> None:
        whole = client.get("/web/api/v2.1/installed-applications", headers=WEB_AUTH,
                           params={"limit": 1000}).json()["data"]
        seen: list[str] = []
        cursor = None
        for _page in range(60):
            params = {"limit": 20, **({"cursor": cursor} if cursor else {})}
            body = client.get("/web/api/v2.1/installed-applications", headers=WEB_AUTH,
                              params=params).json()
            seen.extend(a["id"] for a in body["data"])
            cursor = body["pagination"]["nextCursor"]
            if not cursor:
                break
        assert len(seen) == len(set(seen)), "an application came back twice"
        assert set(seen) == {a["id"] for a in whole}


class TestEndpointMetadataEnvelope:
    """The Kibana endpoint list echoes what it was asked."""

    KBN = {"Authorization": "Basic " + base64.b64encode(
        b"elastic:mock-elastic-password").decode(), "kbn-xsrf": "true"}

    def test_the_page_comes_back_as_it_was_asked_for(self, client: TestClient) -> None:
        # It counts from 0, and mockdr answered with the number after it — so
        # a client paging by the echoed value skipped every other page.
        for page in (0, 1, 2):
            body = client.get("/kibana/api/endpoint/metadata", headers=self.KBN,
                              params={"page": page, "pageSize": 2}).json()
            assert body["page"] == page

    def test_the_sort_is_echoed_and_applied(self, client: TestClient) -> None:
        body = client.get("/kibana/api/endpoint/metadata", headers=self.KBN, params={
            "sortField": "metadata.host.hostname", "sortDirection": "asc", "pageSize": 5,
        }).json()
        assert body["sortField"] == "metadata.host.hostname"
        assert body["sortDirection"] == "asc"
        names = [d["metadata"]["host"]["hostname"] for d in body["data"]]
        assert names == sorted(names)

    def test_the_default_sort_is_the_one_kibana_uses(self, client: TestClient) -> None:
        body = client.get("/kibana/api/endpoint/metadata", headers=self.KBN,
                          params={"pageSize": 1}).json()
        assert (body["sortField"], body["sortDirection"]) == ("enrolled_at", "desc")

    def test_paging_returns_the_whole_list_once(self, client: TestClient) -> None:
        whole = client.get("/kibana/api/endpoint/metadata", headers=self.KBN,
                           params={"pageSize": 1000}).json()
        seen: list[str] = []
        for page in range(0, 30):
            body = client.get("/kibana/api/endpoint/metadata", headers=self.KBN,
                              params={"page": page, "pageSize": 5}).json()
            if not body["data"]:
                break
            seen.extend(d["metadata"]["agent"]["id"] for d in body["data"])
        assert len(seen) == whole["total"]
        assert len(set(seen)) == len(seen)
