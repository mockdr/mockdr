"""Kibana's alerting and actions APIs, and the identity behind them.

Every one of these answered 404 here and 200 on a running Kibana 8.15, which
an endpoint sweep found: the alerting framework's health and rule catalogue,
the connectors a rule can act through, the value lists an exception points
at, and the three calls a client makes to find out who and what it is
talking to.

The rule-type catalogue, the task manager's health and the licence are
captured from a running instance rather than written out: a client reads
deep into each — action groups, authorized consumers, drift percentiles,
which features a licence allows — and a hand-written one had arrays where
Kibana has percentile objects and offered features a Basic licence refuses.
"""
import base64

import pytest
from fastapi.testclient import TestClient

from main import app

AUTH = {"Authorization": "Basic " + base64.b64encode(b"elastic:mock-elastic-password").decode()}


@pytest.fixture(scope="module")
def client() -> TestClient:
    """A client against the seeded app."""
    with TestClient(app) as test_client:
        yield test_client


class TestAlerting:
    """The framework the detection engine runs on."""

    def test_the_health_says_it_can_run_rules(self, client: TestClient) -> None:
        body = client.get("/kibana/api/alerting/_health", headers=AUTH).json()
        assert body["is_sufficiently_secure"] is True
        assert body["alerting_framework_health"]["execution_health"]["status"] == "ok"

    def test_the_rule_types_are_the_ones_a_deployment_shows(
        self, client: TestClient,
    ) -> None:
        body = client.get("/kibana/api/alerting/rule_types", headers=AUTH).json()
        ids = {entry["id"] for entry in body}
        assert "siem.queryRule" in ids
        assert ".es-query" in ids

    def test_a_rule_type_carries_its_alerts_mapping(self, client: TestClient) -> None:
        # Stored once in the fixture and put back on the way out, because the
        # nine siem types carry the same one.
        body = client.get("/kibana/api/alerting/rule_types", headers=AUTH).json()
        query_rule = next(e for e in body if e["id"] == "siem.queryRule")
        assert query_rule["alerts"]["mappings"]["fieldMap"]["kibana.alert.rule.uuid"]
        assert query_rule["authorized_consumers"]

    def test_the_rules_a_deployment_holds(self, client: TestClient) -> None:
        body = client.get("/kibana/api/alerting/rules/_find", headers=AUTH,
                          params={"per_page": 1}).json()
        assert body == {"page": 1, "per_page": 1, "total": 0, "data": []}


class TestActions:
    """The connectors a rule acts through."""

    def test_no_connector_is_configured(self, client: TestClient) -> None:
        assert client.get("/kibana/api/actions/connectors", headers=AUTH).json() == []

    def test_the_connector_types_report_their_licence(self, client: TestClient) -> None:
        body = client.get("/kibana/api/actions/connector_types", headers=AUTH).json()
        by_id = {entry["id"]: entry for entry in body}
        # What a client may create depends on the licence, and it reads this
        # to find out: `.email` needs gold, `.index` is basic.
        assert by_id[".email"]["minimum_license_required"] == "gold"
        assert by_id[".email"]["enabled_in_license"] is False
        assert by_id[".index"]["enabled"] is True


class TestIdentityAndHealth:
    """Who the caller is, what the licence allows, and whether tasks run."""

    def test_the_current_user(self, client: TestClient) -> None:
        body = client.get("/kibana/internal/security/me", headers=AUTH).json()
        assert body["username"] == "elastic"
        assert body["roles"] == ["superuser"]
        assert body["authentication_provider"] == {"type": "http", "name": "__http__"}

    def test_the_licence_is_basic_and_says_what_that_allows(
        self, client: TestClient,
    ) -> None:
        body = client.get("/kibana/api/licensing/info", headers=AUTH).json()
        assert body["license"]["type"] == "basic"
        # A Basic licence has no machine learning and no graph, and a client
        # that reads "available" decides what to offer.
        assert body["features"]["ml"]["isAvailable"] is False
        assert body["features"]["security"]["isAvailable"] is True

    def test_the_task_manager_is_running(self, client: TestClient) -> None:
        body = client.get("/kibana/api/task_manager/_health", headers=AUTH).json()
        assert body["status"] == "OK"
        assert body["stats"]["runtime"]["value"]["drift"]["p50"] is not None


class TestValueLists:
    """The lists an exception can point at."""

    def test_the_envelope_pages_the_way_kibana_pages(self, client: TestClient) -> None:
        body = client.get("/kibana/api/lists/_find", headers=AUTH).json()
        assert body == {"data": [], "page": 1, "per_page": 20, "total": 0,
                        "cursor": "WzBd"}


class TestExceptionItemsForAMissingList:
    """The find that used to say a list exists when it does not."""

    def test_a_list_that_is_not_there_is_a_404(self, client: TestClient) -> None:
        response = client.get(
            "/kibana/api/exception_lists/items/_find", headers=AUTH,
            params={"list_id": "no-such-list", "namespace_type": "single"},
        )
        assert response.status_code == 404
        # The Security Solution's envelope, not Boom's.
        assert response.json() == {
            "message": 'exception list id: "no-such-list" does not exist',
            "status_code": 404,
        }

    def test_a_list_that_is_there_still_answers(self, client: TestClient) -> None:
        lists = client.get("/kibana/api/exception_lists/_find", headers=AUTH).json()
        list_id = lists["data"][0]["list_id"]
        response = client.get(
            "/kibana/api/exception_lists/items/_find", headers=AUTH,
            params={"list_id": list_id, "namespace_type": "single"},
        )
        assert response.status_code == 200
        assert response.json()["page"] == 1


class TestTheRestOfThePlatform:
    """What a client calls around the work, all of it 404 before.

    It lists the saved objects and data views to find out what it can
    search, reads Fleet's policies and readiness, and — where it only
    reaches Kibana — talks to Elasticsearch through the console proxy.
    """

    def test_saved_objects_need_a_type(self, client: TestClient) -> None:
        response = client.get("/kibana/api/saved_objects/_find", headers=AUTH)
        assert response.status_code == 400
        assert response.json()["message"] == (
            "[request query.type]: expected at least one defined value but got "
            "[undefined]"
        )

    def test_saved_objects_of_a_type(self, client: TestClient) -> None:
        body = client.get("/kibana/api/saved_objects/_find", headers=AUTH,
                          params={"type": "index-pattern"}).json()
        assert body == {"page": 1, "per_page": 20, "total": 0, "saved_objects": []}

    def test_data_views(self, client: TestClient) -> None:
        assert client.get("/kibana/api/data_views", headers=AUTH).json() == {
            "data_view": [],
        }

    def test_fleet_is_ready_because_mockdr_has_agents(self, client: TestClient) -> None:
        body = client.get("/kibana/api/fleet/agents/setup", headers=AUTH).json()
        assert body["isReady"] is True
        assert body["missing_requirements"] == []

    def test_timelines_and_notes(self, client: TestClient) -> None:
        assert client.get("/kibana/api/timelines", headers=AUTH).json()["totalCount"] == 0
        assert client.get("/kibana/api/note", headers=AUTH).json() == {
            "notes": [], "totalCount": 0,
        }
        # A timeline that is not there is an empty object, not a 404.
        assert client.get("/kibana/api/timeline", headers=AUTH,
                          params={"id": "nope"}).json() == {}

    def test_the_console_proxy_reaches_elasticsearch(self, client: TestClient) -> None:
        response = client.post("/kibana/api/console/proxy", headers=AUTH,
                               params={"path": "/.siem-signals-default/_count",
                                       "method": "GET"})
        assert response.status_code == 200
        # Pretty-printed the way Elasticsearch prints for the console: two
        # spaces, and a space either side of the colon.
        assert '"count" : ' in response.text

    def test_and_relays_what_elasticsearch_said(self, client: TestClient) -> None:
        response = client.post("/kibana/api/console/proxy", headers=AUTH,
                               params={"path": "/no-such-index/_search",
                                       "method": "GET"})
        # The proxy answers 200 whatever Elasticsearch said; the error is in
        # the body (measured).
        assert response.status_code == 200
        assert "index_not_found_exception" in response.text

    def test_the_proxy_needs_a_path(self, client: TestClient) -> None:
        response = client.post("/kibana/api/console/proxy", headers=AUTH,
                               params={"method": "GET"})
        assert response.status_code == 400
        assert "query.path" in response.json()["message"]
