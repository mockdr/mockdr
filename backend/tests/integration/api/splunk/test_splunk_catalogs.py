"""The read-only catalogues splunkd serves beside its data.

An endpoint sweep against 10.4.2 found every one of these answering 404
here. Where mockdr has the thing it serves it — an index per index, a source
type per sourcetype its events carry, the `notable` macro its own SPL
understands — and where it has none it serves an *empty collection*, which
is the difference between "this deployment has none" and "this endpoint
does not exist".

Each entry's content is filled out from a recording of the real collection,
because a client reads deep into these: an extended index carries a hundred
and nineteen settings.
"""
import base64

import pytest
from fastapi.testclient import TestClient

from main import app

AUTH = {"Authorization": "Basic " + base64.b64encode(b"admin:mockdr-admin").decode()}
JSON = {"output_mode": "json"}


@pytest.fixture(scope="module")
def client() -> TestClient:
    """A client against the seeded app."""
    with TestClient(app) as test_client:
        yield test_client


class TestHealthAndLicence:
    """What a client checks before it trusts the instance."""

    def test_the_health_tree_is_green(self, client: TestClient) -> None:
        body = client.get("/splunk/services/server/health/splunkd", headers=AUTH,
                          params=JSON).json()
        assert body["entry"][0]["content"]["health"] == "green"

    def test_the_licence_is_valid(self, client: TestClient) -> None:
        body = client.get("/splunk/services/licenser/licenses", headers=AUTH,
                          params=JSON).json()
        content = body["entry"][0]["content"]
        assert content["status"] == "VALID"
        # And it carries the settings a client reads to decide what it may
        # ask for: the quota, the features, the roles.
        assert "quota" in content
        assert "features" in content

    def test_the_capabilities_a_role_may_hand_on(self, client: TestClient) -> None:
        body = client.get("/splunk/services/authorization/grantable_capabilities",
                          headers=AUTH, params=JSON).json()
        assert body["entry"][0]["content"]["capabilities"]


class TestIndexesExtended:
    """The index list with the detail an app reads sizes from."""

    def test_every_index_is_listed(self, client: TestClient) -> None:
        plain = client.get("/splunk/services/data/indexes", headers=AUTH,
                           params={**JSON, "count": 0}).json()
        extended = client.get("/splunk/services/data/indexes-extended", headers=AUTH,
                              params={**JSON, "count": 0}).json()
        assert len(extended["entry"]) == len(plain["entry"])

    def test_the_numbers_are_strings(self, client: TestClient) -> None:
        # Every number in an index entry is a string there, which is what a
        # client parsing `currentDBSizeMB` has to cope with.
        body = client.get("/splunk/services/data/indexes-extended", headers=AUTH,
                          params={**JSON, "count": 1}).json()
        assert isinstance(body["entry"][0]["content"]["currentDBSizeMB"], str)

    def test_an_index_counts_its_own_events(self, client: TestClient) -> None:
        body = client.get("/splunk/services/data/indexes-extended", headers=AUTH,
                          params={**JSON, "count": 0}).json()
        counts = {e["name"]: e["content"]["totalEventCount"] for e in body["entry"]}
        assert any(count > 0 for count in counts.values())


class TestKnowledgeObjects:
    """Macros, source types, and the collections with nothing in them."""

    def test_the_notable_macro_is_defined(self, client: TestClient) -> None:
        body = client.get("/splunk/servicesNS/nobody/search/admin/macros",
                          headers=AUTH, params=JSON).json()
        macros = {e["name"]: e["content"]["definition"] for e in body["entry"]}
        assert macros["notable"] == "search index=notable"

    def test_a_macro_can_be_shared(self, client: TestClient) -> None:
        # A knowledge object carries four more acl members than a system
        # entry, because it can be shared.
        body = client.get("/splunk/servicesNS/nobody/search/admin/macros",
                          headers=AUTH, params=JSON).json()
        acl = body["entry"][0]["acl"]
        assert acl["can_share_app"] is True
        assert acl["can_change_perms"] is True

    def test_a_source_type_per_sourcetype_the_events_carry(
        self, client: TestClient,
    ) -> None:
        body = client.get("/splunk/services/saved/sourcetypes", headers=AUTH,
                          params={**JSON, "count": 0}).json()
        names = {entry["name"] for entry in body["entry"]}
        assert names
        # And each carries the parsing settings a client reads.
        assert "KV_MODE" in body["entry"][0]["content"]

    @pytest.mark.parametrize("path", [
        "/splunk/services/saved/eventtypes",
        "/splunk/services/data/transforms/lookups",
        "/splunk/services/data/lookup-table-files",
        "/splunk/services/data/inputs/monitor",
        "/splunk/services/data/inputs/tcp/raw",
        "/splunk/services/data/props/extractions",
    ])
    def test_a_collection_with_nothing_in_it_is_still_a_collection(
        self, client: TestClient, path: str,
    ) -> None:
        response = client.get(path, headers=AUTH, params=JSON)
        assert response.status_code == 200
        body = response.json()
        assert body["entry"] == []
        # The links a knowledge-object collection offers, even when empty.
        assert set(body["links"]) == {"_acl", "_reload", "create"}
