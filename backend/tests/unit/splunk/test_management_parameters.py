"""What splunkd's management API takes in a query, and how it refuses the rest.

Measured against Splunk 10.4.2 across nine collections and ten queries each.
mockdr accepted a sort direction it does not sort by, an output mode it
cannot render, and any argument at all — three ways of telling a client its
parameter worked when in production it will not.
"""
import base64

import pytest
from fastapi.testclient import TestClient

from main import app

AUTH = {"Authorization": "Basic " + base64.b64encode(b"admin:mockdr-admin").decode()}


@pytest.fixture(scope="module")
def client() -> TestClient:
    """A client against the seeded app."""
    with TestClient(app) as test_client:
        yield test_client


def message(response: object) -> str:
    """The text of the one message a refusal carries."""
    return response.json()["messages"][0]["text"]


class TestOutputMode:
    """The mode is checked before anything else, and always answers in XML."""

    def test_a_mode_splunkd_does_not_know(self, client: TestClient) -> None:
        response = client.get(
            "/splunk/services/saved/searches", headers=AUTH,
            params={"output_mode": "nonsense"},
        )
        assert response.status_code == 400
        assert "Invalid output mode specified (nonsense)." in response.text
        # XML even though nothing said so: the mode it would answer in is the
        # thing it could not read.
        assert response.headers["content-type"].startswith("text/xml")

    def test_an_empty_mode_is_no_mode(self, client: TestClient) -> None:
        response = client.get(
            "/splunk/services/saved/searches", headers=AUTH, params={"output_mode": ""},
        )
        assert response.status_code == 400
        assert "Invalid output mode specified ()." in response.text

    @pytest.mark.parametrize("mode", ["csv", "atom", "raw"])
    def test_a_mode_it_knows_but_will_not_serve_here(
        self, client: TestClient, mode: str,
    ) -> None:
        response = client.get(
            "/splunk/services/saved/searches", headers=AUTH,
            params={"output_mode": mode},
        )
        assert response.status_code == 400
        assert f"Output mode '{mode}' is not supported for this endpoint." in response.text

    @pytest.mark.parametrize("mode", ["json", "xml"])
    def test_the_two_it_renders(self, client: TestClient, mode: str) -> None:
        response = client.get(
            "/splunk/services/saved/searches", headers=AUTH,
            params={"output_mode": mode, "count": 1},
        )
        assert response.status_code == 200


class TestSortDirection:
    """A collection sorts one way or the other."""

    def test_a_direction_it_does_not_sort_by(self, client: TestClient) -> None:
        response = client.get(
            "/splunk/services/data/indexes", headers=AUTH,
            params={"output_mode": "json", "sort_dir": "x"},
        )
        assert response.status_code == 400
        assert message(response) == 'Unknown sort order "x".'

    @pytest.mark.parametrize("direction", ["asc", "desc"])
    def test_the_two_it_does(self, client: TestClient, direction: str) -> None:
        response = client.get(
            "/splunk/services/data/indexes", headers=AUTH,
            params={"output_mode": "json", "sort_dir": direction, "count": 1},
        )
        assert response.status_code == 200

    def test_the_job_collection_pairs_them_instead(self, client: TestClient) -> None:
        # It sorts on several keys at once, so it counts them rather than
        # checking the direction against an enum.
        response = client.get(
            "/splunk/services/search/jobs", headers=AUTH,
            params={"output_mode": "json", "sort_dir": "asc"},
        )
        assert response.status_code == 400
        assert response.json()["messages"][0] == {
            "type": "FATAL",
            "text": "Number of sort_key and sort_dir arguments do not match.",
        }

    def test_a_matched_pair_runs(self, client: TestClient) -> None:
        response = client.get(
            "/splunk/services/search/jobs", headers=AUTH,
            params={"output_mode": "json", "sort_key": "name", "sort_dir": "asc"},
        )
        assert response.status_code == 200


class TestUnknownArguments:
    """splunkd names an argument its handler does not declare."""

    @pytest.mark.parametrize("path", [
        "/splunk/services/saved/searches",
        "/splunk/services/data/indexes",
        "/splunk/services/apps/local",
        "/splunk/services/authentication/users",
        "/splunk/services/authorization/roles",
        "/splunk/services/server/info",
        "/splunk/services/messages",
    ])
    def test_a_collection_refuses_it(self, client: TestClient, path: str) -> None:
        response = client.get(
            path, headers=AUTH, params={"output_mode": "json", "nosuch": "1"},
        )
        assert response.status_code == 400
        assert message(response) == 'Argument "nosuch" is not supported by this handler.'

    @pytest.mark.parametrize("path", [
        "/splunk/services/search/jobs",
        "/splunk/services/data/inputs/http",
    ])
    def test_the_handlers_that_take_anything(self, client: TestClient, path: str) -> None:
        # These have dispatchers of their own and do not refuse (measured).
        response = client.get(
            path, headers=AUTH, params={"output_mode": "json", "nosuch": "1"},
        )
        assert response.status_code == 200

    @pytest.mark.parametrize("argument", [
        "count", "offset", "search", "sort_key", "sort_mode", "f", "add_orphan_field",
    ])
    def test_the_arguments_a_collection_declares(
        self, client: TestClient, argument: str,
    ) -> None:
        response = client.get(
            "/splunk/services/saved/searches", headers=AUTH,
            params={"output_mode": "json", argument: "1"},
        )
        assert response.status_code == 200
