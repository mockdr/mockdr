"""A Splunk body is read the way splunklib sends it: a form that names no type.

``splunklib.binding.HttpLib.post`` encodes its keyword arguments as
``key=value&...`` and adds ``Content-Type: application/x-www-form-urlencoded``
only when the caller passes an explicit ``body=``. ``login()``,
``jobs.create()``, ``Entity.update()``, ``saved_searches.create()`` -- almost
every call the SDK makes -- sends the form with no ``Content-Type`` at all,
and splunkd reads it as a form. Starlette reads a form only when the header
says so, so the SDK's first request, the login, reached the route with no
username and no password and was refused ``400 Login failed``.

The requests below carry exactly what splunklib puts on the wire: the
encoded body, and no content type.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

import main


@pytest.fixture()
def raw() -> TestClient:
    """A client that adds nothing -- no output_mode, no content type."""
    return TestClient(main.app)


def _post(raw: TestClient, path: str, body: str, **headers: str):  # type: ignore[no-untyped-def]
    # httpx sends `content=` bytes as they are, with no Content-Type.
    return raw.post(path, content=body.encode(), headers=headers)


def _session(raw: TestClient) -> dict[str, str]:
    response = _post(raw, "/splunk/services/auth/login",
                     "username=admin&password=mockdr-admin&cookie=1")
    assert response.status_code == 200, response.text
    key = response.text.split("<sessionKey>")[1].split("</sessionKey>")[0]
    return {"Authorization": f"Splunk {key}"}


class TestATypelessBodyIsAForm:
    """splunklib's untyped bodies reach the routes as the forms they are."""

    def test_login_reads_the_credentials(self, raw: TestClient) -> None:
        response = _post(raw, "/splunk/services/auth/login",
                         "username=admin&password=mockdr-admin&cookie=1")
        assert response.status_code == 200, response.text
        assert "<sessionKey>" in response.text

    def test_a_wrong_password_is_still_401(self, raw: TestClient) -> None:
        response = _post(raw, "/splunk/services/auth/login",
                         "username=admin&password=nope&cookie=1")
        assert response.status_code == 401

    def test_jobs_create_reads_the_search(self, raw: TestClient) -> None:
        response = _post(raw, "/splunk/servicesNS/nobody/search/search/v2/jobs",
                         "search=search+index%3D%2A+%7C+head+3&output_mode=json",
                         **_session(raw))
        assert response.status_code == 201, response.text
        assert response.json()["sid"]

    def test_a_typed_body_is_left_as_it_is(self, raw: TestClient) -> None:
        """A JSON body that says it is JSON is not turned into a form."""
        response = raw.post("/splunk/services/collector/event",
                            headers={"Authorization": "Splunk 33333333-3333-3333-3333-333333333333"},
                            json={"event": "hello"})
        assert response.status_code == 200, response.text


class TestJobReadersTakeTheirArgumentsFromTheBody:
    """Search API v2 reads a job with POST; its paging arrives in the body.

    splunklib's ``Job.results()``, ``Job.preview()`` and ``Job.events()``
    post ``count``, ``offset``, ``segmentation`` and ``output_mode`` as form
    fields to ``search/v2/jobs/{sid}/<reader>`` (``self.post("results",
    **query_params)``), and splunkd reads an argument from the body as from
    the query string. The routes read only the query string, so the POSTed
    ``offset`` was ignored: a client paging with the SDK got the first page
    back for every offset and never reached the end.
    """

    @staticmethod
    def _job(raw: TestClient, auth: dict[str, str]) -> str:
        response = _post(raw, "/splunk/services/search/v2/jobs",
                         "search=search+index%3D%2A+%7C+head+25&exec_mode=blocking&output_mode=json",
                         **auth)
        assert response.status_code == 201, response.text
        return str(response.json()["sid"])

    @pytest.mark.parametrize("reader", ["results", "results_preview", "events"])
    def test_offset_and_count_in_the_body_page(self, raw: TestClient, reader: str) -> None:
        auth = _session(raw)
        sid = self._job(raw, auth)
        path = f"/splunk/servicesNS/nobody/search/search/v2/jobs/{sid}/{reader}"

        def page(offset: int) -> list[dict]:
            response = _post(raw, path,
                             f"segmentation=none&count=10&offset={offset}&output_mode=json",
                             **auth)
            assert response.status_code == 200, response.text
            return list(response.json()["results"])

        job = raw.get(f"/splunk/services/search/v2/jobs/{sid}?output_mode=json",
                      headers=auth).json()["entry"][0]["content"]
        total = int(job["eventCount"] if reader == "events" else job["resultCount"])

        seen: list[dict] = []
        offset = 0
        while chunk := page(offset):
            assert len(chunk) <= 10
            seen += chunk
            offset += len(chunk)
            assert offset <= total, "paging never ended"
        assert len(seen) == total > 10

    def test_the_query_string_wins_where_both_name_one(self, raw: TestClient) -> None:
        auth = _session(raw)
        sid = self._job(raw, auth)
        response = _post(raw, f"/splunk/services/search/v2/jobs/{sid}/results?count=3",
                         "count=10&output_mode=json", **auth)
        assert response.status_code == 200, response.text
        assert len(response.json()["results"]) == 3
