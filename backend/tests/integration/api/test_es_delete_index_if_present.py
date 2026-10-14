"""Deleting a missing index with ``ignore_unavailable=true`` is acknowledged.

The Delete index API: "ignore_unavailable (Optional, Boolean) If false, the
request returns an error if it targets a missing or closed index. Defaults
to false." elasticsearch-py's ``es.indices.delete(index=...,
ignore_unavailable=True)`` -- the idiom a test set-up opens with, to start
from a clean index -- sends ``DELETE /<index>?ignore_unavailable=true``. The
mock accepted the parameter and never read it, so on a clean cluster the
call raised ``NotFoundError`` and the set-up died before it began.

The requests are the client's: its compatibility media type, its query.
"""
from __future__ import annotations

import base64

from fastapi.testclient import TestClient

HEADERS = {
    "Authorization": "Basic " + base64.b64encode(b"elastic:mock-elastic-password").decode(),
    "Accept": "application/vnd.elasticsearch+json; compatible-with=8",
}


class TestIgnoreUnavailable:
    """The flag turns a missing index from a 404 into an acknowledgement."""

    def test_a_missing_index_is_acknowledged(self, client: TestClient) -> None:
        response = client.delete("/elastic/never-created?ignore_unavailable=true",
                                 headers=HEADERS)
        assert response.status_code == 200, response.text
        assert response.json() == {"acknowledged": True}

    def test_without_it_a_missing_index_is_still_404(self, client: TestClient) -> None:
        response = client.delete("/elastic/never-created", headers=HEADERS)
        assert response.status_code == 404
        assert response.json()["error"]["type"] == "index_not_found_exception"

    def test_false_is_false(self, client: TestClient) -> None:
        response = client.delete("/elastic/never-created?ignore_unavailable=false",
                                 headers=HEADERS)
        assert response.status_code == 404

    def test_an_index_that_exists_is_deleted_either_way(self, client: TestClient) -> None:
        client.put("/elastic/sdk-smoke/_doc/1?refresh=true", headers=HEADERS, json={"n": 1})
        response = client.delete("/elastic/sdk-smoke?ignore_unavailable=true", headers=HEADERS)
        assert response.status_code == 200
        assert client.get("/elastic/sdk-smoke/_doc/1", headers=HEADERS).status_code == 404
