"""A request carrying ``Connection: close`` is answered with it.

RFC 9112 §9.6: a server that receives the ``close`` option "SHOULD send a
"close" connection option in its final response on that connection".
uvicorn's h11 protocol does; its httptools protocol -- the one
``uvicorn[standard]`` installs, so the one the Dockerfile, ``start.sh`` and
the GitHub Action all run -- closes the connection without saying so.

splunklib, the Splunk SDK, sends ``Connection: Close`` on every request and
decides from the answer's ``Connection`` header whether it may keep the
socket (``splunklib/binding.py``, ``handler``): anything but ``keep-alive``
closes the connection straight after ``getresponse()``. An HTTP/1.1 answer
with no header is persistent to ``http.client``, so closing the connection
closed the response too, and splunklib read an empty body from every call --
``splunklib.client.connect()`` died parsing an empty login answer as XML.
TestClient never runs a protocol implementation, so what is held here is the
header the app now sends itself.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

import main


@pytest.fixture()
def raw() -> TestClient:
    return TestClient(main.app)


class TestCloseIsEchoed:
    """The option comes back on every mount, success or refusal."""

    @pytest.mark.parametrize(("method", "path", "kwargs"), [
        ("POST", "/splunk/services/auth/login",
         {"data": {"username": "admin", "password": "mockdr-admin"}}),
        ("GET", "/splunk/services/server/info", {}),
        ("GET", "/web/api/v2.1/system/status", {}),
        ("GET", "/elastic/", {}),
        ("GET", "/no/such/route", {}),
    ])
    def test_close_is_answered_with_close(
        self, raw: TestClient, method: str, path: str, kwargs: dict,
    ) -> None:
        response = raw.request(method, path, headers={"Connection": "Close"}, **kwargs)
        assert response.headers.get("connection") == "close"

    def test_close_among_other_options(self, raw: TestClient) -> None:
        response = raw.get("/web/api/v2.1/system/status",
                           headers={"Connection": "TE, close"})
        assert response.headers.get("connection") == "close"


class TestNothingAddedOtherwise:
    """A request that did not ask to close is not told the connection closes."""

    def test_keep_alive_gets_no_close(self, raw: TestClient) -> None:
        response = raw.get("/web/api/v2.1/system/status",
                           headers={"Connection": "keep-alive"})
        assert "close" not in response.headers.get("connection", "")
