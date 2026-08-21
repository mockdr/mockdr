"""HEC query-string authentication, measured against Splunk 10.4.2.

mockdr accepted ``?token=`` unconditionally. Real splunkd reads the parameter
but only honours it when ``inputs.conf`` sets ``allowQueryStringAuth``, which
is off by default — so a client that worked here would have been rejected by
a stock indexer, which is the direction of error a mock must never take.

The expectations below are transcribed from probes against a real Splunk
10.4.2 instance, not from the documentation:

    allowQueryStringAuth unset (default)
      no token          401 {"text": "Token is required", "code": 2}
      ?token= invalid   403 {"text": "Invalid token", "code": 4}
      ?token= valid     400 {"text": "Query string authorization is not enabled", "code": 16}
      header  valid     200 {"text": "Success", "code": 0}

    allowQueryStringAuth = true
      ?token= valid     200 {"text": "Success", "code": 0}

Note the ordering, which is not the obvious one: the token is validated
*before* the channel is checked, so an invalid token sent by query string is
a 403 rather than the 400 — only a valid token ever reaches the 400.
"""
import pytest
from fastapi.testclient import TestClient

SEEDED_TOKEN = "11111111-1111-1111-1111-111111111111"
BOGUS_TOKEN = "00000000-0000-0000-0000-000000000000"
COLLECTOR = "/splunk/services/collector"


@pytest.fixture
def query_auth(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> bool:
    """Set mockdr's mirror of ``allowQueryStringAuth``."""
    from api import splunk_auth

    enabled = bool(request.param)
    monkeypatch.setattr(splunk_auth, "SPLUNK_HEC_QUERY_STRING_AUTH", enabled)
    return enabled


def _code(response: object) -> int | None:
    body = response.json()  # type: ignore[attr-defined]
    if "code" in body:
        return int(body["code"])
    detail = body.get("detail")
    return int(detail["code"]) if isinstance(detail, dict) and "code" in detail else None


class TestQueryStringAuthDisabledByDefault:
    """splunkd's default, and therefore mockdr's."""

    @pytest.mark.parametrize("query_auth", [False], indirect=True)
    def test_a_valid_token_by_query_string_is_refused(
        self, client: TestClient, query_auth: bool,
    ) -> None:
        resp = client.post(
            COLLECTOR, params={"token": SEEDED_TOKEN}, json={"event": "probe"},
        )
        assert resp.status_code == 400
        assert _code(resp) == 16

    @pytest.mark.parametrize("query_auth", [False], indirect=True)
    def test_an_invalid_token_is_a_403_not_the_400(
        self, client: TestClient, query_auth: bool,
    ) -> None:
        """The token is validated before the channel is."""
        resp = client.post(
            COLLECTOR, params={"token": BOGUS_TOKEN}, json={"event": "probe"},
        )
        assert resp.status_code == 403
        assert _code(resp) == 4

    @pytest.mark.parametrize("query_auth", [False], indirect=True)
    def test_the_header_still_works(self, client: TestClient, query_auth: bool) -> None:
        resp = client.post(
            COLLECTOR, headers={"Authorization": f"Splunk {SEEDED_TOKEN}"},
            json={"event": "probe"},
        )
        assert resp.status_code == 200
        assert _code(resp) == 0

    @pytest.mark.parametrize("query_auth", [False], indirect=True)
    def test_no_token_at_all(self, client: TestClient, query_auth: bool) -> None:
        resp = client.post(COLLECTOR, json={"event": "probe"})
        assert resp.status_code == 401
        assert _code(resp) == 2


class TestQueryStringAuthEnabled:
    """What an operator gets after setting the flag."""

    @pytest.mark.parametrize("query_auth", [True], indirect=True)
    def test_a_valid_token_by_query_string_is_accepted(
        self, client: TestClient, query_auth: bool,
    ) -> None:
        resp = client.post(
            COLLECTOR, params={"token": SEEDED_TOKEN}, json={"event": "probe"},
        )
        assert resp.status_code == 200
        assert _code(resp) == 0

    @pytest.mark.parametrize("query_auth", [True], indirect=True)
    def test_an_invalid_token_is_still_refused(
        self, client: TestClient, query_auth: bool,
    ) -> None:
        resp = client.post(
            COLLECTOR, params={"token": BOGUS_TOKEN}, json={"event": "probe"},
        )
        assert resp.status_code == 403
        assert _code(resp) == 4

    @pytest.mark.parametrize("query_auth", [True], indirect=True)
    def test_no_token_is_still_a_401(
        self, client: TestClient, query_auth: bool,
    ) -> None:
        resp = client.post(COLLECTOR, json={"event": "probe"})
        assert resp.status_code == 401
        assert _code(resp) == 2
