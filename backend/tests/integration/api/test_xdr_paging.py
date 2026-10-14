"""Cortex pages with `search_from`/`search_to`, and some routes have a ceiling.

Two defects:

- `search_to` was used as given, so a client asking for 0..1000 incidents
  received a thousand where Cortex answers at most 100 — incidents: "0 <
  search_size <= 100" (Palo Alto LIVEcommunity, get_incidents), endpoints:
  XSOAR CoreIRApiModule `get_endpoints_command` pages "with the max limit
  supported by the API (100)". A client whose paging loop is wrong passed
  against the mock and failed against the product.
- A `search_from` that is not an integer — `"0"`, a float, an object — reached
  a list slice and answered a plain 500.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from tests.integration.api.test_xdr_misc import XDR_PREFIX, _xdr_headers

#: Every route that pages with `search_from`/`search_to`.
PAGED = [
    ("/incidents/get_incidents/", "incidents"),
    ("/incidents/get_multiple_incidents_extra_data/", "incidents"),
    ("/endpoints/get_endpoint/", "endpoints"),
    ("/alerts/get_alerts_by_filter_data/", "alerts"),
    ("/alerts/get_alerts_multi_events/", "alerts"),
    ("/scripts/get_scripts/", "scripts"),
    ("/audits/management_logs/", "data"),
    ("/audits/agents_reports/", "data"),
]


def _post(client: TestClient, path: str, request_data: dict) -> object:
    return client.post(
        f"{XDR_PREFIX}{path}", json={"request_data": request_data}, headers=_xdr_headers(),
    )


class TestAPageNeverExceedsTheCeiling:
    """Incidents and endpoints answer at most 100 per call, whatever `search_to` says."""

    @pytest.fixture
    def many(self) -> None:
        from domain.xdr_endpoint import XdrEndpoint
        from domain.xdr_incident import XdrIncident
        from repository.xdr_endpoint_repo import xdr_endpoint_repo
        from repository.xdr_incident_repo import xdr_incident_repo

        for i in range(150):
            xdr_incident_repo.save(XdrIncident(incident_id=f"9{i:04d}", description="paging"))
            xdr_endpoint_repo.save(XdrEndpoint(endpoint_id=f"paging-{i:04d}"))

    @pytest.mark.parametrize(("path", "key"), PAGED[:3])
    def test_search_to_past_the_ceiling(
        self, client: TestClient, many: None, path: str, key: str,
    ) -> None:
        resp = _post(client, path, {"search_from": 0, "search_to": 1000})
        assert resp.status_code == 200, resp.text
        reply = resp.json()["reply"]
        assert len(reply[key]) == 100
        assert reply["total_count"] > 100

    def test_the_next_page_starts_where_the_ceiling_stopped(
        self, client: TestClient, many: None,
    ) -> None:
        first = _post(client, "/incidents/get_incidents/", {"search_from": 0, "search_to": 1000})
        second = _post(client, "/incidents/get_incidents/", {"search_from": 100, "search_to": 200})
        ids_1 = {i["incident_id"] for i in first.json()["reply"]["incidents"]}
        ids_2 = {i["incident_id"] for i in second.json()["reply"]["incidents"]}
        assert ids_1.isdisjoint(ids_2) and len(ids_2) > 0


class TestABoundThatIsNotAnIntegerIsA400:
    """`"0"` and friends answered a plain 500; they are a malformed request."""

    @pytest.mark.parametrize(("path", "key"), PAGED)
    @pytest.mark.parametrize("bad", ["0", 1.5, {"a": 1}, -1, True])
    def test_search_from(self, client: TestClient, path: str, key: str, bad: object) -> None:
        resp = _post(client, path, {"search_from": bad})
        assert resp.status_code == 400, (path, bad, resp.text)
        assert resp.json()["reply"]["err_code"] == 400

    @pytest.mark.parametrize(("path", "key"), PAGED)
    def test_search_to(self, client: TestClient, path: str, key: str) -> None:
        resp = _post(client, path, {"search_from": 0, "search_to": "10"})
        assert resp.status_code == 400, (path, resp.text)
