"""Defender's `$top` goes to 10,000 (8,000 on vulnerabilities), not 1,000.

The collection pages say "$top with max value of 10,000" and "Maximum page
size is 10,000" (get-machines, get-alerts, get-ti-indicators-collection,
get-software, get-machineactions-collection, get-investigation-collection on
https://learn.microsoft.com/en-us/defender-endpoint/api/), and
get-all-vulnerabilities "$top with max value of 8,000". The mock capped every
one at 1,000, so a client asking for the documented maximum page -- the usual
way to pull an estate in one call -- was refused with 400.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

TEN_THOUSAND = ["/mde/api/machines", "/mde/api/alerts", "/mde/api/indicators",
                "/mde/api/software", "/mde/api/machineactions", "/mde/api/investigations"]


@pytest.fixture()
def mde_headers(client: TestClient) -> dict[str, str]:
    token = client.post("/mde/oauth2/v2.0/token", data={
        "client_id": "mde-mock-admin-client",
        "client_secret": "mde-mock-admin-secret",
        "grant_type": "client_credentials",
        "scope": "https://api.securitycenter.microsoft.com/.default",
    }).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


class TestTheDocumentedMaximumPage:
    """The documented maximum is accepted, one more is refused."""

    @pytest.mark.parametrize("path", TEN_THOUSAND)
    def test_ten_thousand_is_a_page(
        self, client: TestClient, mde_headers: dict[str, str], path: str,
    ) -> None:
        assert client.get(path, headers=mde_headers,
                          params={"$top": 10000}).status_code == 200
        assert client.get(path, headers=mde_headers,
                          params={"$top": 10001}).status_code == 400

    def test_vulnerabilities_stop_at_eight_thousand(
        self, client: TestClient, mde_headers: dict[str, str],
    ) -> None:
        path = "/mde/api/vulnerabilities"
        assert client.get(path, headers=mde_headers, params={"$top": 8000}).status_code == 200
        assert client.get(path, headers=mde_headers, params={"$top": 8001}).status_code == 400
