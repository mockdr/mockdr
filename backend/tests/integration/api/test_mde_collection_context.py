"""Each Defender collection names its entity set in `@odata.context`.

The list examples on https://learn.microsoft.com/en-us/defender-endpoint/api/
carry `https://api.security.microsoft.com/api/$metadata#Machines`, `#Alerts`,
`#Indicators`, `#MachineActions`, `#Software`, `#Vulnerabilities`,
`#Investigations` and `#MachineReferences` (get-machines, get-alerts,
get-ti-indicators-collection, get-machineactions-collection, get-software,
get-all-vulnerabilities, get-investigation-collection,
get-machines-by-vulnerability). The mock answered the bare `$metadata` on the
legacy host for every collection, so a client could not tell one from another
by its context.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

BASE = "https://api.security.microsoft.com/api/$metadata#"


@pytest.fixture()
def mde_headers(client: TestClient) -> dict[str, str]:
    token = client.post("/mde/oauth2/v2.0/token", data={
        "client_id": "mde-mock-admin-client",
        "client_secret": "mde-mock-admin-secret",
        "grant_type": "client_credentials",
        "scope": "https://api.securitycenter.microsoft.com/.default",
    }).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


class TestEntitySetContext:
    """The context names the entity set the docs' example names."""

    @pytest.mark.parametrize(("path", "entity_set"), [
        ("/mde/api/machines", "Machines"),
        ("/mde/api/alerts", "Alerts"),
        ("/mde/api/indicators", "Indicators"),
        ("/mde/api/machineactions", "MachineActions"),
        ("/mde/api/software", "Software"),
        ("/mde/api/vulnerabilities", "Vulnerabilities"),
        ("/mde/api/investigations", "Investigations"),
    ])
    def test_collection_context(
        self, client: TestClient, mde_headers: dict[str, str], path: str, entity_set: str,
    ) -> None:
        body = client.get(path, headers=mde_headers).json()
        assert body["@odata.context"] == BASE + entity_set

    def test_machine_references_context(
        self, client: TestClient, mde_headers: dict[str, str],
    ) -> None:
        vuln = client.get("/mde/api/vulnerabilities", headers=mde_headers,
                          params={"$top": 1}).json()["value"][0]
        body = client.get(f"/mde/api/vulnerabilities/{vuln['id']}/machineReferences",
                          headers=mde_headers).json()
        assert body["@odata.context"] == BASE + "MachineReferences"
