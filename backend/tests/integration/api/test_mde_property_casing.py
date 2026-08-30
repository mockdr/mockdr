"""One property, one spelling — and a documented property stays filterable.

Microsoft's property tables are camelCase almost everywhere and not quite:
the `machine` table lists `onboardingstatus`, `software` lists `Vendor` and
`Weaknesses`, `investigation` lists `ID` and `State`. The completion matched
those keys exactly, so the record's spelling and the table's both reached the
answer: a machine carried `onboardingStatus: "Onboarded"` *and*
`onboardingstatus: ""`, and a client whose JSON mapper ignores case could
bind the empty one and read the machine as not onboarded.

The same casing made `$filter` refuse real properties, and a route's recorded
sample is a subset of its entity's table besides — `machines` records 18
names where the docs' `machine` table lists 21.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def mde_headers(client: TestClient) -> dict:
    response = client.post("/mde/oauth2/v2.0/token", data={
        "client_id": "mde-mock-admin-client",
        "client_secret": "mde-mock-admin-secret",
        "grant_type": "client_credentials",
        "scope": "https://api.securitycenter.microsoft.com/.default",
    })
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def _first(client: TestClient, headers: dict, path: str) -> dict:
    response = client.get(path, headers=headers)
    assert response.status_code == 200, response.text
    items = response.json()["value"]
    assert items, f"{path} answered no records"
    return items[0]


class TestNoResourceCarriesOneNameTwice:
    @pytest.mark.parametrize(
        ("path", "kept", "dropped"),
        [
            ("/mde/api/machines", "onboardingStatus", "onboardingstatus"),
            ("/mde/api/investigations", "state", "State"),
            ("/mde/api/software", "vendor", "Vendor"),
            ("/mde/api/software", "weaknesses", "Weaknesses"),
        ],
    )
    def test_only_the_spelling_that_carries_the_value_is_answered(
        self, client: TestClient, mde_headers: dict, path: str, kept: str, dropped: str,
    ) -> None:
        record = _first(client, mde_headers, path)
        assert kept in record
        assert dropped not in record
        assert record[kept] not in (None, "")

    def test_no_resource_answers_two_spellings_of_anything(
        self, client: TestClient, mde_headers: dict,
    ) -> None:
        for path in ("/mde/api/machines", "/mde/api/investigations", "/mde/api/software",
                     "/mde/api/alerts"):
            record = _first(client, mde_headers, path)
            folded: dict[str, list[str]] = {}
            for name in record:
                folded.setdefault(name.lower(), []).append(name)
            twice = {k: v for k, v in folded.items() if len(v) > 1}
            assert not twice, f"{path} answers {twice}"


class TestADocumentedPropertyStaysFilterable:
    @pytest.mark.parametrize(
        "expression",
        [
            "deviceValue eq 'Normal'",
            "onboardingStatus eq 'Onboarded'",
            "healthStatus eq 'Active'",
        ],
    )
    def test_a_property_the_docs_record_is_not_refused(
        self, client: TestClient, mde_headers: dict, expression: str,
    ) -> None:
        response = client.get(
            "/mde/api/machines", headers=mde_headers, params={"$filter": expression},
        )
        assert response.status_code == 200, response.text

    def test_a_name_no_spelling_of_which_exists_is_still_refused(
        self, client: TestClient, mde_headers: dict,
    ) -> None:
        response = client.get(
            "/mde/api/machines", headers=mde_headers,
            params={"$filter": "zzzNotAProperty eq 'x'"},
        )
        assert response.status_code == 400, response.text
        assert "Could not find a property named 'zzzNotAProperty'" in response.text
