"""A filter the vendor documents must actually filter.

The 2.1 swagger declares ``incidentStatus``, ``analystVerdict``, ``severity``,
``type``, ``source`` and ``id``; this mock declared only its own plurals, so a
client written against the docs sent the documented name, had it dropped, and
got a 200 with the whole collection — the failure this project exists to
prevent. SentinelOne also spells a filter value one way (``UNRESOLVED``) and
answers another (``Unresolved``); both are accepted.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

BASE = "/web/api/v2.1"


def _data(client: TestClient, path: str, headers: dict, **params: str) -> list[dict]:
    response = client.get(f"{BASE}{path}", headers=headers, params=params)
    assert response.status_code == 200, response.text
    return response.json()["data"]


class TestAlertFilters:
    def test_documented_name_and_enum_spelling_filter(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        everything = _data(client, "/cloud-detection/alerts", auth_headers, limit="100")
        unresolved = [a for a in everything if a["alertInfo"]["incidentStatus"] == "Unresolved"]
        assert unresolved and len(unresolved) < len(everything), "seed cannot prove the filter"

        documented = _data(
            client, "/cloud-detection/alerts", auth_headers,
            incidentStatus="UNRESOLVED", limit="100",
        )
        assert [a["alertInfo"]["alertId"] for a in documented] == [
            a["alertInfo"]["alertId"] for a in unresolved
        ]

    def test_the_readable_spelling_filters_too(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        documented = _data(
            client, "/cloud-detection/alerts", auth_headers,
            incidentStatus="Unresolved", limit="100",
        )
        plural = _data(
            client, "/cloud-detection/alerts", auth_headers,
            incidentStatuses="Unresolved", limit="100",
        )
        assert [a["alertInfo"]["alertId"] for a in documented] == [
            a["alertInfo"]["alertId"] for a in plural
        ]

    def test_analyst_verdict_and_severity(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        by_verdict = _data(
            client, "/cloud-detection/alerts", auth_headers,
            analystVerdict="TRUE_POSITIVE", limit="100",
        )
        assert all(a["alertInfo"]["analystVerdict"] == "True positive" for a in by_verdict)

        everything = _data(client, "/cloud-detection/alerts", auth_headers, limit="100")
        wanted = {a["ruleInfo"]["severity"] for a in everything}.pop()
        by_severity = _data(
            client, "/cloud-detection/alerts", auth_headers, severity=wanted, limit="100",
        )
        assert by_severity and all(a["ruleInfo"]["severity"] == wanted for a in by_severity)


class TestIocAndGroupFilters:
    def test_ioc_type_and_source(self, client: TestClient, auth_headers: dict) -> None:
        everything = _data(client, "/threat-intelligence/iocs", auth_headers, limit="100")
        wanted = everything[0]["type"]
        by_type = _data(client, "/threat-intelligence/iocs", auth_headers, type=wanted)
        assert by_type and all(i["type"] == wanted for i in by_type)

        source = everything[0]["source"]
        by_source = _data(client, "/threat-intelligence/iocs", auth_headers, source=source)
        assert by_source and all(i["source"] == source for i in by_source)

    def test_ioc_uuids(self, client: TestClient, auth_headers: dict) -> None:
        everything = _data(client, "/threat-intelligence/iocs", auth_headers, limit="100")
        wanted = everything[0]["uuid"]
        assert [i["uuid"] for i in _data(
            client, "/threat-intelligence/iocs", auth_headers, uuids=wanted,
        )] == [wanted]

    def test_group_id(self, client: TestClient, auth_headers: dict) -> None:
        everything = _data(client, "/groups", auth_headers, limit="100")
        wanted = everything[0]["id"]
        assert [g["id"] for g in _data(client, "/groups", auth_headers, id=wanted)] == [wanted]
