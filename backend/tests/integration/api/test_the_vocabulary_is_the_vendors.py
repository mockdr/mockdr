"""No answer carries a value its vendor's own vocabulary does not list.

A field with the right name and a value from the wrong vocabulary is invisible
from the outside: the shape is right, the type is right, and a client that
switches on the value silently takes no branch. Defender's alerts answered
`BenignPositive` -- Sentinel's word, borrowed by a seeder standing next to it
-- and Defender's docs list three classifications, none of them that one.

The vendored references state these vocabularies exactly: `mde_docs_reduced`
carries Defender's alert enums, and the Graph CSDL names the members of every
enum type and which property has which type. So this reads them rather than
repeating them here, and asks the question in both directions: nothing outside
the vocabulary, and -- where the estate is big enough to say so -- more than
one member of it.
"""
import json
from pathlib import Path

from fastapi.testclient import TestClient

_SPECS = Path(__file__).resolve().parents[4] / "data" / "vendor-specs"


def _graph_headers(client: TestClient) -> dict[str, str]:
    resp = client.post("/graph/oauth2/v2.0/token", data={
        "grant_type": "client_credentials", "client_id": "graph-mock-admin-client",
        "client_secret": "graph-mock-admin-secret",
        "scope": "https://graph.microsoft.com/.default",
    })
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


def _mde_headers(client: TestClient) -> dict[str, str]:
    resp = client.post("/mde/oauth2/v2.0/token", data={
        "grant_type": "client_credentials", "client_id": "mde-mock-admin-client",
        "client_secret": "mde-mock-admin-secret",
        "scope": "https://api.securitycenter.microsoft.com/.default",
    })
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


class TestDefenderSpeaksDefenders:
    def test_no_alert_carries_a_value_the_docs_do_not_list(
        self, client: TestClient
    ) -> None:
        documented = json.loads((_SPECS / "mde_docs_reduced.json").read_text())
        vocabularies = documented["enums"]["alerts"]
        alerts = client.get("/mde/api/alerts", headers=_mde_headers(client),
                            params={"$top": 200}).json()["value"]

        assert alerts
        strays: list[str] = []
        for alert in alerts:
            for prop, members in vocabularies.items():
                value = alert.get(prop)
                if value and value not in members:
                    strays.append(f"{prop}={value!r}")
        assert not strays, f"values no Defender document lists: {sorted(set(strays))}"

    def test_every_documented_classification_occurs(self, client: TestClient) -> None:
        documented = json.loads((_SPECS / "mde_docs_reduced.json").read_text())
        members = set(documented["enums"]["alerts"]["classification"])
        alerts = client.get("/mde/api/alerts", headers=_mde_headers(client),
                            params={"$top": 200}).json()["value"]

        seen = {a["classification"] for a in alerts if a.get("classification")}

        assert seen == members, (
            "a client filtering for one of these cannot tell an empty estate "
            f"from a broken filter; missing: {sorted(members - seen)}"
        )


class TestGraphSpeaksGraphs:
    def _csdl(self) -> tuple[dict, dict]:
        types = json.loads((_SPECS / "graph_v1.0_csdl_types.json").read_text())
        enums = {k: v["members"] for k, v in types.items() if v.get("kind") == "EnumType"}
        entities = {k: v for k, v in types.items() if v.get("kind") == "EntityType"}
        return enums, entities

    def test_no_security_record_carries_a_value_the_csdl_does_not_declare(
        self, client: TestClient
    ) -> None:
        graph_admin_headers = _graph_headers(client)
        enums, entities = self._csdl()
        strays: list[str] = []
        checked = 0

        for path, entity in (
            ("/graph/v1.0/security/incidents", "microsoft.graph.security.incident"),
            ("/graph/v1.0/security/alerts_v2", "microsoft.graph.security.alert"),
        ):
            records = client.get(path, headers=graph_admin_headers).json()["value"]
            assert records, path
            for prop, declared in entities[entity]["properties"].items():
                members = enums.get(declared.replace("self.", "microsoft.graph.security."))
                if members is None:
                    continue
                checked += 1
                for record in records:
                    value = record.get(prop)
                    if value and value not in members:
                        strays.append(f"{path.split('/')[-1]}.{prop}={value!r}")

        assert checked >= 8, "the sweep found the enum-typed properties"
        assert not strays, f"values the CSDL does not declare: {sorted(set(strays))}"

    def test_an_incident_carries_the_state_of_its_alerts(
        self, client: TestClient
    ) -> None:
        graph_admin_headers = _graph_headers(client)
        incidents = client.get("/graph/v1.0/security/incidents",
                               headers=graph_admin_headers).json()["value"]
        alerts = {a["id"]: a for a in client.get(
            "/graph/v1.0/security/alerts_v2", headers=graph_admin_headers).json()["value"]}

        assert incidents and alerts
        for incident in incidents:
            grouped = [alerts[i] for i in incident.get("alerts", []) if i in alerts]
            if not grouped:
                continue
            states = {alert["status"] for alert in grouped}
            expected = ("resolved" if states == {"resolved"}
                        else "inProgress" if states & {"inProgress", "resolved"}
                        else "active")
            assert incident["status"] == expected, (
                f"incident {incident['id']} says {incident['status']} "
                f"over alerts that are {sorted(states)}"
            )

    def test_more_than_one_status_occurs(
        self, client: TestClient
    ) -> None:
        graph_admin_headers = _graph_headers(client)
        incidents = client.get("/graph/v1.0/security/incidents",
                               headers=graph_admin_headers).json()["value"]

        assert len({i["status"] for i in incidents}) > 1, (
            "every incident had the same status, so no filter on it could be tested"
        )
