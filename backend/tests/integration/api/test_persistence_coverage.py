"""Tests that a state snapshot round-trips every seeded collection.

An unregistered collection is silently dropped from the snapshot, and because
loading a snapshot skips seeding, that data never comes back — the failure is
invisible until someone notices a vendor is empty after a restart. The coverage
test below turns that into a red test the moment a new vendor is added.
"""
import base64
import dataclasses

from fastapi.testclient import TestClient

from application.dev.commands import (
    _BINARY_COLLECTIONS,
    _MAPPING_COLLECTIONS,
    _NOT_PERSISTED,
    _RAW_COLLECTIONS,
    _TYPED_COLLECTIONS,
    export_state,
    import_state,
)
from repository.store import store

_REGISTERED = (
    set(_TYPED_COLLECTIONS) | set(_RAW_COLLECTIONS)
    | set(_MAPPING_COLLECTIONS) | set(_BINARY_COLLECTIONS)
)

_ES_AUTH = {
    "Authorization": "Basic " + base64.b64encode(b"elastic:mock-elastic-password").decode(),
}


class TestSnapshotCoverage:
    """Every store collection must be part of the snapshot or excluded by name."""

    def test_no_collection_is_left_out(self, fresh_seed: None) -> None:
        """Registered or explicitly excluded — every collection, seeded or not.

        This looked only at collections the seed fills, so one that starts
        empty and is written by clients — the Elasticsearch indices and
        documents a client creates — slipped through, and was lost on every
        restart with MOCKDR_PERSIST set and on every export → import.
        """
        missing = set(store._collections) - _REGISTERED - set(_NOT_PERSISTED)
        assert not missing, (
            f"These collections would be lost on restart with MOCKDR_PERSIST "
            f"set: {sorted(missing)}. Register them in _TYPED_COLLECTIONS, "
            f"_RAW_COLLECTIONS, _MAPPING_COLLECTIONS or _BINARY_COLLECTIONS, "
            f"or name them with a reason in _NOT_PERSISTED."
        )

    def test_every_exclusion_names_a_real_collection(self) -> None:
        """An exclusion for a collection the store does not have hides nothing.

        The list named `request_log` (the store says `request_logs`) and
        `webhook_deliveries` (not a store collection at all), so the real
        traffic log was never actually excluded — it simply was not checked.
        """
        assert set(_NOT_PERSISTED) <= set(store._collections)
        assert not set(_NOT_PERSISTED) & _REGISTERED
        assert all(reason.strip() for reason in _NOT_PERSISTED.values())

    def test_every_registered_name_is_a_real_collection(self) -> None:
        """A misspelt registration persists nothing and fails silently."""
        assert _REGISTERED <= set(store._collections), sorted(
            _REGISTERED - set(store._collections))

    def test_typed_collections_hold_dataclasses(self, fresh_seed: None) -> None:
        """A typed entry that is not a dataclass cannot be reconstructed."""
        for name, cls in _TYPED_COLLECTIONS.items():
            records = store.get_all(name)
            if not records:
                continue
            assert dataclasses.is_dataclass(records[0]), f"{name} is not typed"
            assert isinstance(records[0], cls), f"{name} holds a different class"


class TestSnapshotRoundTrip:
    """Exported state restores to the same record counts."""

    def test_every_collection_survives_a_round_trip(self, fresh_seed: None) -> None:
        before = {n: len(r) for n, r in store._collections.items() if r}
        import_state(export_state())
        after = {n: len(r) for n, r in store._collections.items() if r}

        lost = {n: (c, after.get(n, 0)) for n, c in before.items()
                if after.get(n, 0) != c and n not in _NOT_PERSISTED}
        assert not lost, f"records lost or duplicated on restore: {lost}"

    def test_vendor_data_is_queryable_after_restore(self, client: TestClient) -> None:
        """A restored snapshot must still answer vendor requests."""
        import_state(export_state())

        graph = client.post("/graph/oauth2/v2.0/token", data={
            "client_id": "graph-mock-admin-client",
            "client_secret": "graph-mock-admin-secret",
            "grant_type": "client_credentials",
        "scope": "https://graph.microsoft.com/.default",
        })
        assert graph.status_code == 200
        users = client.get(
            "/graph/v1.0/users",
            headers={"Authorization": f"Bearer {graph.json()['access_token']}"},
        )
        assert users.status_code == 200
        assert users.json()["value"], "Graph users vanished across a restore"

        splunk = client.post("/splunk/services/auth/login", data={
            "username": "admin", "password": "mockdr-admin",
        })
        assert splunk.status_code == 200, "Splunk users vanished across a restore"


class TestClientWrittenElasticsearchDataSurvives:
    """An index and a document a client created come back from a snapshot."""

    def test_index_and_document_round_trip_through_export_and_import(
        self, client: TestClient, auth_headers: dict[str, str],
    ) -> None:
        created = client.put(
            "/elastic/soar-cases",
            json={"mappings": {"properties": {"title": {"type": "keyword"}}}},
            headers=_ES_AUTH,
        )
        assert created.status_code == 200, created.text
        written = client.put(
            "/elastic/soar-cases/_doc/case-1?refresh=true",
            json={"title": "phishing triage"}, headers=_ES_AUTH,
        )
        assert written.status_code in (200, 201), written.text

        snapshot = client.get("/web/api/v2.1/_dev/export", headers=auth_headers)
        assert snapshot.status_code == 200
        client.post("/web/api/v2.1/_dev/reset", headers=auth_headers)
        restored = client.post(
            "/web/api/v2.1/_dev/import", json=snapshot.json(), headers=auth_headers,
        )
        assert restored.status_code == 200

        doc = client.get("/elastic/soar-cases/_doc/case-1", headers=_ES_AUTH)
        assert doc.status_code == 200, "the client's document was lost"
        assert doc.json()["_source"] == {"title": "phishing triage"}
        mapping = client.get("/elastic/soar-cases/_mapping", headers=_ES_AUTH)
        assert mapping.status_code == 200, "the client's index was lost"
        assert mapping.json()["soar-cases"]["mappings"]["properties"]["title"] == {
            "type": "keyword"}
        hits = client.post(
            "/elastic/soar-cases/_search", json={"query": {"match_all": {}}},
            headers=_ES_AUTH,
        ).json()["hits"]
        assert hits["total"]["value"] == 1
