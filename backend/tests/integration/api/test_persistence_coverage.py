"""Tests that a state snapshot round-trips every seeded collection.

An unregistered collection is silently dropped from the snapshot, and because
loading a snapshot skips seeding, that data never comes back — the failure is
invisible until someone notices a vendor is empty after a restart. The coverage
test below turns that into a red test the moment a new vendor is added.
"""
import dataclasses

from fastapi.testclient import TestClient

from application.dev.commands import (
    _MAPPING_COLLECTIONS,
    _RAW_COLLECTIONS,
    _TYPED_COLLECTIONS,
    export_state,
    import_state,
)
from repository.store import store

_REGISTERED = set(_TYPED_COLLECTIONS) | set(_RAW_COLLECTIONS) | set(_MAPPING_COLLECTIONS)

# Ephemeral request-scoped collections, deliberately not persisted.
_NOT_PERSISTED = {"request_log", "webhook_sink", "webhook_deliveries"}


class TestSnapshotCoverage:
    """Every seeded collection must be part of the snapshot."""

    def test_no_seeded_collection_is_left_out(self, fresh_seed: None) -> None:
        seeded = {name for name, records in store._collections.items() if records}
        missing = seeded - _REGISTERED - _NOT_PERSISTED
        assert not missing, (
            f"These collections are seeded but would be lost on restart with "
            f"MOCKDR_PERSIST set: {sorted(missing)}. Add them to "
            f"_TYPED_COLLECTIONS, _RAW_COLLECTIONS or _MAPPING_COLLECTIONS."
        )

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
