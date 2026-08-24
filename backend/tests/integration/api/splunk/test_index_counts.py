"""``totalEventCount`` is counted where it is read, and it stays right.

Keeping it up to date on ingest meant scanning the whole event store for
every event a forwarder sent: a 200-event batch scanned it 200 times, 4.8
million comparisons for one request. Counting in the index endpoint — the
only place the number is read — is both cheaper and harder to get wrong.
"""

from __future__ import annotations

import json

from fastapi.testclient import TestClient

_ADMIN = ("admin", "mockdr-admin")
_HEC = {"Authorization": "Splunk 11111111-1111-1111-1111-111111111111"}


def _counts(client: TestClient) -> dict[str, int]:
    entries = client.get(
        "/splunk/services/data/indexes", params={"output_mode": "json"}, auth=_ADMIN
    ).json()["entry"]
    return {e["name"]: int(e["content"]["totalEventCount"]) for e in entries}


class TestIndexEventCount:
    def test_a_batch_moves_the_count_by_its_size(self, client: TestClient) -> None:
        before = _counts(client)["sentinelone"]
        batch = "\n".join(
            json.dumps({"event": {"i": i}, "sourcetype": "probe"}) for i in range(50)
        )
        response = client.post("/splunk/services/collector/event", headers=_HEC, content=batch)
        assert response.json() == {"text": "Success", "code": 0}
        assert _counts(client)["sentinelone"] == before + 50

    def test_a_single_event_moves_it_by_one(self, client: TestClient) -> None:
        before = _counts(client)["sentinelone"]
        client.post(
            "/splunk/services/collector/event",
            headers=_HEC,
            json={"event": {"one": True}, "sourcetype": "probe"},
        )
        assert _counts(client)["sentinelone"] == before + 1

    def test_both_index_endpoints_agree(self, client: TestClient) -> None:
        listed = _counts(client)["sentinelone"]
        single = client.get(
            "/splunk/services/data/indexes/sentinelone",
            params={"output_mode": "json"},
            auth=_ADMIN,
        ).json()["entry"][0]["content"]["totalEventCount"]
        assert int(single) == listed

    def test_a_rejected_batch_moves_nothing(self, client: TestClient) -> None:
        before = _counts(client)
        # The seeded token is bound to its own indexes; splunkd answers code 7.
        response = client.post(
            "/splunk/services/collector/event",
            headers=_HEC,
            content=json.dumps({"event": {"x": 1}, "index": "main", "sourcetype": "probe"}),
        )
        assert response.status_code == 400
        assert response.json()["code"] == 7
        assert _counts(client) == before
