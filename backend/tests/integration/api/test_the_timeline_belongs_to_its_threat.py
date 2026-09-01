"""The timeline must be *this* threat's, not the schema's example.

The response is restricted to ``schemas_TimelineViewSchema``, so any key the
seeder stores under a different name is dropped silently and the field falls
back to the example in the fixture. That reads as a 200 with eight events —
and every one of them blank, dated 2018, identical across every threat. This
asks the two questions that separate a real timeline from the example: do the
scope ids point back at the threat we asked about, and does the text differ
between two different threats?
"""
from fastapi.testclient import TestClient

_BASE = "/web/api/v2.1/threats"


def _threat(client: TestClient, headers: dict, index: int) -> dict:
    resp = client.get(f"{_BASE}?limit=5", headers=headers)
    assert resp.status_code == 200
    return resp.json()["data"][index]


def _timeline(client: TestClient, headers: dict, threat_id: str) -> list[dict]:
    resp = client.get(f"{_BASE}/{threat_id}/timeline", headers=headers)
    assert resp.status_code == 200
    return resp.json()["data"]


class TestTimelineIsThisThreats:
    def test_events_name_the_threat_they_belong_to(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        threat = _threat(client, auth_headers, 0)
        events = _timeline(client, auth_headers, threat["id"])

        assert events, "a seeded threat has a timeline"
        for event in events:
            assert event["threatId"] == threat["id"]
            assert event["hash"] == threat["threatInfo"]["sha1"]
            assert event["agentId"] == threat["agentRealtimeInfo"]["agentId"]

    def test_events_carry_text_and_a_time_of_their_own(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        threat = _threat(client, auth_headers, 0)
        events = _timeline(client, auth_headers, threat["id"])

        for event in events:
            assert event["primaryDescription"].strip()
            assert event["secondaryDescription"].strip()
            # The example in the fixture is dated 2018; a seeded event is not.
            assert event["createdAt"] >= threat["threatInfo"]["createdAt"]

        stamps = [event["createdAt"] for event in events]
        assert stamps == sorted(stamps), "oldest first, as a timeline reads"

    def test_two_threats_do_not_share_one_timeline(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        first, second = _threat(client, auth_headers, 0), _threat(client, auth_headers, 1)
        assert first["id"] != second["id"]

        left = _timeline(client, auth_headers, first["id"])
        right = _timeline(client, auth_headers, second["id"])

        assert {e["id"] for e in left}.isdisjoint({e["id"] for e in right})
        assert {e["createdAt"] for e in left} != {e["createdAt"] for e in right}
