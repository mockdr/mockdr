"""The Splunk EDR bridge writes CrowdStrike events in the shape Event Streams emits.

Reference: ``data/vendor-specs/cs_event_streams_reduced.json`` — key paths
recorded from the Falcon Event Streams API. A recording proves presence, so
every key the bridge writes must be one a real event of that type carries,
and an ``IncidentSummaryEvent`` carries exactly its nine fields.
"""

from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

from repository.splunk.splunk_event_repo import splunk_event_repo

_REFERENCE = (
    Path(__file__).resolve().parents[4] / "data" / "vendor-specs" / "cs_event_streams_reduced.json"
)


def _observed(value: object, prefix: str = "") -> set[str]:
    out: set[str] = set()
    if isinstance(value, dict):
        for k, v in value.items():
            out.add(f"{prefix}{k}")
            out |= _observed(v, f"{prefix}{k}.")
    elif isinstance(value, list):
        for item in value[:5]:
            out |= _observed(item, f"{prefix[:-1]}[*].")
    return out


def _crowdstrike_events() -> list[dict]:
    events = []
    for e in splunk_event_repo.list_all():
        record = e if isinstance(e, dict) else e.__dict__
        if record.get("index") == "crowdstrike":
            events.append(json.loads(record["raw"]))  # the indexed event body
    return events


class TestCrowdStrikeEventStreamsShape:
    def test_every_event_key_is_one_event_streams_records(self, client: TestClient) -> None:
        reference = json.loads(_REFERENCE.read_text())
        events = _crowdstrike_events()
        assert events, "the bridge wrote no CrowdStrike events"
        for event in events:
            kind = event["metadata"]["eventType"]
            assert kind in reference, f"unrecorded event type {kind}"
            unknown = _observed(event) - set(reference[kind]["paths"])
            assert not unknown, (
                f"{kind} carries keys Event Streams never emits: {sorted(unknown)[:5]}"
            )

    def test_incident_summary_has_exactly_its_nine_fields(self, client: TestClient) -> None:
        incidents = [
            e for e in _crowdstrike_events() if e["metadata"]["eventType"] == "IncidentSummaryEvent"
        ]
        assert incidents
        expected = {
            "FalconHostLink",
            "FineScore",
            "HostID",
            "IncidentEndTime",
            "IncidentID",
            "IncidentStartTime",
            "IncidentType",
            "LateralMovement",
            "State",
        }
        for event in incidents:
            assert set(event["event"]) == expected

    def test_detections_are_epp_detection_summary_events(self, client: TestClient) -> None:
        kinds = {e["metadata"]["eventType"] for e in _crowdstrike_events()}
        assert "EppDetectionSummaryEvent" in kinds
        assert "DetectionSummaryEvent" not in kinds  # the legacy type
