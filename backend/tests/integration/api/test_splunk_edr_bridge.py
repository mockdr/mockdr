"""The Splunk EDR bridge writes CrowdStrike events in the shape Event Streams emits.

Reference: ``data/vendor-specs/cs_event_streams_reduced.json`` — key paths
recorded from the Falcon Event Streams API. A recording proves presence, so
every key the bridge writes must be one a real event of that type carries,
and an ``IncidentSummaryEvent`` carries exactly its nine fields.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import time
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


# ── The other add-ons index the API object itself ─────────────────────────

_TA_REFERENCE = _REFERENCE.with_name("splunk_ta_samples_reduced.json")


def _events(sourcetype: str) -> list[dict]:
    out = []
    for e in splunk_event_repo.list_all():
        record = e if isinstance(e, dict) else e.__dict__
        if record.get("sourcetype") == sourcetype:
            out.append(json.loads(record["raw"]))
    return out


_S1 = {"Authorization": "ApiToken admin-token-0000-0000-000000000001"}


def _mde(client: TestClient) -> dict[str, str]:
    resp = client.post(
        "/mde/oauth2/v2.0/token",
        data={
            "client_id": "mde-mock-admin-client",
            "client_secret": "mde-mock-admin-secret",
            "grant_type": "client_credentials",
        "scope": "https://api.securitycenter.microsoft.com/.default",
        },
    )
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


def _xdr() -> dict[str, str]:
    nonce = secrets.token_hex(32)
    timestamp = str(int(time.time() * 1000))
    digest = hashlib.sha256(("xdr-admin-secret" + nonce + timestamp).encode()).hexdigest()
    return {
        "x-xdr-auth-id": "1",
        "x-xdr-nonce": nonce,
        "x-xdr-timestamp": timestamp,
        "Authorization": digest,
    }


def _keys(items: list[dict]) -> set[str]:
    out: set[str] = set()
    for item in items:
        out |= _observed(item)
    return out


class TestAddOnSourcetypes:
    """The sourcetypes are the ones the vendors' add-ons document."""

    def test_sourcetypes_are_the_add_ons(self, client: TestClient) -> None:
        present = {
            (e if isinstance(e, dict) else e.__dict__)["sourcetype"]
            for e in splunk_event_repo.list_all()
        }
        expected = {
            "sentinelone:channel:threats",
            "sentinelone:channel:agents",
            "sentinelone:channel:activities",
            "ms:defender:atp:alerts",
            "ms:defender:machines",
            "pan:xdr:incident",
            "pan:xdr:alert",
            "pan:xdr:endpoint",
        }
        assert expected <= present
        invented = {s for s in present if s.startswith(("ms:defender:endpoint", "pan:xdr:")) and s.endswith("s")}
        assert not invented, invented


class TestBridgeEventIsTheApiObject:
    """An add-on writes what the list route answers, key for key."""

    def test_sentinelone_threats(self, client: TestClient) -> None:
        api = client.get("/web/api/v2.1/threats?limit=50", headers=_S1).json()["data"]
        assert _keys(_events("sentinelone:channel:threats")) == _keys(api)

    def test_sentinelone_agents(self, client: TestClient) -> None:
        api = client.get("/web/api/v2.1/agents?limit=100", headers=_S1).json()["data"]
        assert _keys(_events("sentinelone:channel:agents")) == _keys(api)

    def test_sentinelone_activities(self, client: TestClient) -> None:
        api = client.get("/web/api/v2.1/activities?limit=100", headers=_S1).json()["data"]
        assert _keys(_events("sentinelone:channel:activities")) <= _keys(api)

    def test_defender_alerts(self, client: TestClient) -> None:
        api = client.get("/mde/api/alerts", headers=_mde(client)).json()["value"]
        assert _keys(_events("ms:defender:atp:alerts")) == _keys(api)

    def test_defender_alerts_match_the_recorded_add_on_events(self, client: TestClient) -> None:
        recorded = set(json.loads(_TA_REFERENCE.read_text())["ms:defender:atp:alerts"]["paths"])
        # recorded in 2021; these three have since left the documented alert
        retired = {
            "domains",
            "loggedOnUsers",
            "loggedOnUsers[*].accountName",
            "loggedOnUsers[*].domainName",
            "evidence[*].registryValueName",
        }
        missing = (recorded - retired) - _keys(_events("ms:defender:atp:alerts"))
        assert not missing, sorted(missing)

    def test_defender_machines(self, client: TestClient) -> None:
        api = client.get("/mde/api/machines", headers=_mde(client)).json()["value"]
        assert _keys(_events("ms:defender:machines")) == _keys(api)

    def test_cortex_incidents(self, client: TestClient) -> None:
        api = client.post(
            "/xdr/public_api/v1/incidents/get_incidents/", json={"request_data": {}}, headers=_xdr()
        ).json()["reply"]["incidents"]
        assert _keys(_events("pan:xdr:incident")) == _keys(api)

    def test_cortex_endpoints(self, client: TestClient) -> None:
        api = client.post(
            "/xdr/public_api/v1/endpoints/get_endpoint/", json={"request_data": {}}, headers=_xdr()
        ).json()["reply"]["endpoints"]
        assert _keys(_events("pan:xdr:endpoint")) == _keys(api)

    def test_cortex_alerts_are_what_get_alerts_multi_events_lists(self, client: TestClient) -> None:
        api = client.post(
            "/xdr/public_api/v1/alerts/get_alerts_multi_events/",
            json={"request_data": {}},
            headers=_xdr(),
        ).json()["reply"]["alerts"]
        assert _keys(_events("pan:xdr:alert")) == _keys(api)


class TestBridgeEventTime:
    """An add-on indexes an object at its own time, so ``_time`` is the record's."""

    def test_every_bridge_event_is_dated_by_its_record(self, client: TestClient) -> None:
        from utils.event_time import parse_epoch

        keys = {
            "sentinelone:channel:threats": ("threatInfo", "createdAt"),
            "ms:defender:atp:alerts": ("alertCreationTime",),
            "pan:xdr:incident": ("creation_time",),
            "pan:xdr:alert": ("detection_timestamp",),
        }
        for e in splunk_event_repo.list_all():
            record = e if isinstance(e, dict) else e.__dict__
            path = keys.get(record["sourcetype"])
            if not path:
                continue
            payload = json.loads(record["raw"])
            for key in path:
                payload = payload[key]
            assert abs(parse_epoch(payload) - record["time"]) < 1, record["sourcetype"]

    def test_time_bounded_searches_see_every_vendor(self, client: TestClient) -> None:
        auth = ("admin", "mockdr-admin")
        for index in ("sentinelone", "crowdstrike", "msdefender", "cortex_xdr", "elastic_security"):
            r = client.post(
                "/splunk/services/search/jobs",
                data={
                    "search": f"search index={index} earliest=-90d",
                    "exec_mode": "oneshot",
                    "output_mode": "json",
                    "count": 0,
                },
                auth=auth,
            )
            assert r.json()["results"], f"index={index} is empty in the last 90 days"


class TestSentinelOneChannelAgents:
    """Splunk's SA-SentinelOneDevices reads these fields from the agents channel."""

    def test_agent_events_carry_every_field_the_add_on_reads(self, client: TestClient) -> None:
        reference = json.loads(_REFERENCE.with_name("s1_splunk_channel_fields.json").read_text())
        expected = set(reference["sentinelone:channel:agents"]["fields"])
        events = _events("sentinelone:channel:agents")
        assert events
        missing = expected - _keys(events)
        assert not missing, sorted(missing)
