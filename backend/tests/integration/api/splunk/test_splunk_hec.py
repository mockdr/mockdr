"""Integration tests for Splunk HEC endpoints."""
import json

from fastapi.testclient import TestClient

from tests.clock import Clock

SPLUNK_PREFIX = "/splunk"
HEC_TOKEN = "11111111-1111-1111-1111-111111111111"


def _hec_auth(token: str = HEC_TOKEN) -> dict[str, str]:
    return {"Authorization": f"Splunk {token}"}


class TestHecEvent:
    """Tests for POST /services/collector/event."""

    def test_submit_single_event(self, client: TestClient) -> None:
        resp = client.post(
            f"{SPLUNK_PREFIX}/services/collector/event",
            content=json.dumps({
                "event": {"message": "Test event", "severity": "info"},
                "sourcetype": "test:event",
                "index": "sentinelone",
            }),
            headers={**_hec_auth(), "Content-Type": "application/json"},
        )
        assert resp.status_code == 200
        assert resp.json()["code"] == 0
        assert resp.json()["text"] == "Success"

    def test_submit_batched_events(self, client: TestClient) -> None:
        batch = "\n".join([
            json.dumps({"event": {"msg": "Event 1"}}),
            json.dumps({"event": {"msg": "Event 2"}}),
        ])
        resp = client.post(
            f"{SPLUNK_PREFIX}/services/collector/event",
            content=batch,
            headers={**_hec_auth(), "Content-Type": "application/json"},
        )
        assert resp.status_code == 200
        assert resp.json()["code"] == 0

    def test_invalid_token_returns_403(self, client: TestClient) -> None:
        resp = client.post(
            f"{SPLUNK_PREFIX}/services/collector/event",
            content=json.dumps({"event": {"msg": "test"}}),
            headers={**_hec_auth("invalid-token"), "Content-Type": "application/json"},
        )
        assert resp.status_code == 403

    def test_missing_auth_returns_401(self, client: TestClient) -> None:
        resp = client.post(
            f"{SPLUNK_PREFIX}/services/collector/event",
            content=json.dumps({"event": {"msg": "test"}}),
            headers={"Content-Type": "application/json"},
        )
        assert resp.status_code == 401

    def test_invalid_json_returns_400(self, client: TestClient) -> None:
        resp = client.post(
            f"{SPLUNK_PREFIX}/services/collector/event",
            content="not json",
            headers={**_hec_auth(), "Content-Type": "application/json"},
        )
        assert resp.status_code == 400


class TestHecRaw:
    """Tests for POST /services/collector/raw."""

    def test_submit_raw_event(self, client: TestClient) -> None:
        resp = client.post(
            f"{SPLUNK_PREFIX}/services/collector/raw",
            content="Raw log line from test",
            headers={**_hec_auth(), "Content-Type": "text/plain"},
        )
        assert resp.status_code == 200
        assert resp.json()["code"] == 0


class TestHecHealth:
    """Tests for GET /services/collector/health."""

    def test_health_check(self, client: TestClient) -> None:
        resp = client.get(f"{SPLUNK_PREFIX}/services/collector/health")
        assert resp.status_code == 200
        assert resp.json()["code"] == 17


class TestHecAck:
    """Tests for POST /services/collector/ack."""

    def test_ack_on_a_token_without_ack_is_code_14(self, client: TestClient) -> None:
        """A token with no indexer acknowledgement has nothing to query.

        splunkd answers code 14 "ACK is disabled" before it even looks for a
        channel (measured on 10.4.2); this asserted code 10 here.
        """
        resp = client.post(
            f"{SPLUNK_PREFIX}/services/collector/ack",
            json={"acks": [0]},
            headers=_hec_auth(),
        )
        assert resp.status_code == 400
        assert resp.json() == {"text": "ACK is disabled", "code": 14}

    def test_ack_with_ack_enabled_still_requires_a_channel(self, client: TestClient) -> None:
        """With acknowledgement on, a missing channel is code 10."""
        from repository.splunk.hec_token_repo import hec_token_repo

        record = hec_token_repo.list_all()[0]
        record.use_ack = True
        hec_token_repo.save(record)
        try:
            resp = client.post(
                f"{SPLUNK_PREFIX}/services/collector/ack",
                json={"acks": [0]},
                headers={"Authorization": f"Splunk {record.token}"},
            )
            assert resp.status_code == 400
            assert resp.json()["code"] == 10
        finally:
            record.use_ack = False
            hec_token_repo.save(record)

    def test_only_issued_ids_are_acknowledged(self, client: TestClient) -> None:
        channel = {"X-Splunk-Request-Channel": "test-channel"}

        submitted = client.post(
            f"{SPLUNK_PREFIX}/services/collector/event",
            json={"event": "hello"},
            params={"useACK": "true"},
            headers={**_hec_auth(), **channel},
        ).json()
        issued = submitted["ackId"]

        resp = client.post(
            f"{SPLUNK_PREFIX}/services/collector/ack",
            json={"acks": [issued, 9999]},
            headers={**_hec_auth(), **channel},
        )

        assert resp.status_code == 200
        acks = resp.json()["acks"]
        assert acks[str(issued)] is True
        # An id this channel was never given must not come back acknowledged.
        assert acks["9999"] is False

    def test_an_ack_answered_true_is_forgotten(self, client: TestClient) -> None:
        """HEC deletes an ackID's status once a client has seen it true.

        "If you query the same ackID again, HEC returns false" (Splunk, "About
        HTTP Event Collector Indexer Acknowledgment"). The mock kept every id
        it issued for the life of the process.
        """
        channel = {"X-Splunk-Request-Channel": "forgetful-channel"}
        issued = client.post(
            f"{SPLUNK_PREFIX}/services/collector/event", json={"event": "x"},
            params={"useACK": "true"}, headers={**_hec_auth(), **channel},
        ).json()["ackId"]

        def ask() -> bool:
            return bool(client.post(
                f"{SPLUNK_PREFIX}/services/collector/ack", json={"acks": [issued]},
                headers={**_hec_auth(), **channel},
            ).json()["acks"][str(issued)])

        assert ask() is True
        assert ask() is False

    def test_an_idle_channel_is_forgotten(self, client: TestClient, clock: Clock) -> None:
        """inputs.conf ``maxIdleTime = 600`` with ``ackIdleCleanup = true``.

        A forwarder that opens a channel per batch left one entry per batch
        for the life of the process.
        """
        from api.routers.splunk import splunk_hec

        splunk_hec.reset_ack_state()  # earlier tests' channels live outside the store
        for n in range(3):
            client.post(
                f"{SPLUNK_PREFIX}/services/collector/event", json={"event": n},
                params={"useACK": "true"},
                headers={**_hec_auth(), "X-Splunk-Request-Channel": f"batch-{n}"},
            )
        clock.advance(300)
        client.post(
            f"{SPLUNK_PREFIX}/services/collector/ack", json={"acks": [5]},
            headers={**_hec_auth(), "X-Splunk-Request-Channel": "batch-0"},
        )
        clock.advance(301)

        assert splunk_hec.reap_idle_channels() == 2
        assert set(splunk_hec._ISSUED_ACKS) == {"batch-0"}
