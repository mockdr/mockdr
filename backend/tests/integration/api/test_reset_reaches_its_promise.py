"""A reset must reach the state the API serves back.

`POST /_dev/reset` promises the initial state.  HEC's acknowledgement ids
are per channel and monotonic, and the webhook delivery log is a bounded
deque — neither lives in the store `generate_all` clears, so both used to
survive a reset.  A client that reset between scenarios was handed ack ids
that carried on from the previous one, and `/collector/ack` answered `true`
for ids issued before the reset.
"""
from __future__ import annotations

import uuid

from fastapi.testclient import TestClient

HEC = {"Authorization": "Splunk 11111111-1111-1111-1111-111111111111"}
ADMIN = {"Authorization": "ApiToken admin-token-0000-0000-000000000001"}


def _post_event(client: TestClient, channel: str) -> int:
    resp = client.post(
        "/splunk/services/collector/event",
        headers={**HEC, "X-Splunk-Request-Channel": channel},
        params={"useACK": "1"},
        json={"event": "reset probe"},
    )
    assert resp.status_code == 200, resp.text
    return int(resp.json()["ackId"])


class TestResetReachesHecAcks:
    def test_ack_ids_start_over_after_a_reset(self, client: TestClient) -> None:
        channel = str(uuid.uuid4())
        first = _post_event(client, channel)
        second = _post_event(client, channel)
        assert (first, second) == (0, 1), "ack ids are monotonic per channel"

        assert client.post("/web/api/v2.1/_dev/reset", headers=ADMIN).status_code == 200

        # Same channel, fresh mock: the count starts at 0 again, as it does on
        # a channel that has never been used.
        assert _post_event(client, channel) == 0

    def test_an_ack_from_before_the_reset_is_not_acknowledged(
        self, client: TestClient,
    ) -> None:
        channel = str(uuid.uuid4())
        stale = _post_event(client, channel)

        assert client.post("/web/api/v2.1/_dev/reset", headers=ADMIN).status_code == 200

        resp = client.post(
            "/splunk/services/collector/ack",
            headers={**HEC, "X-Splunk-Request-Channel": channel},
            json={"acks": [stale]},
        )
        # The channel is unknown again, so the token's own `use_ack` decides,
        # and this one does not have it: code 14, exactly what a channel that
        # was never used gets.  Before the reset reached this state the answer
        # was 200 `{"acks": {"0": true}}` — acknowledging an event the reset
        # had thrown away.
        assert resp.status_code == 400, resp.text
        assert resp.json() == {"text": "ACK is disabled", "code": 14}


class TestResetReachesTheWebhookDeliveryLog:
    """The other state `generate_all` cannot reach, served by `_dev`."""

    def test_deliveries_from_before_the_reset_are_gone(
        self, client: TestClient,
    ) -> None:
        from application.webhooks.delivery_log import DeliveryEntry, record

        record(DeliveryEntry(
            subscription_id="wh-reset-probe", event_type="threat.updated",
            status="success", attempt=1, timestamp="2026-01-01T00:00:00Z",
        ))
        before = client.get("/web/api/v2.1/_dev/webhooks/deliveries", headers=ADMIN)
        assert before.status_code == 200
        assert any(e["subscriptionId" if "subscriptionId" in e else "subscription_id"]
                   == "wh-reset-probe" for e in before.json()["data"])

        assert client.post("/web/api/v2.1/_dev/reset", headers=ADMIN).status_code == 200

        after = client.get("/web/api/v2.1/_dev/webhooks/deliveries", headers=ADMIN)
        assert after.status_code == 200
        assert after.json()["data"] == []
