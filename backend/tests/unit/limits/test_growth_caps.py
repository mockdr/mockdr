"""Traffic-written collections are capped; a request body has a ceiling.

Before 2.1.1 a client that fetched a token per request grew the OAuth
collections until the process died, and any route read an unbounded body.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from repository.store import CAPS, store


def test_traffic_collections_evict_oldest_first() -> None:
    cap = CAPS["cs_oauth_tokens"]
    for i in range(cap + 10):
        store.save("cs_oauth_tokens", f"tok-{i}", {"n": i})
    assert store.count("cs_oauth_tokens") == cap
    assert store.get("cs_oauth_tokens", "tok-0") is None
    assert store.get("cs_oauth_tokens", f"tok-{cap + 9}") is not None


def test_updating_an_existing_record_does_not_evict() -> None:
    cap = CAPS["splunk_sessions"]
    for i in range(cap):
        store.save("splunk_sessions", f"s-{i}", {"n": i})
    store.save("splunk_sessions", "s-0", {"n": "updated"})
    assert store.count("splunk_sessions") == cap
    assert store.get("splunk_sessions", "s-0") == {"n": "updated"}


def test_oversized_body_is_refused_before_it_is_read(client: TestClient) -> None:
    from config import MAX_BODY_BYTES

    r = client.post(
        "/splunk/services/collector/event",
        content=b"x",
        headers={"Content-Length": str(MAX_BODY_BYTES + 1), "Authorization": "Splunk 1"},
    )
    assert r.status_code == 413
    assert r.json()["limit_bytes"] == MAX_BODY_BYTES


def test_unmatched_paths_share_one_metrics_series(client: TestClient) -> None:
    for i in range(5):
        client.get(f"/no/such/route/{i}")
    text = client.get("/metrics").text
    assert "/no/such/route" not in text
    # One series however many paths are probed: the SPA catch-all when the
    # built frontend is present, "{unmatched}" (404) when it is not.
    series = [
        line
        for line in text.splitlines()
        if line.startswith('http_requests_total{method="GET"')
        and ('path="/{full_path:path}"' in line or 'path="{unmatched}"' in line)
    ]
    assert len(series) == 1, series
    assert series[0].endswith(" 5")
