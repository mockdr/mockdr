"""A scroll or point in time lives for its keep-alive after its last use.

"The scroll parameter tells Elasticsearch how long it should keep the search
context alive", and every scroll request may renew it (Elasticsearch 8.15,
"Paginate search results"); a point in time stays open for its
``keep_alive``, which each search through it can extend. The mock kept
every context until a cap of 1,000 evicted the oldest: a client that
scrolls per poll and never clears pushed out another client's live scroll,
and a scroll id read back a day later still paged.
"""
from __future__ import annotations

import base64

from fastapi.testclient import TestClient

from application.es_search.queries import keep_alive_seconds, reap_contexts
from repository.store import store
from tests.clock import Clock

AUTH = {"Authorization": "Basic " + base64.b64encode(b"elastic:mock-elastic-password").decode()}
ALERTS = "/elastic/.alerts-security.alerts-default"


def _open_scroll(client: TestClient, keep_alive: str = "1m") -> str:
    response = client.post(f"{ALERTS}/_search", headers=AUTH,
                           params={"scroll": keep_alive}, json={"size": 1})
    assert response.status_code == 200, response.text
    return str(response.json()["_scroll_id"])


def _next_page(client: TestClient, scroll_id: str, **renew: str) -> int:
    return client.post("/elastic/_search/scroll", headers=AUTH,
                       json={"scroll_id": scroll_id, **renew}).status_code


def test_a_scroll_left_past_its_keep_alive_is_gone(client: TestClient, clock: Clock) -> None:
    scroll_id = _open_scroll(client)
    clock.advance(61)

    response = client.post("/elastic/_search/scroll", headers=AUTH,
                           json={"scroll_id": scroll_id})
    assert response.status_code == 404
    assert response.json()["error"]["caused_by"]["type"] == "search_context_missing_exception"


def test_each_page_renews_the_keep_alive(client: TestClient, clock: Clock) -> None:
    scroll_id = _open_scroll(client)
    for _ in range(4):
        clock.advance(50)
        assert _next_page(client, scroll_id, scroll="1m") == 200


def test_a_page_can_ask_for_a_longer_keep_alive(client: TestClient, clock: Clock) -> None:
    scroll_id = _open_scroll(client)
    assert _next_page(client, scroll_id, scroll="10m") == 200
    clock.advance(500)
    assert _next_page(client, scroll_id) == 200


def test_a_point_in_time_expires_unless_searched(client: TestClient, clock: Clock) -> None:
    def open_pit() -> str:
        return str(client.post(f"{ALERTS}/_pit", headers=AUTH,
                               params={"keep_alive": "2m"}).json()["id"])

    def search(pit_id: str) -> int:
        return client.post("/elastic/_search", headers=AUTH, json={
            "size": 1, "pit": {"id": pit_id, "keep_alive": "2m"},
        }).status_code

    kept, left = open_pit(), open_pit()
    clock.advance(100)
    assert search(kept) == 200
    clock.advance(100)
    assert search(kept) == 200
    assert search(left) == 404


def test_the_reaper_frees_abandoned_scrolls(client: TestClient, clock: Clock) -> None:
    for _ in range(3):
        _open_scroll(client, "30s")
    live = _open_scroll(client, "5m")
    clock.advance(31)

    assert reap_contexts() == 3
    assert store.count("es_search_contexts") == 1
    assert _next_page(client, live) == 200


def test_time_units_are_elasticsearchs() -> None:
    assert keep_alive_seconds("1m") == 60
    assert keep_alive_seconds("1500ms") == 1.5
    assert keep_alive_seconds("2h") == 7200
    assert keep_alive_seconds("1d") == 86400
    assert keep_alive_seconds("soon") is None
