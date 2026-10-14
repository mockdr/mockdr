"""A vendor path that names "_dev" is not mockdr's control surface."""
from __future__ import annotations

from fastapi.testclient import TestClient

ES_AUTH = ("elastic", "mock-elastic-password")


def test_a_dev_segment_in_a_vendor_path_does_not_skip_the_rate_limiter(client: TestClient) -> None:
    from api.middleware.rate_limit import reset_counters, set_config

    set_config(enabled=True, rpm=2)
    reset_counters()
    codes = [client.get("/elastic/_cat/indices/_dev/", auth=ES_AUTH).status_code for _ in range(4)]
    assert 429 in codes
