"""Kibana answers under `/s/{space_id}/` exactly as it does at the root.

The spaces plugin strips the prefix on request (`getSpaceIdFromPath`,
kibana v8.15.0), `/s/default/` included. mockdr had no such routes, so a
client configured with a space URL got 404 for every call.
"""
from __future__ import annotations

import base64

from fastapi.testclient import TestClient

AUTH = {"Authorization": "Basic " + base64.b64encode(
    b"elastic:mock-elastic-password").decode()}


class TestTheDefaultSpacePrefix:
    def test_a_read_under_the_prefix_is_the_same_read(self, client: TestClient) -> None:
        root = client.get("/kibana/api/detection_engine/rules/_find", headers=AUTH,
                          params={"per_page": 5})
        spaced = client.get("/kibana/s/default/api/detection_engine/rules/_find",
                            headers=AUTH, params={"per_page": 5})
        assert spaced.status_code == 200, spaced.text
        assert spaced.json() == root.json()

    def test_a_write_under_the_prefix(self, client: TestClient) -> None:
        resp = client.post(
            "/kibana/s/default/api/detection_engine/signals/search",
            headers={**AUTH, "kbn-xsrf": "true"}, json={"size": 1},
        )
        assert resp.status_code == 200, resp.text
        assert resp.json()["hits"]["hits"]

    def test_the_platform_routes_too(self, client: TestClient) -> None:
        resp = client.get("/kibana/s/default/api/spaces/space/default", headers=AUTH)
        assert resp.status_code == 200
        assert resp.json()["id"] == "default"


class TestASpaceThisMockDoesNotHold:
    """Deliberately not served: answering another space with the default
    space's data would be worse than the loud 404 (see kibana_space.py)."""

    def test_is_the_unserved_path_404(self, client: TestClient) -> None:
        resp = client.get("/kibana/s/elsewhere/api/detection_engine/rules/_find",
                          headers=AUTH)
        assert resp.status_code == 404
        assert resp.json()["statusCode"] == 404
