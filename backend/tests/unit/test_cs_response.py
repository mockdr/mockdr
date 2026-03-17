"""Unit tests for CrowdStrike response envelope builders."""
from __future__ import annotations

from utils.cs_response import (
    build_cs_action_response,
    build_cs_entity_response,
    build_cs_error_response,
    build_cs_id_response,
    build_cs_list_response,
)


class TestCsResponseEnvelopes:
    """Tests for the five CrowdStrike response envelope builders."""

    def test_list_response_structure(self) -> None:
        resp = build_cs_list_response(["a", "b"], total=10, offset=0, limit=5)
        assert resp["resources"] == ["a", "b"]
        assert resp["errors"] == []
        meta = resp["meta"]
        assert meta["powered_by"] == "crowdstrike-api"
        assert "trace_id" in meta
        assert meta["pagination"] == {"offset": 0, "limit": 5, "total": 10}

    def test_list_response_custom_query_time(self) -> None:
        resp = build_cs_list_response([], total=0, query_time=0.5)
        assert resp["meta"]["query_time"] == 0.5

    def test_id_response_structure(self) -> None:
        resp = build_cs_id_response(["id1", "id2"], total=2, offset=0, limit=100)
        assert resp["resources"] == ["id1", "id2"]
        assert resp["meta"]["pagination"]["total"] == 2

    def test_entity_response_no_pagination(self) -> None:
        resp = build_cs_entity_response([{"id": "1"}])
        assert "pagination" not in resp["meta"]
        assert resp["resources"] == [{"id": "1"}]

    def test_action_response_defaults_empty(self) -> None:
        resp = build_cs_action_response()
        assert resp["resources"] == []

    def test_action_response_with_resources(self) -> None:
        resp = build_cs_action_response(resources=[{"id": "x"}])
        assert len(resp["resources"]) == 1

    def test_error_response_structure(self) -> None:
        resp = build_cs_error_response(401, "unauthorized")
        assert resp["meta"]["query_time"] == 0.0
        assert resp["resources"] == []
        assert len(resp["errors"]) == 1
        assert resp["errors"][0]["code"] == 401
        assert resp["errors"][0]["message"] == "unauthorized"

    def test_trace_id_is_unique(self) -> None:
        r1 = build_cs_entity_response([])
        r2 = build_cs_entity_response([])
        assert r1["meta"]["trace_id"] != r2["meta"]["trace_id"]
