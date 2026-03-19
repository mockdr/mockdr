"""Unit tests for vendor routing (path prefix -> vendor detection)."""
from __future__ import annotations

import pytest

from application.proxy.vendor_routing import detect_vendor, strip_prefix


class TestDetectVendor:
    @pytest.mark.parametrize("path,expected", [
        ("/web/api/v2.1/agents", "s1"),
        ("/web/api/v2.1/threats?limit=25", "s1"),
        ("/cs/devices/queries/devices/v1", "crowdstrike"),
        ("/cs/oauth2/token", "crowdstrike"),
        ("/mde/api/machines", "mde"),
        ("/mde/oauth2/v2.0/token", "mde"),
        ("/elastic/_search", "elastic"),
        ("/elastic/some/other/path", "elastic"),
        ("/kibana/api/detection_engine/rules/_find", "elastic"),
        ("/xdr/public_api/v1/incidents/get_incidents", "cortex_xdr"),
        ("/splunk/services/auth/login", "splunk"),
        ("/splunk/services/search/jobs", "splunk"),
        ("/sentinel/oauth2/v2.0/token", "sentinel"),
        ("/sentinel/subscriptions/mock-sub/resourceGroups/rg/providers/foo", "sentinel"),
        ("/graph/v1.0/users", "graph"),
        ("/graph/oauth2/v2.0/token", "graph"),
    ])
    def test_known_prefixes(self, path: str, expected: str) -> None:
        assert detect_vendor(path) == expected

    @pytest.mark.parametrize("path", [
        "/unknown/path",
        "/",
        "",
        "/api/v1/something",
    ])
    def test_unknown_paths_return_none(self, path: str) -> None:
        assert detect_vendor(path) is None


class TestStripPrefix:
    @pytest.mark.parametrize("path,vendor,expected", [
        # S1: path is forwarded as-is (real API uses same prefix).
        ("/web/api/v2.1/agents", "s1", "/web/api/v2.1/agents"),
        # CrowdStrike: /cs stripped.
        ("/cs/devices/queries/devices/v1", "crowdstrike", "/devices/queries/devices/v1"),
        ("/cs/oauth2/token", "crowdstrike", "/oauth2/token"),
        # MDE: /mde stripped.
        ("/mde/api/machines", "mde", "/api/machines"),
        # Elastic: /elastic stripped.
        ("/elastic/_search", "elastic", "/_search"),
        # Kibana: /kibana stripped (also elastic vendor).
        ("/kibana/api/detection_engine/rules/_find", "elastic", "/api/detection_engine/rules/_find"),
        # Cortex XDR: /xdr/public_api/v1 stripped.
        ("/xdr/public_api/v1/incidents/get_incidents", "cortex_xdr", "/incidents/get_incidents"),
        # Splunk: /splunk stripped.
        ("/splunk/services/auth/login", "splunk", "/services/auth/login"),
        # Sentinel: /sentinel stripped.
        ("/sentinel/subscriptions/sub/resourceGroups/rg", "sentinel", "/subscriptions/sub/resourceGroups/rg"),
        # Graph: /graph stripped.
        ("/graph/v1.0/users", "graph", "/v1.0/users"),
    ])
    def test_strip_prefix(self, path: str, vendor: str, expected: str) -> None:
        assert strip_prefix(path, vendor) == expected
