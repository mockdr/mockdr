"""Unit tests for vendor-shaped framework-level error envelopes."""
import pytest

from utils.vendor_errors import build_vendor_error, vendor_for_path


class TestVendorForPath:
    """Path-to-vendor resolution."""

    @pytest.mark.parametrize(("path", "expected"), [
        ("/web/api/v2.1/agents", "s1"),
        ("/cs/devices/queries/devices/v1", "crowdstrike"),
        ("/mde/api/machines", "mde"),
        ("/graph/v1.0/users", "graph"),
        ("/xdr/public_api/v1/incidents/get_incidents/", "xdr"),
        ("/elastic/logs-x/_search", "elasticsearch"),
        ("/kibana/api/cases", "kibana"),
        ("/splunk/services/server/info", "splunk"),
        ("/sentinel/subscriptions/x/resourceGroups/y", "sentinel"),
    ])
    def test_known_prefixes(self, path: str, expected: str) -> None:
        assert vendor_for_path(path) == expected

    def test_bare_mount_point_resolves(self) -> None:
        """The mount point itself belongs to the vendor, not the default."""
        assert vendor_for_path("/elastic") == "elasticsearch"

    def test_unknown_path_falls_back_to_s1(self) -> None:
        assert vendor_for_path("/metrics") == "s1"

    def test_prefix_must_end_at_a_segment_boundary(self) -> None:
        """A path merely starting with the letters must not match."""
        assert vendor_for_path("/csv-export") == "s1"


class TestBuildVendorError:
    """Each vendor gets the envelope its real API uses."""

    def test_s1_uses_errors_array(self) -> None:
        body = build_vendor_error("s1", 400, "bad")
        assert body["data"] is None
        assert body["errors"][0]["title"] == "Bad Request"

    def test_crowdstrike_uses_meta_resources_errors(self) -> None:
        body = build_vendor_error("crowdstrike", 400, "bad")
        assert set(body) == {"meta", "resources", "errors"}

    def test_microsoft_apis_use_error_object(self) -> None:
        for vendor in ("mde", "graph", "sentinel"):
            body = build_vendor_error(vendor, 400, "bad")
            assert body["error"]["code"] == "BadRequest"
            assert body["error"]["message"] == "bad"

    def test_xdr_uses_reply_envelope(self) -> None:
        body = build_vendor_error("xdr", 400, "bad")
        assert body["reply"]["err_code"] == 400
        assert body["reply"]["err_msg"] == "bad"

    def test_elasticsearch_uses_root_cause(self) -> None:
        body = build_vendor_error("elasticsearch", 400, "bad")
        assert body["status"] == 400
        assert body["error"]["root_cause"][0]["reason"] == "bad"

    def test_kibana_uses_status_code_envelope(self) -> None:
        body = build_vendor_error("kibana", 400, "bad")
        assert body == {"statusCode": 400, "error": "Bad Request", "message": "bad"}

    def test_splunk_uses_messages_array(self) -> None:
        body = build_vendor_error("splunk", 400, "bad")
        assert body["messages"][0] == {"type": "ERROR", "text": "bad"}

    def test_no_vendor_emits_fastapi_detail_key(self) -> None:
        """``detail`` is FastAPI's shape and belongs to none of these APIs."""
        for vendor in ("s1", "crowdstrike", "mde", "graph", "sentinel", "xdr",
                       "elasticsearch", "kibana", "splunk"):
            assert "detail" not in build_vendor_error(vendor, 400, "bad")
