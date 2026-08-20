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
        assert "data" not in body, "S1 error bodies carry `errors` alone"
        assert body["errors"][0]["code"] == 4000010
        assert body["errors"][0]["title"] == "Validation Error"

    @pytest.mark.parametrize(("status", "title"), [
        (401, "Authentication Failed"),
        (403, "Insufficient permissions"),
        (404, "Requested resource was not found"),
    ])
    def test_s1_uses_its_own_titles(self, status: int, title: str) -> None:
        """S1 writes its own wording into `title`, not the HTTP reason phrase."""
        body = build_vendor_error("s1", status, "x")
        assert body["errors"][0]["title"] == title

    def test_crowdstrike_uses_meta_resources_errors(self) -> None:
        body = build_vendor_error("crowdstrike", 400, "bad")
        assert set(body) == {"meta", "resources", "errors"}

    def test_microsoft_apis_use_error_object(self) -> None:
        for vendor in ("mde", "graph", "sentinel"):
            body = build_vendor_error(vendor, 400, "bad")
            assert body["error"]["message"] == "bad"

    @pytest.mark.parametrize(("vendor", "status", "code"), [
        # The three Microsoft APIs share an envelope but not their code strings.
        ("mde", 401, "Unauthorized"),
        ("mde", 404, "ResourceNotFound"),
        ("graph", 401, "InvalidAuthenticationToken"),
        ("graph", 403, "Authorization_RequestDenied"),
        ("graph", 404, "Request_ResourceNotFound"),
        ("sentinel", 401, "AuthenticationFailed"),
        ("sentinel", 403, "AuthorizationFailed"),
        ("sentinel", 404, "ResourceNotFound"),
    ])
    def test_microsoft_codes_are_per_vendor(
        self, vendor: str, status: int, code: str,
    ) -> None:
        assert build_vendor_error(vendor, status, "x")["error"]["code"] == code

    def test_mde_error_carries_tracking_target(self) -> None:
        """Defender's envelope has a third member the others do not."""
        body = build_vendor_error("mde", 404, "gone")
        assert body["error"]["target"]

    def test_splunk_auth_failure_is_warn_not_error(self) -> None:
        """splunkd labels an auth failure WARN; permission failures stay ERROR."""
        assert build_vendor_error("splunk", 401, "x")["messages"][0]["type"] == "WARN"
        assert build_vendor_error("splunk", 403, "x")["messages"][0]["type"] == "ERROR"

    def test_kibana_envelope_differs_from_elasticsearch(self) -> None:
        """They ship together but do not share an error shape."""
        kbn = build_vendor_error("kibana", 404, "nope")
        es = build_vendor_error("elasticsearch", 404, "nope")
        assert kbn == {"statusCode": 404, "error": "Not Found", "message": "nope"}
        assert isinstance(es["error"], dict)
        assert es["status"] == 404

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
