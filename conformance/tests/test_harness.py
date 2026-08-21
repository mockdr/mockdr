"""Tests for the comparison logic itself.

The harness makes claims about mockdr, so its own reasoning has to be sound:
a differ that under-reports hides defects, and one that over-reports buries
them. These run without any service, because the logic under test is the part
that decides what a difference *means*.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from harness.diff import Response, compare
from harness.normalize import mask, skeleton, strip_prefix
from harness.spec import SpecError, load_spec, substitute

SIGNIFICANT = frozenset({"code", "text", "status"})


def _response(status: int = 200, body: object = None, **headers: str) -> Response:
    return Response(status, {k.replace("_", "-"): v for k, v in headers.items()}, body)


class TestMasking:
    """Volatile values must not read as differences."""

    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            ("11111111-1111-1111-1111-111111111111", "<uuid>"),
            ("2026-08-21T19:00:00Z", "<timestamp>"),
            ("1787321651.04aaf445671d4140838bec79", "<sid>"),
            ("1787321651", "<epoch>"),
            ("9.4.0", "<version>"),
            ("https://localhost:8089/services", "<url>"),
        ],
    )
    def test_volatile_values_collapse(self, value: str, expected: str) -> None:
        assert mask(value) == expected

    @pytest.mark.parametrize("value", ["DONE", "Success", "Invalid token", "parsing_exception"])
    def test_meaningful_values_survive(self, value: str) -> None:
        """The values a client branches on must never be masked away."""
        assert mask(value) == value


class TestSkeleton:
    """Shape and type, plus the values that carry meaning."""

    def test_significant_keys_keep_their_value(self) -> None:
        out = skeleton({"text": "Invalid token", "code": 4}, SIGNIFICANT)
        assert out["$.code"] == "=4"

    def test_other_keys_keep_only_their_type(self) -> None:
        out = skeleton({"sid": "abc", "count": 3}, SIGNIFICANT)
        assert out["$.sid"] == "string"
        assert out["$.count"] == "int"

    def test_array_elements_collapse_onto_one_path(self) -> None:
        """Length differs legitimately; the element shape does not."""
        one = skeleton({"rows": [{"a": 1}]}, SIGNIFICANT)
        many = skeleton({"rows": [{"a": 1}, {"a": 2}, {"a": 3}]}, SIGNIFICANT)
        assert one == many

    def test_recursion_is_bounded(self) -> None:
        deep: dict = {}
        node = deep
        for _ in range(200):
            node["next"] = {}
            node = node["next"]
        assert any(v == "<truncated>" for v in skeleton(deep, SIGNIFICANT).values())


class TestCompare:
    """What counts as a finding, and in what order."""

    def test_identical_responses_yield_nothing(self) -> None:
        body = {"code": 0, "text": "Success"}
        assert compare("p", _response(200, body), _response(200, body), SIGNIFICANT) == []

    def test_status_difference_is_reported_first(self) -> None:
        findings = compare(
            "p", _response(404, {"code": 4}), _response(400, {"code": 16}), SIGNIFICANT,
        )
        assert findings[0].kind == "status"
        assert (findings[0].mock, findings[0].real) == ("404", "400")

    def test_a_significant_value_difference_is_a_value_finding(self) -> None:
        """The HEC defect's shape: same structure, different meaning."""
        findings = compare(
            "p", _response(400, {"code": 4}), _response(400, {"code": 16}), SIGNIFICANT,
        )
        assert [f.kind for f in findings] == ["value"]

    def test_a_missing_key_outranks_an_extra_one(self) -> None:
        findings = compare(
            "p", _response(200, {"extra": 1}), _response(200, {"needed": "x"}), SIGNIFICANT,
        )
        assert [f.kind for f in findings] == ["missing_key", "extra_key"]

    def test_volatile_values_do_not_differ(self) -> None:
        findings = compare(
            "p",
            _response(200, {"code": "2026-01-01T00:00:00Z"}),
            _response(200, {"code": "2030-06-15T12:30:00Z"}),
            SIGNIFICANT,
        )
        assert findings == []

    def test_an_empty_array_suppresses_its_element_shape(self) -> None:
        """A seeded mock against a fresh install compares nothing, not everything."""
        findings = compare(
            "p",
            _response(200, {"data": [{"a": 1, "b": 2, "c": 3}]}),
            _response(200, {"data": []}),
            SIGNIFICANT,
        )
        assert findings == []

    def test_a_non_json_body_is_itself_a_finding(self) -> None:
        mock = Response(200, {}, None, body_error="non-json (text/html)")
        findings = compare("p", mock, _response(200, {"ok": True}), SIGNIFICANT)
        assert findings[0].kind == "type"

    def test_ignored_paths_are_dropped(self) -> None:
        findings = compare(
            "p", _response(200, {"a": 1}), _response(200, {"a": "x"}), SIGNIFICANT,
            ignore_paths=("$.a",),
        )
        assert findings == []

    def test_security_headers_are_not_compared(self) -> None:
        """Mockdr being stricter than the real product is not a defect."""
        findings = compare(
            "p",
            _response(200, {}, x_content_type_options="nosniff"),
            _response(200, {}),
            SIGNIFICANT,
        )
        assert findings == []


class TestPrefixStripping:
    """A mount prefix is an artefact of hosting, not a behaviour difference."""

    def test_prefix_is_removed_from_nested_strings(self) -> None:
        body = {"error": {"reason": "no handler for [/elastic/_cat]"}}
        assert strip_prefix(body, "/elastic") == {
            "error": {"reason": "no handler for [/_cat]"},
        }

    def test_an_empty_prefix_changes_nothing(self) -> None:
        assert strip_prefix({"a": "/elastic/x"}, "") == {"a": "/elastic/x"}


class TestSpecLoading:
    """Probe files are configuration, so their errors must be legible."""

    def test_placeholders_resolve_from_context(self) -> None:
        out = substitute({"h": "Splunk ${hec_token}"}, {"hec_token": "abc"})
        assert out == {"h": "Splunk abc"}

    def test_an_unresolvable_placeholder_is_left_alone(self) -> None:
        """A probe may deliberately send a token that cannot be resolved."""
        assert substitute("${nope}", {}) == "${nope}"

    @pytest.mark.parametrize("name", ["splunk", "elastic"])
    def test_the_shipped_specs_load(self, name: str) -> None:
        spec = load_spec(Path(__file__).resolve().parents[1] / "probes" / f"{name}.yaml")
        assert spec.probes
        assert all(p.endpoint in spec.endpoints for p in spec.probes)

    def test_an_unknown_endpoint_is_rejected(self, tmp_path: Path) -> None:
        path = tmp_path / "bad.yaml"
        path.write_text(
            "platform: x\n"
            "endpoints: {a: {mock: http://m, real: http://r}}\n"
            "probes: [{id: p, endpoint: nope, request: {path: /}}]\n",
        )
        with pytest.raises(SpecError, match="unknown endpoint"):
            load_spec(path)

    def test_duplicate_probe_ids_are_rejected(self, tmp_path: Path) -> None:
        path = tmp_path / "dupe.yaml"
        path.write_text(
            "platform: x\n"
            "endpoints: {a: {mock: http://m, real: http://r}}\n"
            "probes:\n"
            "  - {id: p, endpoint: a, request: {path: /1}}\n"
            "  - {id: p, endpoint: a, request: {path: /2}}\n",
        )
        with pytest.raises(SpecError, match="duplicate"):
            load_spec(path)


class TestExitStatus:
    """"Nothing differed" and "nothing ran" must not look the same."""

    def test_an_unreachable_target_is_not_a_clean_bill(self) -> None:
        """The distinction the exit codes exist to make."""
        from harness.runner import main

        spec = Path(__file__).resolve().parents[1] / "probes" / "splunk.yaml"
        # Nothing is listening on the real ports in a unit-test run.
        assert main([str(spec)]) == 2
