"""Tests for the comparison logic itself.

The harness makes claims about mockdr, so its own reasoning has to be sound:
a differ that under-reports hides defects, and one that over-reports buries
them. These run without any service, because the logic under test is the part
that decides what a difference *means*.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from harness.diff import Response, compare, compare_values, strip_volatile
from harness.normalize import mask, skeleton, strip_prefix
from harness.seed import SEED_EPOCH, SEED_EVENTS, SEED_INDEX, _hec_payload, seed_sourcetype
from harness.spec import SpecError, load_spec, resolve_env, substitute

ROOT = Path(__file__).resolve().parents[1]
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

    def test_a_message_that_merely_starts_with_a_timestamp_is_not_a_timestamp(self) -> None:
        """An unanchored pattern masked the diagnostic that followed the date."""
        assert mask("2026-01-01T00:00:00 search failed: quota") != "<timestamp>"

    @pytest.mark.parametrize("value", [
        "2026-01-01T00:00:00Z", "2026-01-01T00:00:00.123+00:00", "2026-01-01 00:00:00",
    ])
    def test_timestamp_variants_still_mask(self, value: str) -> None:
        assert mask(value) == "<timestamp>"


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

    def test_array_elements_merge_their_types_rather_than_overwriting(self) -> None:
        """The last element used to win, hiding a malformed first one."""
        out = skeleton({"hits": [{"f": None}, {"f": "x"}]}, SIGNIFICANT)
        assert out["$.hits[*].f"] == "null|string"

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

    def test_a_null_collection_suppresses_element_shape_like_an_empty_one(self) -> None:
        """A fresh install may say `null` where the mock says `[...]`."""
        findings = compare(
            "p",
            _response(200, {"data": [{"a": 1, "b": 2}]}),
            _response(200, {"data": None}),
            SIGNIFICANT,
        )
        # The null-versus-array difference at the path is real and reported;
        # the element fields beneath it were never comparable and are not.
        assert [(f.kind, f.path) for f in findings] == [("type", "$.data")]

    def test_a_non_json_body_is_itself_a_finding(self) -> None:
        mock = Response(200, {}, None, body_error="non-json (text/html)")
        findings = compare("p", mock, _response(200, {"ok": True}), SIGNIFICANT)
        assert findings[0].kind == "type"

    def test_identical_non_json_is_agreement(self) -> None:
        """Both sides answering Atom XML is not a finding."""
        xml = Response(200, {}, None, body_error="non-json (text/xml)")
        assert compare("p", xml, xml, SIGNIFICANT) == []

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

    def test_only_a_mount_point_is_stripped_not_a_word(self) -> None:
        """A blind replace rewrote `/Documentation/elastic/x`, which is a word."""
        text = "see /Documentation/elastic/x and /elastic/_cat [/elastic]"
        assert strip_prefix(text, "/elastic") == "see /Documentation/elastic/x and /_cat []"

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

    def test_env_references_resolve_with_defaults(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.delenv("CONF_PROBE_X", raising=False)
        assert resolve_env("${env:CONF_PROBE_X:-fallback}") == "fallback"
        monkeypatch.setenv("CONF_PROBE_X", "set")
        assert resolve_env("${env:CONF_PROBE_X:-fallback}") == "set"

    def test_an_env_reference_with_no_value_and_no_default_is_an_error(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.delenv("CONF_PROBE_MISSING", raising=False)
        with pytest.raises(SpecError, match="CONF_PROBE_MISSING"):
            resolve_env("${env:CONF_PROBE_MISSING}")

    @pytest.mark.parametrize("name", ["splunk", "elastic"])
    def test_the_shipped_specs_carry_credentials_for_both_targets(self, name: str) -> None:
        """A spec without them would fall back to nothing and 401 on both sides."""
        spec = load_spec(ROOT / "probes" / f"{name}.yaml")
        assert set(spec.credentials) == {"mock", "real"}

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

    def test_an_unreachable_target_is_not_a_clean_bill(self, tmp_path: Path) -> None:
        """The distinction the exit codes exist to make.

        Points at a port nothing can be listening on, rather than assuming
        the shipped spec's ports are free: they are exactly the ones the
        compose file binds, and a Splunk left running from a fidelity check
        would have made this pass or fail on host state.
        """
        from harness.runner import main

        spec = tmp_path / "dead.yaml"
        spec.write_text(
            "platform: x\n"
            "endpoints: {a: {mock: 'http://127.0.0.1:1', real: 'http://127.0.0.1:1'}}\n"
            "probes: [{id: p, endpoint: a, request: {path: /}}]\n",
        )
        assert main([str(spec)]) == 2


class TestFixturesAgreeWithTheBackend:
    """The harness names mockdr's seeded values; the seeder defines them.

    Read as text rather than imported, so the harness stays a separate
    project that needs no mockdr source on its path — while still failing
    the moment the seeded value and the harness's copy of it diverge.
    """

    def test_the_mock_hec_token_is_the_seeded_one(self) -> None:
        from harness.bootstrap import MOCK_HEC_TOKEN

        seeder = (ROOT.parent / "backend/infrastructure/seeders/splunk/splunk_seeder.py")
        assert MOCK_HEC_TOKEN in seeder.read_text()

    @pytest.mark.parametrize(("name", "source"), [
        ("splunk", "backend/infrastructure/seeders/splunk/splunk_seeder.py"),
        ("elastic", "backend/api/es_auth.py"),
    ])
    def test_the_mock_credential_is_one_the_backend_accepts(
        self, name: str, source: str,
    ) -> None:
        spec = load_spec(ROOT / "probes" / f"{name}.yaml")
        text = (ROOT.parent / source).read_text()
        assert spec.credentials["mock"].password in text


class TestSeededValueComparison:
    """With the same events on both sides, the rows themselves are the claim.

    The structural comparison cannot see a wrong answer: a search matching
    nothing agrees with every other search matching nothing. These probes
    exist because `tail` reversing its output, `stats ... by` leaving its
    groups unsorted and `_time` rendering as an epoch all passed every
    structural probe.
    """

    VOLATILE = frozenset({"_bkt", "_indextime", "splunk_server"})

    def test_identical_rows_are_no_finding(self) -> None:
        body = {"results": [{"host": "srv-1", "count": "2"}]}
        assert compare_values(
            "p", _response(body=body), _response(body=dict(body)), self.VOLATILE,
        ) == []

    def test_a_differing_row_is_reported_once(self) -> None:
        findings = compare_values(
            "p",
            _response(body={"results": [{"host": "srv-1", "count": "2"}]}),
            _response(body={"results": [{"host": "srv-1", "count": "3"}]}),
            self.VOLATILE,
        )
        # One finding, not one per key: a row that differs usually differs in
        # several places, and listing each buries the answer.
        assert len(findings) == 1
        assert findings[0].kind == "value"

    def test_row_order_is_part_of_the_comparison(self) -> None:
        findings = compare_values(
            "p",
            _response(body={"results": [{"n": "1"}, {"n": "2"}]}),
            _response(body={"results": [{"n": "2"}, {"n": "1"}]}),
            self.VOLATILE,
        )
        assert len(findings) == 1

    def test_the_instances_own_fields_are_dropped_first(self) -> None:
        assert compare_values(
            "p",
            _response(body={"results": [{"host": "a", "_bkt": "main~0~AAA"}]}),
            _response(body={"results": [{"host": "a", "_bkt": "main~9~ZZZ"}]}),
            self.VOLATILE,
        ) == []

    def test_volatile_fields_are_dropped_at_every_depth(self) -> None:
        stripped = strip_volatile(
            {"results": [{"a": 1, "_bkt": "x", "nested": {"_indextime": "1", "b": 2}}]},
            self.VOLATILE,
        )
        assert stripped == {"results": [{"a": 1, "nested": {"b": 2}}]}

    def test_a_status_difference_is_still_reported(self) -> None:
        findings = compare_values(
            "p", _response(status=400, body={}), _response(status=200, body={}),
            self.VOLATILE,
        )
        assert [f.kind for f in findings] == ["status"]


class TestSeedPayload:
    """What goes into both targets before a seeded probe runs."""

    def test_every_event_carries_the_same_index_and_sourcetype(self) -> None:
        lines = [json.loads(line) for line in _hec_payload("probe:test").splitlines()]
        assert len(lines) == len(SEED_EVENTS)
        assert {line["sourcetype"] for line in lines} == {"probe:test"}
        assert {line["index"] for line in lines} == {SEED_INDEX}

    def test_the_timestamps_are_absolute_and_an_hour_apart(self) -> None:
        # Absolute, so a search bounded by earliest/latest means the same
        # thing on every run.
        times = [json.loads(line)["time"] for line in _hec_payload("s").splitlines()]
        assert times == [SEED_EPOCH + i * 3600 for i in range(len(SEED_EVENTS))]

    def test_the_sourcetype_is_unique_to_the_run(self) -> None:
        # A real instance keeps what it is given; running twice under one
        # sourcetype would double every count and read as a difference.
        assert seed_sourcetype().startswith("probe:conformance:")


class TestSpecLevelIgnorePaths:
    """A path the spec ignores is ignored by every probe."""

    def test_the_elastic_spec_ignores_shard_failures(self) -> None:
        spec = load_spec(ROOT / "probes" / "elastic.yaml")
        assert "$._shards.failures" in spec.ignore_paths

    def test_a_spec_without_them_gets_an_empty_tuple(self) -> None:
        spec = load_spec(ROOT / "probes" / "splunk.yaml")
        assert spec.ignore_paths == ()

    def test_an_ignored_path_produces_no_finding(self) -> None:
        """The eight findings a still-allocating shard produced in CI."""
        real = Response(status=200, headers={}, body={
            "count": 6,
            "_shards": {"total": 1, "successful": 0, "failed": 1, "failures": [
                {"shard": 0, "index": "x", "reason": {"type": "no_shard_available_action_"
                                                              "exception", "reason": None}},
            ]},
        })
        mock = Response(status=200, headers={}, body={
            "count": 6, "_shards": {"total": 1, "successful": 1, "failed": 0},
        })
        assert compare("es-count", mock, real, frozenset(),
                       ("$._shards.failures",)) == []
        assert compare("es-count", mock, real, frozenset()) != []


class TestSeededProbesLoad:
    """The probe file's seeded entries parse into what the runner expects."""

    def test_seeded_probes_declare_both_flags(self) -> None:
        spec = load_spec(ROOT / "probes" / "splunk.yaml")
        seeded = [p for p in spec.probes if p.needs_seed]
        assert seeded, "the splunk probes should include seeded ones"
        # `compare: values` without data on both sides would compare a seeded
        # mock against an empty install and report every row as a difference.
        assert all(p.compare_values for p in seeded)
        for probe in spec.probes:
            if not probe.compare_values or probe.needs_seed:
                continue
            # Two exceptions, both of which read no indexed data. A search
            # that generates its own rows — both engines answer
            # `| makeresults` from the search text alone. And a request that
            # never reaches the data: a refusal, or a read of something every
            # install has, such as the `main` index's own settings.
            content = probe.request.content or ""
            path = probe.request.path
            if path.startswith("/services/data/indexes"):
                continue
            # A refusal reads no data either: what a wrong verb answers is
            # the same on an empty install and a seeded one.
            if probe.request.method not in ("POST", "GET") or "takes-no-get" in probe.id:
                continue
            assert "makeresults" in content, (
                f"{probe.id} compares values without data on either side"
            )

    def test_every_seeded_probe_uses_the_bootstrap_sourcetype(self) -> None:
        spec = load_spec(ROOT / "probes" / "splunk.yaml")
        for probe in spec.probes:
            if probe.needs_seed:
                assert "${sourcetype}" in str(probe.request.content)

    def test_the_volatile_field_list_is_loaded(self) -> None:
        spec = load_spec(ROOT / "probes" / "splunk.yaml")
        assert "_bkt" in spec.volatile_fields
        assert "splunk_server" in spec.volatile_fields


class TestSeededTextComparison:
    """A seeded probe against a body that is not JSON — Splunk's CSV.

    The first version of `compare_values` parsed both bodies as JSON, so two
    unparsed CSV documents both became `None` and every csv probe agreed with
    itself. A probe that cannot fail is worse than no probe: it reads as
    coverage.
    """

    VOLATILE = frozenset({"_bkt"})

    def _csv(self, text: str) -> Response:
        return Response(200, {"content-type": "text/csv"}, None, "non-json (text/csv)", text)

    def test_two_different_csv_bodies_are_a_finding(self) -> None:
        findings = compare_values(
            "p", self._csv("a\n1\n"), self._csv("a\n2\n"), self.VOLATILE,
        )
        assert [f.kind for f in findings] == ["value"]

    def test_two_identical_csv_bodies_are_not(self) -> None:
        assert compare_values(
            "p", self._csv("a\n1\n"), self._csv("a\n1\n"), self.VOLATILE,
        ) == []

    def test_one_side_answering_json_is_a_type_finding(self) -> None:
        json_side = Response(200, {}, {"a": 1}, "", '{"a": 1}')
        findings = compare_values("p", self._csv("a\n1\n"), json_side, self.VOLATILE)
        assert [f.kind for f in findings] == ["type"]

    def test_a_leading_line_can_be_left_out(self) -> None:
        # splunkd puts a line before a oneshot's CSV that is empty on one run
        # and a single space on the next.
        assert compare_values(
            "p", self._csv("\na\n1\n"), self._csv(" \na\n1\n"), self.VOLATILE,
            ignore_leading_lines=1,
        ) == []

    def test_leaving_it_out_does_not_hide_the_rest(self) -> None:
        findings = compare_values(
            "p", self._csv("\na\n1\n"), self._csv(" \na\n2\n"), self.VOLATILE,
            ignore_leading_lines=1,
        )
        assert [f.kind for f in findings] == ["value"]

    def test_the_probe_file_declares_why_it_skips_one(self) -> None:
        spec = load_spec(ROOT / "probes" / "splunk.yaml")
        skipping = [p for p in spec.probes if p.ignore_leading_lines]
        assert skipping, "the csv probes should skip splunkd's preamble"
        assert all(p.compare_values for p in skipping)
