"""Elasticsearch query DSL conformance regressions.

Each test here pins a behaviour where the interpreter previously answered a
well-formed client request with something a real cluster never returns — a
fresh ``_id`` per response, a plain-text 500, or a silently dropped clause.
"""
import pytest

from utils.es_query import (
    ESQueryError,
    apply_es_query,
    apply_source_filter,
    wrap_as_hits,
)


class TestHitIdStability:
    """``_id`` must identify the document, not the response."""

    def test_same_record_keeps_the_same_id_across_calls(self) -> None:
        rec = {"id": "abc-123", "hostname": "SERVER-1"}
        first = wrap_as_hits([rec])[0]["_id"]
        second = wrap_as_hits([rec])[0]["_id"]
        assert first == second

    def test_id_is_the_documents_own_identifier(self) -> None:
        assert wrap_as_hits([{"id": "abc-123"}])[0]["_id"] == "abc-123"

    def test_records_without_an_id_field_still_get_a_stable_id(self) -> None:
        rec = {"hostname": "SERVER-1", "port": 443}
        assert wrap_as_hits([rec])[0]["_id"] == wrap_as_hits([dict(rec)])[0]["_id"]

    def test_distinct_records_get_distinct_ids(self) -> None:
        hits = wrap_as_hits([{"hostname": "A"}, {"hostname": "B"}])
        assert hits[0]["_id"] != hits[1]["_id"]


class TestQueryParsingErrors:
    """Unparseable bodies raise, so the app can answer 400 rather than 500."""

    @pytest.mark.parametrize(
        "query_type", ["prefix", "ids", "multi_match", "nested", "regexp", "fuzzy"],
    )
    def test_unsupported_query_type_raises(self, query_type: str) -> None:
        with pytest.raises(ESQueryError):
            apply_es_query([], {"query": {query_type: {"field": "value"}}})

    def test_multiple_clauses_in_one_query_object_are_rejected(self) -> None:
        # Real ES: "malformed query, expected [END_OBJECT]". Previously the
        # first key won and every later clause was discarded.
        with pytest.raises(ESQueryError):
            apply_es_query([], {
                "query": {
                    "term": {"severity": "low"},
                    "range": {"risk_score": {"gte": 99999}},
                },
            })


class TestBoolMinimumShouldMatch:
    """``should`` only carries a match requirement without must/filter."""

    RECORDS = [{"severity": "low"}, {"severity": "high"}]

    def test_non_matching_should_does_not_filter_when_must_present(self) -> None:
        body = {
            "query": {"bool": {
                "must": [{"exists": {"field": "severity"}}],
                "should": [{"term": {"severity": "never-matches"}}],
            }},
            "size": 100,
        }
        assert len(apply_es_query(self.RECORDS, body)) == 2

    def test_non_matching_should_does_not_filter_when_filter_present(self) -> None:
        body = {
            "query": {"bool": {
                "filter": [{"exists": {"field": "severity"}}],
                "should": [{"term": {"severity": "never-matches"}}],
            }},
            "size": 100,
        }
        assert len(apply_es_query(self.RECORDS, body)) == 2

    def test_should_alone_still_requires_one_match(self) -> None:
        body = {
            "query": {"bool": {"should": [{"term": {"severity": "low"}}]}},
            "size": 100,
        }
        assert len(apply_es_query(self.RECORDS, body)) == 1

    def test_explicit_minimum_should_match_is_honoured(self) -> None:
        body = {
            "query": {"bool": {
                "must": [{"exists": {"field": "severity"}}],
                "should": [{"term": {"severity": "never-matches"}}],
                "minimum_should_match": 1,
            }},
            "size": 100,
        }
        assert apply_es_query(self.RECORDS, body) == []


class TestDefaultSize:
    """An omitted ``size`` means 10, not "the whole index"."""

    def test_omitted_size_caps_at_ten(self) -> None:
        records = [{"id": str(n)} for n in range(50)]
        assert len(apply_es_query(records, {})) == 10

    def test_explicit_size_overrides_the_default(self) -> None:
        records = [{"id": str(n)} for n in range(50)]
        assert len(apply_es_query(records, {"size": 25})) == 25


class TestSourceFiltering:
    """``_source`` selects which fields come back, and was ignored."""

    HITS = [
        {"_index": "i", "_id": "1", "_score": 1.0,
         "_source": {"host": "a", "port": 1, "user_name": "u", "user_id": 7}},
    ]

    def test_none_returns_hits_unchanged(self) -> None:
        assert apply_source_filter(self.HITS, None) == self.HITS

    def test_false_drops_the_source_entirely(self) -> None:
        hit = apply_source_filter(self.HITS, False)[0]
        assert "_source" not in hit
        assert hit["_id"] == "1"

    def test_list_keeps_only_named_fields(self) -> None:
        hit = apply_source_filter(self.HITS, ["host", "port"])[0]
        assert hit["_source"] == {"host": "a", "port": 1}

    def test_bare_string_is_treated_as_one_field(self) -> None:
        assert apply_source_filter(self.HITS, "host")[0]["_source"] == {"host": "a"}

    def test_wildcards_are_honoured(self) -> None:
        hit = apply_source_filter(self.HITS, ["user_*"])[0]
        assert hit["_source"] == {"user_name": "u", "user_id": 7}

    def test_includes_and_excludes_combine(self) -> None:
        hit = apply_source_filter(
            self.HITS, {"includes": ["user_*"], "excludes": ["user_id"]},
        )[0]
        assert hit["_source"] == {"user_name": "u"}

    def test_metadata_fields_are_preserved(self) -> None:
        hit = apply_source_filter(self.HITS, ["host"])[0]
        assert hit["_index"] == "i"
        assert hit["_score"] == 1.0
