"""The query clauses a SIEM client sends, measured against Elasticsearch 8.15.

`prefix`, `regexp`, `fuzzy`, `ids`, `multi_match`, `simple_query_string`,
`match_phrase_prefix`, `match_bool_prefix`, `terms_set` and the three
wrappers were all "unknown query" here, so a detection rule or a Kibana
search bar that used one got a 400 from the mock and hits from the cluster.
53 searches were run against a real cluster and this one and compared.

mockdr does not hold the index mapping while it filters, so a term is tried
against the field's own value *and* against its analysed tokens: `prefix` on
a keyword field compares the whole value, and on a text field a token. Three
differences are left in place deliberately: a `nested` query (mockdr models
no nested mappings), a `script` query (it does not run Painless), and a
`terms` aggregation over a text field, which a real cluster refuses because
fielddata is off — the mock has no mapping to refuse it from.
"""
import pytest

from utils.es_query import ESQueryError, apply_es_query

DOCS = [
    {"id": "1", "host": "srv-1", "message": "failed login attempt",
     "ip": "10.0.0.1", "tags": ["auth", "linux"], "sev": 10},
    {"id": "2", "host": "srv-2", "message": "Login succeeded for alice",
     "ip": "10.0.1.9", "tags": ["auth"], "sev": 20},
    {"id": "3", "host": "srv-10", "message": "malware detected on host",
     "ip": "192.168.0.5", "tags": ["edr", "linux"], "sev": 30},
    {"id": "4", "host": "web-1", "message": "process created cmd.exe",
     "ip": "192.168.0.6", "tags": [], "sev": 40},
]


def ids(query: dict, docs: list[dict] | None = None) -> list[str]:
    """The ids a query selects, in id order."""
    body = {"query": query, "size": 100}
    return sorted(r["id"] for r in apply_es_query(list(docs or DOCS), body))


class TestPrefix:
    """``prefix``, on a keyword value and on an analysed one."""

    def test_a_keyword_prefix_matches_the_whole_value(self) -> None:
        assert ids({"prefix": {"host": "srv"}}) == ["1", "2", "3"]

    def test_the_object_form_says_the_same(self) -> None:
        assert ids({"prefix": {"host": {"value": "srv"}}}) == ["1", "2", "3"]

    def test_a_text_prefix_matches_a_token(self) -> None:
        # "log" is not how either message starts; it is how a word in them does.
        assert ids({"prefix": {"message": "log"}}) == ["1", "2"]


class TestRegexp:
    """``regexp``, which Lucene anchors."""

    def test_the_pattern_must_match_the_whole_value(self) -> None:
        assert ids({"regexp": {"host": "srv-[0-9]+"}}) == ["1", "2", "3"]

    def test_a_partial_match_is_not_enough(self) -> None:
        assert ids({"regexp": {"host": "srv"}}) == []

    def test_a_pattern_that_will_not_compile_is_a_shard_failure(self) -> None:
        # Not a parsing error: the shards are what try to run it.
        with pytest.raises(ESQueryError) as caught:
            apply_es_query(DOCS, {"query": {"regexp": {"host": "["}}})
        assert caught.value.shard_failure is True


class TestFuzzy:
    """``fuzzy``, and how ``AUTO`` reads."""

    def test_one_edit_away_matches(self) -> None:
        assert ids({"fuzzy": {"host": {"value": "srv-2", "fuzziness": 1}}}) == ["1", "2"]

    def test_auto_allows_nothing_below_three_characters(self) -> None:
        assert ids({"fuzzy": {"host": {"value": "srx"}}}) == []


class TestIds:
    """``ids`` selects by ``_id``."""

    def test_the_named_documents_come_back(self) -> None:
        assert ids({"ids": {"values": ["1", "3"]}}) == ["1", "3"]

    def test_an_id_no_document_has_selects_nothing(self) -> None:
        assert ids({"ids": {"values": ["nope"]}}) == []


class TestMultiMatch:
    """One query over several fields."""

    def test_any_of_the_named_fields_may_match(self) -> None:
        assert ids({"multi_match": {"query": "login", "fields": ["message", "host"]}}) == ["1", "2"]

    def test_a_phrase_needs_the_words_in_order(self) -> None:
        query = {"multi_match": {"query": "failed login", "fields": ["message"],
                                 "type": "phrase"}}
        assert ids(query) == ["1"]

    def test_a_wildcard_reads_every_field(self) -> None:
        assert ids({"multi_match": {"query": "malware", "fields": ["*"]}}) == ["3"]

    def test_operator_and_needs_every_word(self) -> None:
        query = {"multi_match": {"query": "failed login", "fields": ["message"],
                                 "operator": "and"}}
        assert ids(query) == ["1"]


class TestSimpleQueryString:
    """The forgiving sibling of ``query_string``."""

    def test_a_pipe_is_or(self) -> None:
        query = {"simple_query_string": {"query": "login | malware", "fields": ["message"]}}
        assert ids(query) == ["1", "2", "3"]

    def test_a_minus_negates_its_own_clause(self) -> None:
        # Not an exclusion: under the default `or`, "login -alice" is every
        # document that either says login or does not say alice.
        query = {"simple_query_string": {"query": "login -alice", "fields": ["message"]}}
        assert ids(query) == ["1", "2", "3", "4"]

    def test_and_excludes_once_the_operator_is_and(self) -> None:
        query = {"simple_query_string": {"query": "login -alice", "fields": ["message"],
                                         "default_operator": "and"}}
        assert ids(query) == ["1"]

    def test_a_tilde_is_an_edit_distance(self) -> None:
        query = {"simple_query_string": {"query": "logn~1", "fields": ["message"]}}
        assert ids(query) == ["1", "2"]

    def test_a_plus_requires(self) -> None:
        query = {"simple_query_string": {"query": "+login +failed", "fields": ["message"]}}
        assert ids(query) == ["1"]

    def test_quotes_make_a_phrase(self) -> None:
        query = {"simple_query_string": {"query": '"failed login"', "fields": ["message"]}}
        assert ids(query) == ["1"]

    def test_a_star_is_a_prefix(self) -> None:
        query = {"simple_query_string": {"query": "mal*", "fields": ["message"]}}
        assert ids(query) == ["3"]


class TestPhrasePrefixes:
    """``match_phrase_prefix`` and ``match_bool_prefix``."""

    def test_a_phrase_whose_last_word_is_a_prefix(self) -> None:
        assert ids({"match_phrase_prefix": {"message": "failed log"}}) == ["1"]

    def test_the_words_still_have_to_be_in_order(self) -> None:
        assert ids({"match_phrase_prefix": {"message": "log failed"}}) == []

    def test_bool_prefix_takes_the_last_word_as_a_prefix(self) -> None:
        assert ids({"match_bool_prefix": {"message": "log"}}) == ["1", "2"]


class TestWrappers:
    """The clauses that only re-shape another one."""

    def test_constant_score_runs_its_filter(self) -> None:
        assert ids({"constant_score": {"filter": {"term": {"host": "srv-1"}}}}) == ["1"]

    def test_dis_max_matches_any_of_its_queries(self) -> None:
        query = {"dis_max": {"queries": [{"term": {"host": "srv-1"}},
                                         {"term": {"host": "srv-2"}}]}}
        assert ids(query) == ["1", "2"]

    def test_boosting_only_demotes(self) -> None:
        # The negative side changes the score, not whether a document matches.
        query = {"boosting": {"positive": {"match_all": {}},
                              "negative": {"term": {"host": "srv-1"}},
                              "negative_boost": 0.1}}
        assert ids(query) == ["1", "2", "3", "4"]


class TestTermsSet:
    """``terms_set``: how many of the terms have to match."""

    def test_a_constant_script_says_how_many(self) -> None:
        query = {"terms_set": {"tags": {"terms": ["auth", "linux"],
                                        "minimum_should_match_script": {"source": "2"}}}}
        assert ids(query) == ["1"]

    def test_one_is_enough_when_one_is_asked_for(self) -> None:
        query = {"terms_set": {"tags": {"terms": ["auth", "linux"],
                                        "minimum_should_match_script": {"source": "1"}}}}
        assert ids(query) == ["1", "2", "3"]

    def test_a_field_can_say_how_many(self) -> None:
        docs = [{"id": "1", "tags": ["a", "b"], "need": 2},
                {"id": "2", "tags": ["a"], "need": 2}]
        query = {"terms_set": {"tags": {"terms": ["a", "b"],
                                        "minimum_should_match_field": "need"}}}
        assert ids(query, docs) == ["1"]


class TestMatchSemantics:
    """What ``match`` does beyond splitting on spaces."""

    def test_minimum_should_match_counts_the_terms(self) -> None:
        query = {"match": {"message": {"query": "login failed malware",
                                       "minimum_should_match": 2}}}
        # Ignoring it made this an OR: three documents instead of one.
        assert ids(query) == ["1"]

    @pytest.mark.parametrize(("spec", "expected"), [
        ("60%", ["1", "2", "3"]), ("70%", ["1"]), (-1, ["1"]), (3, []),
    ])
    def test_a_share_of_them_rounds_down(self, spec: object, expected: list) -> None:
        # 60% of three terms is one, not two; a negative is how many may be
        # missing rather than how many must match.
        query = {"match": {"message": {"query": "login failed malware",
                                       "minimum_should_match": spec}}}
        assert ids(query) == expected


class TestWildcard:
    """``wildcard``, which is case-sensitive on a keyword."""

    def test_a_keyword_pattern_is_matched_as_written(self) -> None:
        assert ids({"wildcard": {"host": "srv-*"}}) == ["1", "2", "3"]

    def test_and_a_pattern_in_the_wrong_case_matches_nothing(self) -> None:
        assert ids({"wildcard": {"host": "SRV-*"}}) == []

    def test_case_insensitive_asks_for_the_other_behaviour(self) -> None:
        query = {"wildcard": {"host": {"value": "SRV-*", "case_insensitive": True}}}
        assert ids(query) == ["1", "2", "3"]

    def test_a_text_field_matches_a_token(self) -> None:
        assert ids({"wildcard": {"message": "log*"}}) == ["1", "2"]


class TestTermAndExists:
    """Two rules a real cluster follows and the mock did not."""

    def test_a_term_on_an_ip_field_takes_a_network(self) -> None:
        assert ids({"term": {"ip": "10.0.0.0/24"}}) == ["1"]

    def test_an_empty_array_is_not_a_value(self) -> None:
        # Document 4 carries `tags: []`, which indexes nothing at all.
        assert ids({"exists": {"field": "tags"}}) == ["1", "2", "3"]
