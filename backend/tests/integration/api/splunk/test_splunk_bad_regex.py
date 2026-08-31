"""A regular expression splunkd's PCRE2 refuses, refused in its words.

mockdr compiled a client's pattern with Python's `re` and let
`re.PatternError` escape the handler, so `| rex field=_raw "(?P<bad>["`
answered 500 — where splunkd answers 200 with a FATAL message and no rows.
A client cannot tell a broken search from a broken server through a 500, and
retries the one thing that will never work.

Every sentence below was measured on Splunk 10.4.2 against
`search index=main`, one pattern per PCRE2 error, and is reproduced here
verbatim: CI has no splunkd, so the strings are the oracle.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

AUTH = {"Authorization": "Basic YWRtaW46bW9ja2RyLWFkbWlu"}  # admin:mockdr-admin

#: `rex` quotes the pattern back and ends in a full stop.
_REX = "Error in 'rex' command: Encountered the following error while " \
       "compiling the regex '{pattern}': Regex: {clause}."

#: PCRE2's own name for each error, measured one pattern at a time.
BAD_PATTERNS = [
    ("(?P<bad>[", "missing terminating ] for character class"),
    ("(?P<bad>", "missing closing parenthesis"),
    ("a**", "quantifier does not follow a repeatable item"),
    ("*a", "quantifier does not follow a repeatable item"),
    ("(?P<1bad>x)", "subpattern name must start with a non-digit"),
    ("a{3,1}", "numbers out of order in {} quantifier"),
    ("[z-a]", "range out of order in character class"),
    ("(?P<x>a)(?P<x>b)",
     "two named subpatterns have the same name (PCRE2_DUPNAMES not set)"),
    ("a)", "unmatched closing parenthesis"),
    # Truncated, and in splunkd's own `(?<name>` spelling: `_cmd_rex` rewrites
    # it to Python's before compiling, so `re` names this error differently
    # than it names the same truncation written `(?P<`.  One PCRE2 clause.
    ("(?<", "subpattern name expected"),
]


def _messages(client: TestClient, search: str) -> list[dict[str, str]]:
    resp = client.post("/splunk/services/search/jobs", headers=AUTH,
                       data={"search": search, "exec_mode": "oneshot"})
    assert resp.status_code == 200, resp.text
    return list(resp.json().get("messages") or [])


class TestRexRefusesInPcreWords:
    @pytest.mark.parametrize(("pattern", "clause"), BAD_PATTERNS)
    def test_the_message_is_splunkds(
        self, client: TestClient, pattern: str, clause: str,
    ) -> None:
        messages = _messages(
            client, f'search index=sentinelone | rex field=_raw "{pattern}" '
                    f'| stats count')
        assert messages == [{
            "type": "FATAL", "text": _REX.format(pattern=pattern, clause=clause),
        }]

    def test_a_pattern_that_compiles_still_extracts(
        self, client: TestClient,
    ) -> None:
        """The guard must not refuse splunkd's own `(?<name>` spelling."""
        resp = client.post("/splunk/services/search/jobs", headers=AUTH, data={
            "search": r'search index=sentinelone | rex field=_raw "(?<w>\w+)" '
                      r'| stats count',
            "exec_mode": "oneshot"})
        body = resp.json()
        assert not body.get("messages")
        assert body["results"] == [{"count": "210"}]


class TestTheOtherTwoCommandsWordItDifferently:
    """Same clause, three sentences — measured, not assumed."""

    def test_regex_names_the_operator_and_calls_it_invalid(
        self, client: TestClient,
    ) -> None:
        for search in ('search index=sentinelone | regex _raw="(?P<b>[" | stats count',
                       'search index=sentinelone | regex "(?P<b>[" | stats count'):
            assert _messages(client, search) == [{
                "type": "FATAL",
                "text": "Error in 'SearchOperator:regex': The regex '(?P<b>[' "
                        "is invalid. Regex: missing terminating ] for "
                        "character class.",
            }], search

    def test_eval_neither_quotes_the_pattern_nor_ends_in_a_stop(
        self, client: TestClient,
    ) -> None:
        assert _messages(
            client,
            'search index=sentinelone | eval y=replace(_raw,"(?P<b>[","x") '
            '| stats count',
        ) == [{
            "type": "FATAL",
            "text": "Error in 'EvalCommand': Regex: missing terminating ] "
                    "for character class",
        }]


class TestAnUnmeasuredErrorIsStillNotA500:
    """Python's own wording, rather than a guess at PCRE2's — but a 200."""

    def test_it_answers_fatal_and_not_five_hundred(
        self, client: TestClient,
    ) -> None:
        messages = _messages(
            client, r'search index=sentinelone | rex field=_raw "(?P<a-b>x)" '
                    r'| stats count')
        assert len(messages) == 1
        assert messages[0]["type"] == "FATAL"
        assert messages[0]["text"].startswith(
            "Error in 'rex' command: Encountered the following error")
