"""A client-supplied regex that backtracks catastrophically is refused.

Each engine mockdr imitates runs a client pattern without exponential
blow-up (Lucene's automaton, Kusto's RE2, splunkd's PCRE2 backtrack limit);
Python's ``re`` does not. ``^(a+)+$`` against a 30-character subject held a
worker for 26 seconds here before the guard, from one request with the
documented credentials.
"""
from __future__ import annotations

import time

import pytest

from utils.safe_regex import UnsafeRegexError, check_regex
from utils.splunk.spl_exec import execute_pipeline
from utils.splunk.spl_parser import parse_spl

HOSTILE = "^(a+)+$"
SUBJECT = "a" * 40 + "!"


@pytest.mark.parametrize("pattern", ["^(a+)+$", "(a*)*", "(a+)*b", "((ab)+)+"])
def test_nested_unbounded_quantifiers_are_refused(pattern: str) -> None:
    with pytest.raises(UnsafeRegexError):
        check_regex(pattern)


@pytest.mark.parametrize("pattern", [r"(?:foo|bar)+", r"\d{1,5}-\w+", r"([a-z]+\.)+", "(abc)+x"])
def test_ordinary_patterns_are_allowed(pattern: str) -> None:
    check_regex(pattern)  # does not raise


def test_spl_regex_command_refuses_the_hostile_pattern_promptly() -> None:
    started = time.perf_counter()
    rows, messages = execute_pipeline(
        [], parse_spl(f'| makeresults | eval x="{SUBJECT}" | regex x="{HOSTILE}"'),
    )
    assert time.perf_counter() - started < 2
    assert rows == []
    assert messages[0]["type"] == "FATAL"


def test_kvstore_regex_selects_nothing_promptly() -> None:
    """The KV store's ``$regex`` ran unguarded: twenty-five seconds for this one."""
    from utils.splunk.kvstore_query import apply_query

    started = time.perf_counter()
    found = apply_query([{"user": SUBJECT}], f'{{"user": {{"$regex": "{HOSTILE}"}}}}')
    assert time.perf_counter() - started < 2
    assert found == []


def test_kvstore_regex_that_does_not_compile_selects_nothing() -> None:
    """It raised re.error out of the handler as a 500."""
    from utils.splunk.kvstore_query import apply_query

    assert apply_query([{"user": "x"}], '{"user": {"$regex": "("}}') == []
    assert apply_query([{"user": "abc"}], '{"user": {"$regex": "^a"}}') == [{"user": "abc"}]


def test_spl_match_function_refuses_the_hostile_pattern_promptly() -> None:
    started = time.perf_counter()
    _rows, messages = execute_pipeline(
        [], parse_spl(f'| makeresults | eval y=if(match("{SUBJECT}", "{HOSTILE}"), 1, 0)'),
    )
    assert time.perf_counter() - started < 2
    assert messages and messages[0]["type"] == "FATAL"
