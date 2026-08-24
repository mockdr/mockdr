"""Splunk time modifiers — ``earliest=-1mon@mon`` and the rest of the grammar.

Snapping used to be modulo arithmetic on epoch seconds. That is right by
accident below a day and wrong above it: the epoch fell on a Thursday, so
``@w`` snapped to a Thursday rather than the preceding Sunday, ``@mon`` to a
multiple of 30 days rather than the first of the month, and ``@y`` to a
multiple of 365 days rather than 1 January. A dashboard asking for "since the
start of last month" got a window off by up to a fortnight, with a 200 and a
plausible-looking event count.
"""
import re
from datetime import UTC, datetime

import pytest

from application.splunk.commands.search import (
    InvalidTimeParameterError,
    _execute_query,
    _validate_time_parameters,
)
from utils.splunk import spl_parser
from utils.splunk.spl_parser import parse_spl, resolve_relative_time

#: Monday, 24 August 2026, 13:30:15 UTC — a Monday, so the weekday cases are
#: not accidentally satisfied by today happening to be the snap target.
NOW = datetime(2026, 8, 24, 13, 30, 15, tzinfo=UTC)


@pytest.fixture(autouse=True)
def _pinned_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pin ``now`` so the expectations are calendar arithmetic, not a race."""
    monkeypatch.setattr(spl_parser, "current_time", lambda: NOW.timestamp())
    monkeypatch.setattr(
        "application.splunk.commands.search.current_time", lambda: NOW.timestamp(),
    )


def resolved(modifier: str) -> str:
    """A modifier as the instant it names, spelled out."""
    return datetime.fromtimestamp(
        resolve_relative_time(modifier), tz=UTC,
    ).strftime("%Y-%m-%d %H:%M:%S %a")


class TestOffsets:
    """The offset half of the grammar."""

    @pytest.mark.parametrize(("modifier", "expected"), [
        ("now", "2026-08-24 13:30:15 Mon"),
        ("-24h", "2026-08-23 13:30:15 Sun"),
        ("-30d", "2026-07-25 13:30:15 Sat"),
        ("+1h", "2026-08-24 14:30:15 Mon"),
        ("-1w", "2026-08-17 13:30:15 Mon"),
        # No count means one, which is how `earliest=-h` is written.
        ("-h", "2026-08-24 12:30:15 Mon"),
        ("-d", "2026-08-23 13:30:15 Sun"),
    ])
    def test_offset_resolves(self, modifier: str, expected: str) -> None:
        assert resolved(modifier) == expected

    def test_a_month_is_a_calendar_month_not_thirty_days(self) -> None:
        # 30 days back from 24 August is 25 July, which is a different month.
        assert resolved("-1mon") == "2026-07-24 13:30:15 Fri"

    def test_a_year_is_a_calendar_year_not_365_days(self) -> None:
        assert resolved("-1y") == "2025-08-24 13:30:15 Sun"

    def test_a_quarter_is_three_calendar_months(self) -> None:
        assert resolved("-1q") == "2026-05-24 13:30:15 Sun"

    def test_month_arithmetic_clamps_the_day(self) -> None:
        # A month back from 31 March is 28 February, not 3 March.
        pinned = datetime(2026, 3, 31, 12, 0, tzinfo=UTC).timestamp()
        assert spl_parser._add_months(pinned, -1) == datetime(
            2026, 2, 28, 12, 0, tzinfo=UTC,
        ).timestamp()

    def test_an_epoch_literal_passes_through(self) -> None:
        assert resolve_relative_time("1787574615") == 1787574615.0

    @pytest.mark.parametrize("modifier", ["-30x", "yesterday", "-", "@"])
    def test_an_expression_outside_the_grammar_is_refused(self, modifier: str) -> None:
        # 0.0 is the caller's "not a usable bound"; guessing a window would
        # filter events the client never asked to exclude.
        assert resolve_relative_time(modifier) == 0.0


class TestSnapping:
    """``@`` snaps down to the start of a unit, on the calendar."""

    @pytest.mark.parametrize(("modifier", "expected"), [
        ("@s", "2026-08-24 13:30:15 Mon"),
        ("@m", "2026-08-24 13:30:00 Mon"),
        ("@h", "2026-08-24 13:00:00 Mon"),
        ("@d", "2026-08-24 00:00:00 Mon"),
        ("@mon", "2026-08-01 00:00:00 Sat"),
        ("@y", "2026-01-01 00:00:00 Thu"),
        # Q3 begins on 1 July.
        ("@q", "2026-07-01 00:00:00 Wed"),
    ])
    def test_snap_resolves(self, modifier: str, expected: str) -> None:
        assert resolved(modifier) == expected

    def test_a_week_snaps_back_to_sunday(self) -> None:
        assert resolved("@w") == "2026-08-23 00:00:00 Sun"

    @pytest.mark.parametrize(("modifier", "expected"), [
        ("@w0", "2026-08-23 00:00:00 Sun"),
        ("@w1", "2026-08-24 00:00:00 Mon"),
        ("@w2", "2026-08-18 00:00:00 Tue"),
        ("@w6", "2026-08-22 00:00:00 Sat"),
    ])
    def test_a_numbered_weekday_snaps_back_to_that_day(
        self, modifier: str, expected: str,
    ) -> None:
        assert resolved(modifier) == expected

    def test_the_offset_applies_before_the_snap(self) -> None:
        assert resolved("-1mon@mon") == "2026-07-01 00:00:00 Wed"
        assert resolved("-1d@d") == "2026-08-23 00:00:00 Sun"

    def test_an_offset_after_the_snap_shifts_the_snapped_instant(self) -> None:
        assert resolved("-1d@d+3h") == "2026-08-23 03:00:00 Sun"
        assert resolved("@d-1h") == "2026-08-23 23:00:00 Sun"

    def test_an_unknown_snap_unit_is_refused(self) -> None:
        assert resolve_relative_time("-1d@zz") == 0.0


class TestSearchIntegration:
    """The modifier reaches the parser from the search string itself."""

    def test_earliest_is_read_off_the_search_clause(self) -> None:
        query = parse_spl("search index=main earliest=-1mon@mon latest=@d")
        assert query.earliest_time == "-1mon@mon"
        assert query.latest_time == "@d"
        assert resolved(query.earliest_time) == "2026-07-01 00:00:00 Wed"


class TestTimeTermDiagnostics:
    """What splunkd says — and returns — when a time term is not usable.

    Measured against Splunk 9: an unreadable term in the search string is a
    FATAL message inside a 200 with no results, the same value as a request
    parameter is a 400, and a readable term written into the search draws an
    INFO line. The mock used to drop the bound it could not read and answer
    with every event in the index, so a typo produced a full result set here
    and an empty one in production.
    """

    def _run(self, search: str) -> tuple[list, list]:
        _events, results, messages = _execute_query(parse_spl(search))
        return results, messages

    def test_an_unreadable_earliest_yields_no_results_and_a_fatal(self) -> None:
        results, messages = self._run("search index=sentinelone earliest=-30x")
        assert results == []
        assert messages == [{
            "type": "FATAL",
            "text": 'Invalid value "-30x" for time term \'earliest\'',
        }]

    def test_an_unreadable_latest_names_that_term(self) -> None:
        _results, messages = self._run("search index=sentinelone latest=nope")
        assert messages[0]["text"] == 'Invalid value "nope" for time term \'latest\''

    def test_only_the_first_bad_term_is_reported(self) -> None:
        _results, messages = self._run(
            "search index=sentinelone earliest=-30x latest=alsobad",
        )
        assert len(messages) == 1
        assert "earliest" in messages[0]["text"]

    def test_an_inverted_window_is_a_parse_failure_quoting_both_epochs(self) -> None:
        results, messages = self._run(
            "search index=sentinelone earliest=now latest=-1d",
        )
        assert results == []
        assert messages[0]["type"] == "FATAL"
        assert messages[0]["text"] == (
            "Error in 'search' command: Unable to parse the search: "
            f"Invalid time bounds in search: start={int(NOW.timestamp())} > "
            f"end={int(NOW.timestamp()) - 86400}."
        )

    def test_equal_bounds_in_the_search_string_are_accepted(self) -> None:
        _results, messages = self._run(
            "search index=sentinelone earliest=-5m latest=-5m",
        )
        assert messages[0]["type"] == "INFO"

    def test_a_readable_term_in_the_search_draws_the_info_line(self) -> None:
        _results, messages = self._run("search index=sentinelone earliest=-5m")
        assert messages == [{
            "type": "INFO",
            "text": "Your timerange was substituted based on your search string",
        }]

    def test_a_search_without_time_terms_says_nothing(self) -> None:
        _results, messages = self._run("search index=sentinelone | head 1")
        assert messages == []


class TestTimeParameters:
    """The same values as request parameters, which splunkd refuses outright."""

    @pytest.mark.parametrize(("params", "message"), [
        ({"earliest_time": "-30x"}, "Invalid earliest_time."),
        ({"latest_time": "nope"},
         "Invalid latest_time: latest_time must be after earliest_time."),
        ({"earliest_time": "-5m", "latest_time": "-5m"},
         "Invalid latest_time: latest_time must be after earliest_time."),
        ({"earliest_time": "now", "latest_time": "-1d"},
         "Invalid latest_time: latest_time must be after earliest_time."),
    ])
    def test_an_unusable_parameter_is_refused(
        self, params: dict, message: str,
    ) -> None:
        with pytest.raises(InvalidTimeParameterError, match=re.escape(message)):
            _validate_time_parameters(
                params.get("earliest_time", ""), params.get("latest_time", ""),
            )

    @pytest.mark.parametrize("params", [
        {"earliest_time": "-5m"},
        {"latest_time": "-1d"},
        {"earliest_time": "-1d", "latest_time": "now"},
        {},
    ])
    def test_a_usable_pair_passes(self, params: dict) -> None:
        _validate_time_parameters(
            params.get("earliest_time", ""), params.get("latest_time", ""),
        )
