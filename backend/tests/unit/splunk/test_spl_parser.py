"""Unit tests for the SPL query parser."""
from utils.splunk.spl_parser import parse_spl, resolve_relative_time


class TestParseSPL:
    """Tests for parse_spl function."""

    def test_basic_index_filter(self) -> None:
        q = parse_spl("search index=sentinelone")
        assert q.index == "sentinelone"

    def test_index_and_sourcetype(self) -> None:
        q = parse_spl("search index=crowdstrike sourcetype=CrowdStrike:Event:Streams:JSON")
        assert q.index == "crowdstrike"
        assert q.sourcetype == "CrowdStrike:Event:Streams:JSON"

    def test_quoted_value(self) -> None:
        q = parse_spl('search index=main sourcetype="my:custom:type"')
        assert q.sourcetype == "my:custom:type"

    def test_field_filters(self) -> None:
        q = parse_spl("search index=sentinelone severity=high hostname=WKSTN-001")
        assert q.field_filters["severity"] == "high"
        assert q.field_filters["hostname"] == "WKSTN-001"

    def test_host_is_parsed_as_builtin(self) -> None:
        q = parse_spl("search index=sentinelone host=WKSTN-001")
        assert q.host == "WKSTN-001"

    def test_notable_macro(self) -> None:
        q = parse_spl("`notable`")
        assert q.is_notable is True
        assert q.index == "notable"

    def test_head_command(self) -> None:
        q = parse_spl("search index=main | head 10")
        assert q.head == 10

    def test_tail_command(self) -> None:
        q = parse_spl("search index=main | tail 5")
        assert q.tail == 5

    def test_table_command(self) -> None:
        q = parse_spl("search index=main | table _time host source sourcetype")
        assert q.table_fields == ["_time", "host", "source", "sourcetype"]

    def test_stats_count_by(self) -> None:
        q = parse_spl("search index=sentinelone | stats count by sourcetype")
        assert q.stats_count_by == "sourcetype"

    def test_sort_ascending(self) -> None:
        q = parse_spl("search index=main | sort _time")
        assert q.sort_field == "_time"
        assert q.sort_descending is False

    def test_sort_descending(self) -> None:
        q = parse_spl("search index=main | sort -_time")
        assert q.sort_field == "_time"
        assert q.sort_descending is True

    def test_where_clause(self) -> None:
        q = parse_spl("search index=main | where severity=high")
        assert len(q.where_clauses) == 1
        assert q.where_clauses[0] == ("severity", "high")

    def test_rename_command(self) -> None:
        q = parse_spl("search index=main | rename old_field as new_field")
        assert q.renames == {"old_field": "new_field"}

    def test_eval_command(self) -> None:
        q = parse_spl("search index=main | eval combined=field1+field2")
        assert "combined" in q.evals

    def test_pipeline_with_multiple_commands(self) -> None:
        q = parse_spl("search index=sentinelone | where severity=high | head 5 | table _time host severity")
        assert q.index == "sentinelone"
        assert len(q.where_clauses) == 1
        assert q.head == 5
        assert q.table_fields == ["_time", "host", "severity"]

    def test_time_modifiers(self) -> None:
        q = parse_spl("search index=main earliest=-24h latest=now")
        assert q.earliest_time == "-24h"
        assert q.latest_time == "now"

    def test_without_search_prefix(self) -> None:
        q = parse_spl("index=sentinelone sourcetype=sentinelone:channel:threats")
        assert q.index == "sentinelone"
        assert q.sourcetype == "sentinelone:channel:threats"


class TestResolveRelativeTime:
    """Tests for resolve_relative_time function."""

    def test_now(self) -> None:
        import time
        result = resolve_relative_time("now")
        assert abs(result - time.time()) < 2

    def test_relative_hours(self) -> None:
        import time
        result = resolve_relative_time("-24h")
        expected = time.time() - (24 * 3600)
        assert abs(result - expected) < 2

    def test_relative_days(self) -> None:
        import time
        result = resolve_relative_time("-7d")
        expected = time.time() - (7 * 86400)
        assert abs(result - expected) < 2

    def test_snap_modifier(self) -> None:
        result = resolve_relative_time("-1h@h")
        assert result > 0

    def test_epoch_literal(self) -> None:
        result = resolve_relative_time("1710590400")
        assert result == 1710590400.0

    def test_empty_string(self) -> None:
        result = resolve_relative_time("")
        assert result == 0.0
