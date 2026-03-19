"""Unit tests for the KQL query parser."""
from utils.sentinel.kql_parser import parse_kql


class TestParseKQL:
    """Tests for parse_kql function."""

    def test_simple_table(self) -> None:
        q = parse_kql("SecurityIncident")
        assert q.tables == ["SecurityIncident"]

    def test_table_with_take(self) -> None:
        q = parse_kql("SecurityIncident | take 50")
        assert q.tables == ["SecurityIncident"]
        assert q.take == 50

    def test_table_with_limit(self) -> None:
        q = parse_kql("SecurityAlert | limit 10")
        assert q.take == 10

    def test_where_equals(self) -> None:
        q = parse_kql('SecurityIncident | where Status == "New"')
        assert len(q.where_clauses) == 1
        assert q.where_clauses[0] == ("Status", "==", "New")

    def test_where_not_equals(self) -> None:
        q = parse_kql('SecurityIncident | where Status != "Closed"')
        assert q.where_clauses[0] == ("Status", "!=", "Closed")

    def test_where_in(self) -> None:
        q = parse_kql('SecurityIncident | where Severity in ("High", "Medium")')
        assert len(q.where_in_clauses) == 1
        assert q.where_in_clauses[0][0] == "Severity"
        assert q.where_in_clauses[0][1] == ["High", "Medium"]

    def test_where_ago(self) -> None:
        q = parse_kql("SecurityAlert | where TimeGenerated > ago(24h)")
        assert len(q.ago_filters) == 1
        assert q.ago_filters[0][0] == "TimeGenerated"
        assert q.ago_filters[0][1] > 0

    def test_project(self) -> None:
        q = parse_kql("SecurityIncident | project Title, Severity, Status")
        assert q.project_fields == ["Title", "Severity", "Status"]

    def test_sort_by_desc(self) -> None:
        q = parse_kql("SecurityIncident | sort by CreatedTime desc")
        assert q.sort_field == "CreatedTime"
        assert q.sort_descending is True

    def test_sort_by_asc(self) -> None:
        q = parse_kql("SecurityIncident | sort by IncidentNumber asc")
        assert q.sort_field == "IncidentNumber"
        assert q.sort_descending is False

    def test_summarize_count_by(self) -> None:
        q = parse_kql("SecurityIncident | summarize count() by Severity")
        assert q.summarize_func == "count"
        assert q.summarize_by == "Severity"

    def test_extend(self) -> None:
        q = parse_kql("SecurityIncident | extend Custom = strcat(Title, Severity)")
        assert "Custom" in q.extend_fields

    def test_union_tables(self) -> None:
        q = parse_kql("union SecurityIncident, SecurityAlert | take 10")
        assert q.tables == ["SecurityIncident", "SecurityAlert"]
        assert q.take == 10

    def test_pipeline_multiple(self) -> None:
        q = parse_kql('SecurityIncident | where Severity == "High" | sort by CreatedTime desc | take 5')
        assert q.where_clauses[0] == ("Severity", "==", "High")
        assert q.sort_field == "CreatedTime"
        assert q.sort_descending is True
        assert q.take == 5

    def test_top(self) -> None:
        q = parse_kql("SecurityIncident | top 20")
        assert q.take == 20
