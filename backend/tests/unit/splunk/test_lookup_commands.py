"""``inputlookup`` and ``lookup``, the two commands ES content reads tables with.

Both were unknown commands here, so a correlation search that enriched its
results from a threat-intel collection — or a playbook that read the
`splunk_xsoar_users` mapping with `| inputlookup` — was refused outright.

The rules below are the Search Reference's (inputlookup and lookup command
pages) and transforms.conf's defaults: a lookup compares case-sensitively,
takes up to 1000 matches per value and writes several as a multivalue;
``OUTPUT`` overwrites, so a row that matches nothing loses the field, and
``OUTPUTNEW`` writes only what a row lacks. The refusals are splunkd's own
lines for a table it does not have and for a field the table does not hold.
"""
from tests.unit.splunk.sources import FakeSources, failure, out
from utils.splunk.spl_data_cmds import MAX_RESULT_ROWS
from utils.splunk.spl_exec import execute_pipeline
from utils.splunk.spl_parser import parse_spl
from utils.splunk.spl_sources import LookupTable

INTEL = LookupTable(
    name="ip_intel",
    fields=["_key", "ip", "threat_key", "weight"],
    rows=[
        {"_key": "k1", "ip": "203.0.113.10", "threat_key": "c2", "weight": 3},
        {"_key": "k2", "ip": "203.0.113.20", "threat_key": "tor", "weight": 1},
        {"_key": "k3", "ip": "203.0.113.20", "threat_key": "scanner", "weight": 2},
    ],
)
ASSETS = LookupTable(
    name="assets",
    fields=["nt_host", "owner", "category"],
    rows=[
        {"nt_host": "SRV-1", "owner": "alice", "category": "server"},
        {"nt_host": "WKS-2", "owner": "bob", "category": "laptop"},
        {"nt_host": "WKS-3", "category": "laptop"},
    ],
)
SOURCES = FakeSources({"ip_intel": INTEL, "assets": ASSETS, "assets.csv": ASSETS})

#: Three rows to enrich.
EVENTS = '| makeresults format=csv data="ip,host\n203.0.113.10,SRV-1\n203.0.113.20,wks-2\n198.51.100.1,WKS-3" '


class TestInputlookup:
    """A lookup table read as search results."""

    def test_every_row_in_the_table_order_with_its_fields(self) -> None:
        assert out("| inputlookup assets", SOURCES) == ASSETS.rows

    def test_a_field_a_row_lacks_is_not_written(self) -> None:
        assert "owner" not in out("| inputlookup assets", SOURCES)[2]

    def test_a_csv_file_is_read_by_its_file_name(self) -> None:
        assert len(out("| inputlookup assets.csv", SOURCES)) == 3

    def test_where_is_a_search_expression_with_wildcards(self) -> None:
        rows = out('| inputlookup assets where nt_host="wks*" AND NOT owner=bob', SOURCES)
        assert [r["nt_host"] for r in rows] == ["WKS-3"]

    def test_where_compares_numbers_as_numbers(self) -> None:
        assert [r["_key"] for r in out("| inputlookup ip_intel where weight>1", SOURCES)] == [
            "k1", "k3",
        ]

    def test_start_skips_and_max_caps(self) -> None:
        rows = out("| inputlookup start=1 max=1 ip_intel", SOURCES)
        assert [r["_key"] for r in rows] == ["k2"]

    def test_append_adds_the_table_after_the_rows_there(self) -> None:
        rows = out(EVENTS + "| inputlookup append=t assets", SOURCES)
        assert len(rows) == 6 and rows[3] == ASSETS.rows[0]

    def test_without_append_it_must_begin_the_search(self) -> None:
        assert failure(EVENTS + "| inputlookup assets", SOURCES) == (
            "Error in 'inputlookup' command: This command must be the first "
            "command of a search."
        )

    def test_a_name_with_no_definition_is_refused(self) -> None:
        assert failure("| inputlookup nosuch", SOURCES) == (
            "Error in 'inputlookup' command: The lookup table 'nosuch' requires "
            "a .csv or KV store lookup definition."
        )

    def test_a_csv_file_that_is_not_there_is_refused(self) -> None:
        assert failure("| inputlookup nosuch.csv", SOURCES) == (
            "Error in 'inputlookup' command: The lookup table 'nosuch.csv' does "
            "not exist or is not available."
        )

    def test_an_option_value_is_checked(self) -> None:
        assert failure("| inputlookup max=-1 assets", SOURCES) == (
            "Error in 'SearchProcessor': Invalid option value. Expecting a "
            "'non-negative integer' for option 'max'. Instead got '-1'."
        )

    def test_a_second_table_name_is_refused(self) -> None:
        assert "Invalid argument: 'other'" in failure("| inputlookup assets other", SOURCES)

    def test_no_table_is_refused(self) -> None:
        assert "Must specify a lookup table name." in failure("| inputlookup", SOURCES)

    def test_a_pipeline_given_no_sources_fails_rather_than_answering_empty(self) -> None:
        _rows, messages = execute_pipeline([], parse_spl("| inputlookup assets"))
        assert messages == [{
            "type": "FATAL",
            "text": "Error in 'inputlookup' command: This search has no data to read.",
        }]


class TestInputlookupLimits:
    """A table bigger than a search hands back stops where splunkd stops."""

    def test_a_huge_table_is_read_up_to_maxresultrows(self) -> None:
        big = LookupTable(
            name="big", fields=["n"], rows=[{"n": str(i)} for i in range(MAX_RESULT_ROWS + 5)],
        )
        assert len(out("| inputlookup big", FakeSources({"big": big}))) == MAX_RESULT_ROWS

    def test_and_max_cannot_raise_the_ceiling(self) -> None:
        big = LookupTable(
            name="big", fields=["n"], rows=[{"n": str(i)} for i in range(MAX_RESULT_ROWS + 5)],
        )
        rows = out("| inputlookup max=99999999 big", FakeSources({"big": big}))
        assert len(rows) == MAX_RESULT_ROWS


class TestLookup:
    """Rows enriched from a table."""

    def test_output_writes_the_named_field(self) -> None:
        rows = out(EVENTS + "| lookup ip_intel ip OUTPUT threat_key", SOURCES)
        assert rows[0]["threat_key"] == "c2"

    def test_several_matches_are_a_multivalue_in_table_order(self) -> None:
        rows = out(EVENTS + "| lookup ip_intel ip OUTPUT threat_key", SOURCES)
        assert rows[1]["threat_key"] == ["tor", "scanner"]

    def test_a_row_that_matches_nothing_gets_nothing(self) -> None:
        rows = out(EVENTS + "| lookup ip_intel ip OUTPUT threat_key", SOURCES)
        assert "threat_key" not in rows[2]

    def test_as_renames_both_sides(self) -> None:
        rows = out(EVENTS + "| lookup assets nt_host AS host OUTPUT owner AS asset_owner",
                   SOURCES)
        assert rows[0]["asset_owner"] == "alice" and "owner" not in rows[0]

    def test_matching_is_case_sensitive_by_default(self) -> None:
        rows = out(EVENTS + "| lookup assets nt_host AS host OUTPUT owner", SOURCES)
        assert "owner" not in rows[1], "wks-2 is not WKS-2"

    def test_unless_the_definition_says_otherwise(self) -> None:
        loose = LookupTable(name="loose", fields=ASSETS.fields, rows=ASSETS.rows,
                            case_sensitive_match=False)
        rows = out(EVENTS + "| lookup loose nt_host AS host OUTPUT owner",
                   FakeSources({"loose": loose}))
        assert rows[1]["owner"] == "bob"

    def test_without_an_output_clause_every_other_table_field_is_written(self) -> None:
        rows = out(EVENTS + "| lookup assets nt_host AS host", SOURCES)
        assert rows[0] == {"ip": "203.0.113.10", "host": "SRV-1", "owner": "alice",
                           "category": "server"}

    def test_output_overwrites_and_clears_on_a_miss(self) -> None:
        rows = out(EVENTS + '| eval threat_key="old" | lookup ip_intel ip OUTPUT threat_key',
                   SOURCES)
        assert rows[0]["threat_key"] == "c2"
        assert "threat_key" not in rows[2], "OUTPUT replaces the field with null"

    def test_outputnew_keeps_what_the_row_already_has(self) -> None:
        rows = out(
            EVENTS + '| eval threat_key="old" | lookup ip_intel ip OUTPUTNEW threat_key weight',
            SOURCES,
        )
        assert rows[0]["threat_key"] == "old" and rows[0]["weight"] == 3
        assert rows[2]["threat_key"] == "old"

    def test_several_match_fields_must_all_agree(self) -> None:
        rows = out(
            EVENTS + '| eval category="server" '
            "| lookup assets nt_host AS host, category OUTPUT owner",
            SOURCES,
        )
        assert rows[0]["owner"] == "alice" and "owner" not in rows[2]

    def test_a_multivalue_field_is_looked_up_value_by_value(self) -> None:
        rows = out('| makeresults | eval ip=split("203.0.113.10;198.51.100.9", ";") '
                   "| lookup ip_intel ip OUTPUT threat_key", SOURCES)
        assert rows[0]["threat_key"] == "c2"

    def test_max_matches_caps_the_values(self) -> None:
        capped = LookupTable(name="capped", fields=INTEL.fields, rows=INTEL.rows, max_matches=1)
        rows = out(EVENTS + "| lookup capped ip OUTPUT threat_key",
                   FakeSources({"capped": capped}))
        assert rows[1]["threat_key"] == "tor"

    def test_min_matches_fills_the_default(self) -> None:
        filled = LookupTable(name="filled", fields=INTEL.fields, rows=INTEL.rows,
                             min_matches=1, default_match="unknown")
        rows = out(EVENTS + "| lookup filled ip OUTPUT threat_key",
                   FakeSources({"filled": filled}))
        assert rows[2]["threat_key"] == "unknown"

    def test_a_table_it_does_not_have_cannot_be_constructed(self) -> None:
        assert failure(EVENTS + "| lookup nosuch ip OUTPUT x", SOURCES) == (
            "Error in 'lookup' command: Could not construct lookup "
            "'nosuch, ip, OUTPUT, x'. See search.log for more details."
        )

    def test_a_match_field_the_table_lacks_is_refused(self) -> None:
        assert failure(EVENTS + "| lookup ip_intel addr", SOURCES) == (
            "Error in 'lookup' command: Could not find all of the specified "
            "lookup fields in the lookup table."
        )

    def test_an_output_field_the_table_lacks_is_refused(self) -> None:
        assert failure(EVENTS + "| lookup ip_intel ip OUTPUT nosuch", SOURCES) == (
            "Error in 'lookup' command: Could not find all of the specified "
            "destination fields in the lookup table."
        )

    def test_a_lookup_with_no_fields_is_refused(self) -> None:
        assert "Must specify one or more lookup fields." in failure(
            EVENTS + "| lookup ip_intel", SOURCES)

    def test_an_output_keyword_with_nothing_after_it_is_refused(self) -> None:
        assert "after OUTPUT" in failure(EVENTS + "| lookup ip_intel ip OUTPUT", SOURCES)

    def test_a_dangling_as_is_refused(self) -> None:
        assert "Invalid argument: 'AS'" in failure(EVENTS + "| lookup ip_intel ip AS", SOURCES)

    def test_local_and_update_are_taken_and_checked(self) -> None:
        rows = out(EVENTS + "| lookup local=t update=f ip_intel ip OUTPUT weight", SOURCES)
        assert rows[0]["weight"] == 3
        assert "boolean" in failure(EVENTS + "| lookup local=maybe ip_intel ip", SOURCES)

    def test_a_quoted_field_name_is_unquoted(self) -> None:
        rows = out(EVENTS + '| lookup ip_intel "ip" OUTPUT "threat_key"', SOURCES)
        assert rows[0]["threat_key"] == "c2"
