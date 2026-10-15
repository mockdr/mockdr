"""``tstats``: statistics over indexed fields, and over the CIM data models.

Most Enterprise Security correlation searches are `| tstats … from
datamodel=…`; the most common search outside ES is `| tstats count where
index=x by sourcetype`. Both were refused as an unknown command.

Two halves, as in the tstats command reference:

* **Without a data model** tstats reads the index's own fields — ``_time``,
  ``index``, ``sourcetype``, ``source``, ``host`` — and nothing a search
  extracts at search time, so grouping by an event's JSON field groups
  nothing.
* **With one** it reads the dataset's CIM fields, prefixed with the
  dataset's name (``Processes.process_name``), beside the unprefixed fields
  every event inherits. mockdr states the CIM's tag constraints as feeds
  from its EDR sourcetypes (``utils/splunk/spl_datamodels.py``), and admits
  any event carrying the dataset's tags as it is.
"""
from tests.unit.splunk.sources import FakeSources, failure, out, run
from utils.splunk.spl_data_cmds import MAX_RESULT_ROWS

T0 = 1_787_500_000.0

EVENTS = [
    {"_time": T0, "index": "main", "sourcetype": "app:a", "source": "s1", "host": "srv-1",
     "action": "allow"},
    {"_time": T0 + 3600, "index": "main", "sourcetype": "app:a", "source": "s1",
     "host": "srv-2", "action": "block"},
    {"_time": T0 + 7200, "index": "main", "sourcetype": "app:b", "source": "s2",
     "host": "srv-2"},
    {"_time": T0 + 90000, "index": "other", "sourcetype": "app:a", "source": "s3",
     "host": "srv-3"},
    # A CrowdStrike detection as the EDR bridge indexes it.
    {"_time": T0, "index": "crowdstrike", "sourcetype": "CrowdStrike:Event:Streams:JSON",
     "source": "CrowdStrike:Event:Streams", "host": "mockdr",
     "metadata.eventType": "EppDetectionSummaryEvent",
     "event.Hostname": "WKS-1", "event.UserName": "alice", "event.FileName": "cmd.exe",
     "event.CommandLine": "cmd.exe /c whoami", "event.SHA256String": "ab" * 32,
     "event.Name": "sensor_based_ml", "event.SeverityName": "High",
     "event.Tactic": "Execution", "event.FilePath": "\\Windows\\cmd.exe",
     "event.PatternDispositionFlags": {"KillProcess": True}},
    # An incident on the same stream is not a process event.
    {"_time": T0, "index": "crowdstrike", "sourcetype": "CrowdStrike:Event:Streams:JSON",
     "source": "CrowdStrike:Event:Streams", "host": "mockdr",
     "metadata.eventType": "IncidentSummaryEvent"},
    # An event that arrived already shaped as CIM, tags and all.
    {"_time": T0 + 60, "index": "main", "sourcetype": "pan:traffic", "source": "fw",
     "host": "fw-1", "tag": ["network", "communicate"], "src_ip": "10.0.0.5",
     "dest_ip": "203.0.113.10", "dest_port": "443", "action": "allowed"},
]
SOURCES = FakeSources(events=EVENTS)


class TestOverIndexedFields:
    """The tsidx files' own fields, without a data model."""

    def test_count_where_index_by_sourcetype(self) -> None:
        assert out("| tstats count where index=main by sourcetype", SOURCES) == [
            {"sourcetype": "app:a", "count": 2},
            {"sourcetype": "app:b", "count": 1},
            {"sourcetype": "pan:traffic", "count": 1},
        ]

    def test_the_index_narrows_what_is_read(self) -> None:
        sources = FakeSources(events=EVENTS)
        out("| tstats count where index=main", sources)
        assert sources.selectors[-1].index == "main"

    def test_a_field_extracted_at_search_time_groups_nothing(self) -> None:
        assert out("| tstats count where index=main by action", SOURCES) == []

    def test_and_selects_nothing(self) -> None:
        assert out("| tstats count where index=main action=allow", SOURCES) == [{"count": 0}]

    def test_several_by_fields_sort_like_stats(self) -> None:
        rows = out("| tstats count where index=main by host, sourcetype", SOURCES)
        assert [(r["host"], r["sourcetype"]) for r in rows] == [
            ("fw-1", "pan:traffic"), ("srv-1", "app:a"), ("srv-2", "app:a"), ("srv-2", "app:b"),
        ]

    def test_where_takes_the_search_grammar(self) -> None:
        rows = out('| tstats count where index=main (host=SRV-1 OR sourcetype="app:b")',
                   SOURCES)
        assert rows == [{"count": 2}]

    def test_by_time_with_a_span_buckets(self) -> None:
        rows = out("| tstats count where index=main by _time span=1d", SOURCES)
        assert sum(r["count"] for r in rows) == 4
        assert all(r["_time"] % 86400 == 0 for r in rows)

    def test_the_dispatch_window_bounds_it(self) -> None:
        rows = out("| tstats count", SOURCES, window=(T0 + 1, T0 + 7200))
        assert rows == [{"count": 3}]

    def test_and_so_do_time_terms_in_the_where_clause(self) -> None:
        rows = out(f"| tstats count where earliest={int(T0 + 1)} latest={int(T0 + 7200)}",
                   SOURCES)
        assert rows == [{"count": 3}]

    def test_an_unreadable_time_term_is_refused(self) -> None:
        assert failure("| tstats count where earliest=-3x", SOURCES) == (
            "Invalid value \"-3x\" for time term 'earliest'"
        )

    def test_statistics_beside_count(self) -> None:
        rows = out("| tstats dc(host) as hosts values(sourcetype) earliest(_time) "
                   "latest_time(host) where index=main", SOURCES)
        assert rows == [{
            "hosts": 3, "values(sourcetype)": ["app:a", "app:b", "pan:traffic"],
            "earliest(_time)": T0, "latest_time(host)": int(T0 + 7200),
        }]

    def test_a_stats_function_tstats_lacks_is_refused(self) -> None:
        assert failure("| tstats list(host) where index=main", SOURCES) == (
            "Error in 'tstats' command: The argument 'list' is invalid."
        )

    def test_a_stray_word_is_refused(self) -> None:
        assert "The argument 'nonsense' is invalid." in failure(
            "| tstats count nonsense where index=main", SOURCES)

    def test_no_statistic_is_refused(self) -> None:
        assert "at least one aggregation" in failure("| tstats where index=main", SOURCES)

    def test_it_must_begin_the_search(self) -> None:
        assert failure("| makeresults | tstats count", SOURCES) == (
            "Error in 'tstats' command: This command must be the first command of a search."
        )

    def test_fillnull_value_groups_the_rows_missing_a_by_field(self) -> None:
        rows = out("| tstats count from datamodel=Endpoint.Processes "
                   "by Processes.process_name Processes.parent_process_name", SOURCES)
        assert rows == []
        rows = out("| tstats fillnull_value=null count from datamodel=Endpoint.Processes "
                   "by Processes.process_name Processes.parent_process_name", SOURCES)
        assert rows == [{"Processes.process_name": "cmd.exe",
                         "Processes.parent_process_name": "null", "count": 1}]

    def test_prestats_hands_the_rows_to_the_next_command(self) -> None:
        rows = out("| tstats prestats=t count where index=main by host | stats count by host",
                   SOURCES)
        assert rows == [{"host": "fw-1", "count": 1}, {"host": "srv-1", "count": 1},
                        {"host": "srv-2", "count": 2}]

    def test_prestats_with_append_runs_on_top_of_earlier_results(self) -> None:
        rows = out("| tstats prestats=t count where index=main "
                   "| tstats prestats=t append=t count where index=other "
                   "| stats count", SOURCES)
        assert rows == [{"count": 5}]

    def test_a_boolean_option_is_checked(self) -> None:
        assert "boolean" in failure("| tstats summariesonly=maybe count", SOURCES)

    def test_a_zero_span_is_refused(self) -> None:
        assert "span" in failure("| tstats count by _time span=0", SOURCES)

    def test_by_with_no_field_is_refused(self) -> None:
        assert "after BY" in failure("| tstats count where index=main by", SOURCES)


class TestOverDataModels:
    """CIM datasets, their prefixed fields, and the errors for what is not there."""

    def test_a_dataset_reads_its_feeds_under_the_prefix(self) -> None:
        rows = out("| tstats count from datamodel=Endpoint.Processes "
                   "where Processes.process_name=cmd.exe by Processes.dest Processes.user",
                   SOURCES)
        assert rows == [{"Processes.dest": "WKS-1", "Processes.user": "alice", "count": 1}]

    def test_an_event_its_feed_does_not_admit_is_not_in_it(self) -> None:
        rows = out("| tstats count from datamodel=Endpoint.Processes", SOURCES)
        assert rows == [{"count": 1}], "the incident event is not a process"

    def test_computed_fields_follow_the_add_on(self) -> None:
        rows = out("| tstats values(Malware_Attacks.action) values(Malware_Attacks.severity) "
                   "from datamodel=Malware.Malware_Attacks", SOURCES)
        assert rows == [{"values(Malware_Attacks.action)": ["blocked"],
                         "values(Malware_Attacks.severity)": ["high"]}]

    def test_a_tagged_event_joins_with_its_own_field_names(self) -> None:
        rows = out("| tstats count from datamodel=Network_Traffic.All_Traffic "
                   "by All_Traffic.dest_ip All_Traffic.dest_port", SOURCES)
        assert rows == [{"All_Traffic.dest_ip": "203.0.113.10",
                         "All_Traffic.dest_port": "443", "count": 1}]

    def test_the_inherited_fields_are_unprefixed(self) -> None:
        rows = out("| tstats count from datamodel=Network_Traffic by sourcetype host", SOURCES)
        assert rows == [{"sourcetype": "pan:traffic", "host": "fw-1", "count": 1}]

    def test_a_model_without_a_dataset_reads_every_root(self) -> None:
        rows = out("| tstats count from datamodel=Endpoint", SOURCES)
        assert rows == [{"count": 2}], "the detection is a process and a file"

    def test_nodename_picks_the_dataset(self) -> None:
        rows = out("| tstats count from datamodel=Endpoint where nodename=Filesystem "
                   "by Filesystem.file_name", SOURCES)
        assert rows == [{"Filesystem.file_name": "cmd.exe", "count": 1}]

    def test_an_unprefixed_dataset_field_is_not_there(self) -> None:
        assert out("| tstats count from datamodel=Endpoint.Processes by process_name",
                   SOURCES) == []

    def test_summariesonly_changes_nothing_for_a_complete_summary(self) -> None:
        query = "| tstats {} count from datamodel=Endpoint.Processes"
        assert out(query.format("summariesonly=true allow_old_summaries=true"), SOURCES) == (
            out(query.format(""), SOURCES)
        )

    def test_a_model_that_does_not_exist_is_refused(self) -> None:
        assert failure("| tstats count from datamodel=No_Such_Model", SOURCES) == (
            "Error in 'DataModelEvaluator': Data model 'No_Such_Model' was not found."
        )

    def test_a_dataset_the_model_lacks_is_refused(self) -> None:
        assert failure("| tstats count from datamodel=Endpoint.Nope", SOURCES) == (
            "Error in 'DataModelEvaluator': Data model 'Endpoint' does not contain "
            "object 'Nope'."
        )

    def test_from_must_name_a_data_model(self) -> None:
        assert "Invalid argument" in failure("| tstats count from mynamespace", SOURCES)

    def test_a_clause_given_twice_is_refused(self) -> None:
        assert "Invalid argument: 'where'" in failure(
            "| tstats count where index=a where index=b", SOURCES)


class TestLimits:
    """High-cardinality groupings stop at limits.conf's maxresultrows."""

    def test_groups_are_capped(self) -> None:
        many = [{"_time": T0 + i, "index": "big", "sourcetype": "s", "host": f"h{i}"}
                for i in range(MAX_RESULT_ROWS + 10)]
        rows, messages = run("| tstats count where index=big by host",
                             FakeSources(events=many))
        assert not [m for m in messages if m["type"] == "FATAL"]
        assert len(rows) == MAX_RESULT_ROWS
