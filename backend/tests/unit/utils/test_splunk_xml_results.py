"""Splunk XML results rendering regressions.

XML is splunkd's default output mode, and ``splunklib.results.ResultsReader``
parses exactly the ``<results><result><field k=...>`` shape. The results
envelope always carries a ``messages`` key, so dispatching on that first
matched here and rendered an empty ``<messages/>`` — silently discarding every
row for any client that did not explicitly ask for JSON.
"""
from utils.splunk.xml_output import render_splunk_xml

_RESULTS_PAYLOAD = {
    "preview": False,
    "init_offset": 0,
    "messages": [],
    "fields": [{"name": "host"}, {"name": "index"}],
    "results": [
        {"host": "mockdr", "index": "sentinelone"},
        {"host": "mockdr", "index": "msdefender"},
    ],
}


class TestResultsRendering:
    """A results envelope renders as a results document, not as messages."""

    def test_rows_are_not_discarded(self) -> None:
        # Each result is numbered with the offset a client pages by, which is
        # how splunkd writes them.
        xml = render_splunk_xml(_RESULTS_PAYLOAD)
        assert xml.count("<result offset=") == 2

    def test_uses_the_results_document_shape(self) -> None:
        xml = render_splunk_xml(_RESULTS_PAYLOAD)
        assert "<results" in xml
        assert "<messages>" not in xml

    def test_field_values_are_present(self) -> None:
        xml = render_splunk_xml(_RESULTS_PAYLOAD)
        # Single quotes, as splunkd writes its attributes.
        assert "k='host'" in xml
        assert "sentinelone" in xml

    def test_the_fields_are_named_once_at_the_top(self) -> None:
        xml = render_splunk_xml(_RESULTS_PAYLOAD)
        assert "<meta>\n<fieldOrder>\n<field>host</field>" in xml

    def test_empty_result_set_still_renders_a_results_document(self) -> None:
        xml = render_splunk_xml({**_RESULTS_PAYLOAD, "results": []})
        # Nothing to show is an empty element, which is what splunkd sends.
        assert xml.endswith("<results preview='0'/>")


class TestOtherPayloadsUnaffected:
    """Reordering the dispatch must not steal the other document shapes."""

    def test_message_only_payload_still_renders_messages(self) -> None:
        xml = render_splunk_xml({"messages": [{"type": "WARN", "text": "nope"}]})
        assert "<messages>" in xml
        assert "nope" in xml

    def test_feed_payload_still_renders_a_feed(self) -> None:
        xml = render_splunk_xml({"entry": [{"name": "x", "content": {}}], "messages": []})
        assert "<entry>" in xml

    def test_session_key_payload_is_unchanged(self) -> None:
        assert "sessionKey" in render_splunk_xml({"sessionKey": "abc"})
