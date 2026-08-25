"""Index mappings and field capabilities, measured against Elasticsearch 8.15.

mockdr took a client's ``mappings`` on ``PUT /{index}`` and threw them away —
``GET /{index}`` answered ``"mappings": {}`` where a cluster echoes back what
it was given — and did not serve ``_field_caps`` at all, which is what every
Kibana data view asks for before it can draw anything.

A cluster also *adds* to the mapping as documents arrive, and the types it
picks are not obvious. Each one below was taken by writing a document to a
real cluster and reading what it mapped the field as.
"""
import pytest

from utils.es_mapping import (
    MappingConflictError,
    field_capabilities,
    flatten_properties,
    infer_properties,
    merge_properties,
)


class TestDynamicTypes:
    """What a cluster infers from a value it has no mapping for."""

    @pytest.mark.parametrize(("value", "expected"), [
        (5, "long"), (1.5, "float"), (True, "boolean"),
        ("2026-08-01T00:00:00Z", "date"), ("2026-08-01", "date"),
    ])
    def test_the_type_a_value_maps_to(self, value: object, expected: str) -> None:
        assert infer_properties({"f": value})["f"]["type"] == expected

    def test_a_string_is_text_with_a_keyword_subfield(self) -> None:
        # Which is why `terms` on `host` fails and on `host.keyword` works.
        mapped = infer_properties({"f": "text value"})["f"]
        assert mapped["type"] == "text"
        assert mapped["fields"] == {"keyword": {"type": "keyword", "ignore_above": 256}}

    def test_an_address_is_still_text(self) -> None:
        # Dynamic mapping does not guess `ip`; only a declared mapping does.
        assert infer_properties({"f": "10.0.0.1"})["f"]["type"] == "text"

    def test_an_array_takes_its_element_type(self) -> None:
        assert infer_properties({"f": [1, 2]})["f"]["type"] == "long"

    def test_an_empty_array_maps_to_nothing(self) -> None:
        assert infer_properties({"f": []}) == {}

    def test_a_null_maps_to_nothing(self) -> None:
        assert infer_properties({"f": None}) == {}

    def test_an_object_becomes_nested_properties(self) -> None:
        mapped = infer_properties({"o": {"inner": 3}})
        assert mapped["o"]["properties"]["inner"]["type"] == "long"


class TestMerging:
    """What happens when a mapping meets a field it already has."""

    def test_a_new_field_is_added(self) -> None:
        merged = merge_properties({"a": {"type": "keyword"}}, {"b": {"type": "long"}})
        assert sorted(merged) == ["a", "b"]

    def test_a_mapped_field_keeps_the_type_it_has(self) -> None:
        # The documents are already indexed under it.
        merged = merge_properties({"a": {"type": "keyword"}}, {"a": {"type": "text"}})
        assert merged["a"]["type"] == "keyword"

    def test_and_a_client_asking_to_change_one_is_refused(self) -> None:
        with pytest.raises(MappingConflictError) as caught:
            merge_properties({"a": {"type": "long"}}, {"a": {"type": "keyword"}}, strict=True)
        assert str(caught.value) == (
            "mapper [a] cannot be changed from type [long] to [keyword]"
        )

    def test_objects_merge_field_by_field(self) -> None:
        merged = merge_properties(
            {"o": {"properties": {"a": {"type": "keyword"}}}},
            {"o": {"properties": {"b": {"type": "long"}}}},
        )
        assert sorted(merged["o"]["properties"]) == ["a", "b"]


class TestFlattening:
    """Every field by its dotted name, subfields included."""

    PROPERTIES = {
        "host": {"type": "keyword"},
        "msg": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
        "o": {"properties": {"a": {"type": "long"}}},
    }

    def test_a_subfield_is_a_field_of_its_own(self) -> None:
        assert "msg.keyword" in flatten_properties(self.PROPERTIES)

    def test_an_object_is_listed_and_so_is_what_is_in_it(self) -> None:
        flat = flatten_properties(self.PROPERTIES)
        assert flat["o"] == {"type": "object"}
        assert flat["o.a"]["type"] == "long"


class TestFieldCapabilities:
    """``_field_caps``, and what "aggregatable" means."""

    PROPERTIES = {
        "host": {"type": "keyword"},
        "msg": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
        "o": {"properties": {"a": {"type": "long"}}},
    }

    def caps(self, wanted: list[str]) -> dict:
        return field_capabilities(self.PROPERTIES, wanted)

    def test_a_keyword_can_be_aggregated(self) -> None:
        assert self.caps(["host"])["host"]["keyword"]["aggregatable"] is True

    def test_a_text_field_cannot(self) -> None:
        # It is searchable, and that is the distinction the whole endpoint
        # exists to report.
        entry = self.caps(["msg"])["msg"]["text"]
        assert entry["searchable"] is True
        assert entry["aggregatable"] is False

    def test_its_keyword_subfield_can(self) -> None:
        assert self.caps(["msg.keyword"])["msg.keyword"]["keyword"]["aggregatable"] is True

    def test_asking_for_a_field_reports_the_object_it_sits_in(self) -> None:
        assert "o" in self.caps(["o.a"])

    def test_the_metadata_fields_come_with_a_wildcard(self) -> None:
        fields = self.caps(["*"])
        assert fields["_id"]["_id"]["metadata_field"] is True
        assert fields["_index"]["_index"]["aggregatable"] is True

    def test_and_not_when_a_field_is_named(self) -> None:
        assert "_id" not in self.caps(["host"])
