"""The drift comparator judges nested typed objects, not only top-level keys.

An alert's `evidence` carried two properties Graph has never had while
``schema_drift.py graph`` reported no drift, because the comparison stopped
at an item's top-level keys. OData marks a polymorphic object with
``@odata.type``, which is the handle needed to judge it — and the fix is
worth a test of its own, because a comparator that silently stops looking is
worse than no comparator.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "scripts"))

schema_drift = pytest.importorskip("schema_drift")


class TestFindingTypedObjects:
    """``graph_typed_objects`` reaches every object that names its type."""

    def test_it_finds_one_nested_in_a_list(self) -> None:
        found = schema_drift.graph_typed_objects({
            "id": "1",
            "evidence": [{"@odata.type": "#microsoft.graph.security.deviceEvidence",
                          "mdeDeviceId": "x"}],
        })
        assert found == [
            ("evidence[]", "microsoft.graph.security.deviceEvidence", {"mdeDeviceId"}),
        ]

    def test_it_reaches_through_several_levels(self) -> None:
        found = schema_drift.graph_typed_objects({
            "a": {"b": {"@odata.type": "#microsoft.graph.x", "k": 1}},
        })
        assert found == [("a.b", "microsoft.graph.x", {"k"})]

    def test_an_object_without_a_type_is_not_judged(self) -> None:
        """Graph marks only polymorphic members, so an untyped one is normal."""
        assert schema_drift.graph_typed_objects({"a": {"k": 1}}) == []

    def test_the_odata_annotations_are_not_counted_as_properties(self) -> None:
        found = schema_drift.graph_typed_objects({
            "a": {"@odata.type": "#microsoft.graph.x", "@odata.id": "y", "k": 1},
        })
        assert found == [("a", "microsoft.graph.x", {"k"})]


class TestJudgingThem:
    """The properties come from the vendored metadata, not from the mock."""

    def test_device_evidence_declares_the_property_the_mock_now_uses(self) -> None:
        declared = schema_drift.graph_type_props(
            "microsoft.graph.security.deviceEvidence")
        assert "mdeDeviceId" in declared
        assert "azureAdDeviceId" in declared
        # And not the two that were invented.
        assert "deviceId" not in declared
        assert "type" not in declared

    def test_an_invented_property_would_be_reported(self) -> None:
        declared = schema_drift.graph_type_props(
            "microsoft.graph.security.deviceEvidence")
        _, _, keys = schema_drift.graph_typed_objects({
            "evidence": [{"@odata.type": "#microsoft.graph.security.deviceEvidence",
                          "mdeDeviceId": "x", "zzzInvented": 1}],
        })[0]
        assert sorted(keys - declared) == ["zzzInvented"]
