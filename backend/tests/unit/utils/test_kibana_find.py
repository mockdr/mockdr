"""What Kibana refuses in a ``_find`` query, and how it says so.

Measured against Kibana 8.15 by sending each parameter to a real instance and
reading the message back. mockdr accepted almost all of it: `severity=nonsens`
came back as ``200`` with no cases — which a client reads as "there are none"
rather than as the typo it is — and `sortField=nope` came back sorted by
something else entirely.
"""
import pytest

from utils.kibana_find import (
    FindQueryError,
    RulesQueryError,
    validate_find_query,
    validate_rules_find_query,
)


def refuse(**params: str) -> str:
    """The message Kibana would answer this query with."""
    with pytest.raises(FindQueryError) as caught:
        validate_find_query(params)
    return str(caught.value)


class TestValues:
    """Each value against its codec."""

    @pytest.mark.parametrize(("field", "value"), [
        ("status", "nonsense"),
        ("severity", "nonsense"),
        ("sortOrder", "sideways"),
        ("sortField", "nope"),
        # Perfectly good case fields that this endpoint will not sort by.
        ("sortField", "owner"),
        ("sortField", "totalComment"),
        ("sortField", "id"),
    ])
    def test_a_value_outside_the_codec_is_named(self, field: str, value: str) -> None:
        assert refuse(**{field: value}) == f'Invalid value "{value}" supplied to "{field}"'

    @pytest.mark.parametrize("field", ["createdAt", "updatedAt", "closedAt",
                                       "title", "status", "severity", "category"])
    def test_the_sort_fields_it_does_take(self, field: str) -> None:
        validate_find_query({"sortField": field})

    @pytest.mark.parametrize("value", ["open", "in-progress", "closed"])
    def test_the_statuses_it_takes(self, value: str) -> None:
        validate_find_query({"status": value})

    def test_a_number_that_is_not_one_says_so(self) -> None:
        assert refuse(perPage="abc") == (
            'Invalid value "abc" supplied to "perPage",cannot parse to a number'
        )

    def test_a_fractional_page_is_accepted(self) -> None:
        validate_find_query({"page": "1.5"})

    @pytest.mark.parametrize("field", ["customFields", "searchFields"])
    def test_a_scalar_never_satisfies_an_object_field(self, field: str) -> None:
        assert refuse(**{field: "x"}) == f'Invalid value "x" supplied to "{field}"'


class TestPaging:
    """The page size cap, and the window underneath it."""

    def test_the_cap_is_a_hundred(self) -> None:
        validate_find_query({"perPage": "100"})
        assert refuse(perPage="101") == (
            "The provided perPage value is too high. "
            "The maximum allowed perPage value is 100."
        )

    def test_a_page_below_one_is_a_negative_window(self) -> None:
        # Kibana relays what Elasticsearch says about it, twice: once as the
        # message and once under "Root causes".
        message = refuse(page="0")
        assert message.startswith("[from] parameter cannot be negative but was [-20]")
        assert "Root causes" in message

    def test_the_offset_is_computed_from_the_page_size(self) -> None:
        assert "[-5]" in refuse(page="0", perPage="5")
        assert "[-30]" in refuse(page="-2", perPage="10")

    def test_a_negative_page_size_is_reported_as_size(self) -> None:
        assert refuse(perPage="-1").startswith(
            "[size] parameter cannot be negative, found [-1]",
        )


class TestUnknownKeys:
    """A key the endpoint does not have."""

    def test_it_is_named(self) -> None:
        assert refuse(nosuchparam="1") == 'invalid keys "nosuchparam"'

    def test_several_are_named_together(self) -> None:
        assert refuse(nosuchparam="1", another="2") == 'invalid keys "nosuchparam,another"'

    def test_a_value_error_is_reported_before_it(self) -> None:
        # An unknown key alongside a bad value: only the value is reported.
        assert refuse(nosuchparam="1", status="nonsense") == (
            'Invalid value "nonsense" supplied to "status"'
        )


class TestSeveralProblemsAtOnce:
    """Kibana reports them all, joined, in its codec's own order."""

    def test_the_order_is_the_codecs(self) -> None:
        assert refuse(status="bad", sortField="bad") == (
            'Invalid value "bad" supplied to "status",'
            'Invalid value "bad" supplied to "sortField"'
        )

    def test_the_page_size_cap_comes_after_the_value_errors(self) -> None:
        assert refuse(perPage="101", sortOrder="bad") == (
            'Invalid value "bad" supplied to "sortOrder",'
            "The provided perPage value is too high. "
            "The maximum allowed perPage value is 100."
        )

    def test_the_window_error_comes_last_of_all(self) -> None:
        # `perPage=101&page=0` reports only the cap: the query never reaches
        # Elasticsearch, so the negative window is never computed.
        assert refuse(perPage="101", page="0").startswith("The provided perPage value")


class TestAcceptedQueries:
    """What passes without a word."""

    @pytest.mark.parametrize("params", [
        {},
        {"owner": "securitySolution"},
        {"tags": "a"},
        {"search": "Beta"},
        {"reporters": "elastic"},
        {"category": "x"},
        {"page": "2", "perPage": "50", "sortField": "title", "sortOrder": "asc"},
    ])
    def test_a_usable_query_passes(self, params: dict) -> None:
        validate_find_query(params)


class TestRulesFindQuery:
    """The Detection Rules API validates with zod, and words it differently.

    Measured against Kibana 8.15. `sort_order=sideways` came back 200 here,
    sorted the other way round without saying so, and a `sort_field` without
    its `sort_order` — a pairing Kibana refuses outright — came back 200 too.
    """

    def refuse(self, **params: str) -> RulesQueryError:
        with pytest.raises(RulesQueryError) as caught:
            validate_rules_find_query(params)
        return caught.value

    def test_a_number_below_its_minimum(self) -> None:
        assert str(self.refuse(page="0")) == (
            "[request query]: page: Number must be greater than or equal to 1"
        )
        assert str(self.refuse(per_page="-1")) == (
            "[request query]: per_page: Number must be greater than or equal to 0"
        )

    def test_a_number_that_is_not_one(self) -> None:
        assert str(self.refuse(page="bad")) == (
            "[request query]: page: Expected number, received nan"
        )

    def test_an_enum_lists_what_it_takes(self) -> None:
        message = str(self.refuse(sort_order="sideways"))
        assert message == (
            "[request query]: sort_order: Invalid enum value. "
            "Expected 'asc' | 'desc', received 'sideways'"
        )

    def test_the_sort_field_enum_carries_every_spelling(self) -> None:
        message = str(self.refuse(sort_field="nope"))
        assert "'created_at' | 'createdAt' | 'enabled'" in message
        assert "'risk_score' | 'riskScore'" in message
        assert message.endswith("received 'nope'")

    def test_several_problems_are_joined_in_the_schemas_order(self) -> None:
        message = str(self.refuse(page="0", per_page="-1"))
        assert message == (
            "[request query]: page: Number must be greater than or equal to 1, "
            "per_page: Number must be greater than or equal to 0"
        )
        joined = str(self.refuse(sort_order="bad", per_page="-1"))
        assert joined.index("sort_order") < joined.index("per_page")

    def test_the_sort_pair_must_be_whole(self) -> None:
        for params in ({"sort_field": "name"}, {"sort_order": "asc"}):
            error = self.refuse(**params)
            assert str(error) == (
                'when "sort_order" and "sort_field" must exist together or not at all'
            )
            # It travels in an envelope of its own, not the schema's.
            assert error.sort_pair

    def test_a_whole_pair_passes(self) -> None:
        validate_rules_find_query({"sort_field": "name", "sort_order": "asc"})

    @pytest.mark.parametrize("params", [
        {}, {"page": "2", "per_page": "50"}, {"nosuchparam": "1"}, {"per_page": "101"},
    ])
    def test_what_this_endpoint_does_accept(self, params: dict) -> None:
        # Unlike the Cases API, it takes an unknown key and has no page cap.
        validate_rules_find_query(params)
