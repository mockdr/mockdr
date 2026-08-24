"""What Kibana refuses in a ``_find`` query, and how it says so.

Measured against Kibana 8.15 by sending each parameter to a real instance and
reading the message back. mockdr accepted almost all of it: `severity=nonsens`
came back as ``200`` with no cases — which a client reads as "there are none"
rather than as the typo it is — and `sortField=nope` came back sorted by
something else entirely.
"""
import pytest

from utils.kibana_validation import (
    ENDPOINT_ACTION_BODY,
    ENDPOINT_ACTION_STATUS_QUERY,
    ENDPOINT_METADATA_QUERY,
    CaseBodyError,
    ConfigSchemaError,
    ExceptionListError,
    FindQueryError,
    RulesQueryError,
    validate_case_body,
    validate_config_schema,
    validate_exception_find_query,
    validate_exception_list_body,
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


class TestCaseBody:
    """What the Cases API takes when a case is created.

    mockdr took a severity outside the enum, a title that was a number, and a
    `status` no client may set at creation — all with 200, so the case
    existed and nobody learned of the typo. Measured against Kibana 8.15.
    """

    GOOD = {
        "title": "t", "description": "d", "tags": [],
        "connector": {"id": "none", "name": "none", "type": ".none", "fields": None},
        "settings": {"syncAlerts": False}, "owner": "securitySolution",
    }

    def refuse(self, **overrides: object) -> CaseBodyError:
        with pytest.raises(CaseBodyError) as caught:
            validate_case_body({**self.GOOD, **overrides})
        return caught.value

    def test_a_valid_body_passes(self) -> None:
        validate_case_body(self.GOOD)

    @pytest.mark.parametrize("severity", ["low", "medium", "high", "critical"])
    def test_the_severities_it_takes(self, severity: str) -> None:
        validate_case_body({**self.GOOD, "severity": severity})

    def test_a_severity_outside_the_enum(self) -> None:
        assert str(self.refuse(severity="nonsense")) == (
            'Invalid value "nonsense" supplied to "severity"'
        )

    @pytest.mark.parametrize(("field", "value"), [
        ("title", 5), ("description", 5), ("tags", "a"),
        ("connector", "x"), ("settings", "x"), ("assignees", "x"),
    ])
    def test_a_member_of_the_wrong_type(self, field: str, value: object) -> None:
        assert str(self.refuse(**{field: value})) == (
            f'Invalid value "{value}" supplied to "{field}"'
        )

    def test_a_missing_member_is_undefined(self) -> None:
        with pytest.raises(CaseBodyError) as caught:
            validate_case_body({})
        # Reported in the codec's own order, all six at once.
        assert str(caught.value) == ",".join(
            f'Invalid value "undefined" supplied to "{f}"'
            for f in ("description", "tags", "title", "connector", "settings", "owner")
        )

    def test_a_status_cannot_be_asked_for(self) -> None:
        # A case is created open; asking for another state is an unknown key,
        # not a state to honour.
        assert str(self.refuse(status="open")) == 'invalid keys "status"'

    def test_unknown_keys_are_named_together(self) -> None:
        assert str(self.refuse(nosuch=1, another=2)) == 'invalid keys "nosuch,another"'

    def test_a_bad_value_is_reported_before_an_unknown_key(self) -> None:
        assert str(self.refuse(severity="x", nosuch=1)) == (
            'Invalid value "x" supplied to "severity"'
        )

    def test_several_bad_values_come_in_the_codecs_order(self) -> None:
        assert str(self.refuse(title=5, severity="x", tags="a")) == (
            'Invalid value "a" supplied to "tags",'
            'Invalid value "5" supplied to "title",'
            'Invalid value "x" supplied to "severity"'
        )

    @pytest.mark.parametrize("owner", ["securitySolution", "cases", "observability"])
    def test_the_plugins_that_own_cases(self, owner: str) -> None:
        validate_case_body({**self.GOOD, "owner": owner})

    def test_an_unknown_owner_is_forbidden_rather_than_invalid(self) -> None:
        error = self.refuse(owner="nosuchowner")
        assert str(error) == 'Unauthorized to create case with owners: "nosuchowner"'
        # 403, where every other failure here is a 400.
        assert error.forbidden

    def test_the_optional_members_it_takes(self) -> None:
        validate_case_body({
            **self.GOOD, "severity": "high", "assignees": [], "category": None,
            "customFields": [],
        })


class TestExceptionLists:
    """A third dialect again: io-ts, with the prefix the Cases API leaves off.

    Measured against Kibana 8.15. `page=0`, an unknown `namespace_type`, a
    `sort_field` the saved object is not indexed on and a `type` outside the
    enum all came back 200 here — the last of which created a list a real
    Kibana would have refused.
    """

    def refuse_query(self, **params: str) -> str:
        with pytest.raises(ExceptionListError) as caught:
            validate_exception_find_query(params)
        return str(caught.value)

    def refuse_body(self, **body: object) -> str:
        with pytest.raises(ExceptionListError) as caught:
            validate_exception_list_body(body)
        return str(caught.value)

    @pytest.mark.parametrize(("field", "value"), [
        ("page", "0"), ("page", "-1"), ("per_page", "0"), ("per_page", "-1"),
        ("per_page", "abc"),
    ])
    def test_paging_starts_at_one_here(self, field: str, value: str) -> None:
        # Unlike the Cases API, a per_page of 0 is a value error rather than
        # an empty page.
        assert self.refuse_query(**{field: value}) == (
            f'[request query]: Invalid value "{value}" supplied to "{field}"'
        )

    def test_there_is_no_page_cap(self) -> None:
        validate_exception_find_query({"per_page": "101"})

    @pytest.mark.parametrize("namespace", ["single", "agnostic"])
    def test_the_namespaces_it_knows(self, namespace: str) -> None:
        validate_exception_find_query({"namespace_type": namespace})

    def test_a_namespace_it_does_not(self) -> None:
        assert self.refuse_query(namespace_type="nonsense") == (
            '[request query]: Invalid value "nonsense" supplied to "namespace_type"'
        )

    def test_an_unknown_sort_field_has_a_message_of_its_own(self) -> None:
        # Raised by the search after the codec is satisfied, so no prefix.
        assert self.refuse_query(sort_field="nope") == "Unknown sort field nope"

    @pytest.mark.parametrize("field", ["name", "created_at", "updated_at",
                                       "description", "list_id", "type", "_score"])
    def test_the_fields_it_is_indexed_on(self, field: str) -> None:
        validate_exception_find_query({"sort_field": field})

    def test_an_unknown_query_key(self) -> None:
        assert self.refuse_query(nosuchparam="1") == (
            '[request query]: invalid keys "nosuchparam"'
        )

    def test_several_problems_in_the_codecs_order(self) -> None:
        assert self.refuse_query(page="0", per_page="-1", namespace_type="x") == (
            '[request query]: Invalid value "x" supplied to "namespace_type",'
            'Invalid value "0" supplied to "page",'
            'Invalid value "-1" supplied to "per_page"'
        )

    @pytest.mark.parametrize("list_type", [
        "detection", "rule_default", "endpoint", "endpoint_trusted_apps",
        "endpoint_events", "endpoint_host_isolation_exceptions", "endpoint_blocklists",
    ])
    def test_the_types_a_list_can_be(self, list_type: str) -> None:
        validate_exception_list_body({"name": "n", "description": "d", "type": list_type})

    def test_a_type_it_cannot_be(self) -> None:
        assert self.refuse_body(name="n", description="d", type="nonsense") == (
            '[request body]: Invalid value "nonsense" supplied to "type"'
        )

    def test_the_body_reports_what_is_missing(self) -> None:
        assert self.refuse_body() == (
            '[request body]: Invalid value "undefined" supplied to "description",'
            'Invalid value "undefined" supplied to "name",'
            'Invalid value "undefined" supplied to "type"'
        )

    def test_an_unknown_body_key(self) -> None:
        assert self.refuse_body(
            name="n", description="d", type="detection", nosuch=1,
        ) == '[request body]: invalid keys "nosuch"'

    def test_a_member_of_the_wrong_type(self) -> None:
        assert self.refuse_body(name=5, description="d", type="detection") == (
            '[request body]: Invalid value "5" supplied to "name"'
        )


class TestEndpointSchemas:
    """A fourth dialect: @kbn/config-schema, on the Endpoint routes.

    It names the member in the bracket, stops at the *first* failure, and
    refuses a key it has no definition for. mockdr took four filters Kibana
    does not declare, spelled the page size its own way, and reported a body
    it could not read as a 404 about an endpoint rather than a 400 about the
    request. Measured against Kibana 8.15.
    """

    def refuse_query(self, **params: str) -> str:
        with pytest.raises(ConfigSchemaError) as caught:
            validate_config_schema(
                params, ENDPOINT_METADATA_QUERY, where="request query", from_query=True,
            )
        return str(caught.value)

    def refuse_body(self, **body: object) -> str:
        with pytest.raises(ConfigSchemaError) as caught:
            validate_config_schema(body, ENDPOINT_ACTION_BODY, where="request body")
        return str(caught.value)

    def test_the_page_counts_from_zero_here(self) -> None:
        validate_config_schema(
            {"page": "0"}, ENDPOINT_METADATA_QUERY,
            where="request query", from_query=True,
        )
        assert self.refuse_query(page="-1") == (
            "[request query.page]: Value must be equal to or greater than [0]."
        )

    def test_the_page_size_has_both_bounds(self) -> None:
        assert self.refuse_query(pageSize="0") == (
            "[request query.pageSize]: Value must be equal to or greater than [1]."
        )
        assert self.refuse_query(pageSize="10001") == (
            "[request query.pageSize]: Value must be equal to or lower than [10000]."
        )

    def test_a_number_that_is_not_one_names_the_type_it_got(self) -> None:
        assert self.refuse_query(pageSize="abc") == (
            "[request query.pageSize]: expected value of type [number] but got [string]"
        )

    def test_a_key_the_schema_has_no_definition_for(self) -> None:
        assert self.refuse_query(nosuch="1") == (
            "[request query.nosuch]: definition for this key is missing"
        )

    def test_it_stops_at_the_first_failure(self) -> None:
        # Not a joined list, as the io-ts endpoints send.
        assert self.refuse_query(page="-1", pageSize="0") == (
            "[request query.page]: Value must be equal to or greater than [0]."
        )

    def test_a_union_lists_each_value_it_would_equal(self) -> None:
        message = self.refuse_query(sortDirection="x")
        assert message == (
            "[request query.sortDirection]: types that failed validation:\n"
            "- [request query.sortDirection.0]: expected value to equal [asc]\n"
            "- [request query.sortDirection.1]: expected value to equal [desc]"
        )

    def test_the_sort_fields_the_endpoint_list_knows(self) -> None:
        message = self.refuse_query(sortField="x")
        assert "expected value to equal [enrolled_at]" in message
        assert "expected value to equal [last_checkin]" in message

    def test_an_action_needs_at_least_one_endpoint(self) -> None:
        assert self.refuse_body() == (
            "[request body.endpoint_ids]: expected value of type [array] but got "
            "[undefined]"
        )
        assert self.refuse_body(endpoint_ids=[]) == (
            "[request body.endpoint_ids]: array size is [0], but cannot be smaller "
            "than [1]"
        )

    def test_ids_that_are_not_an_array(self) -> None:
        assert self.refuse_body(endpoint_ids="x") == (
            "[request body.endpoint_ids]: could not parse array value from json input"
        )

    def test_a_comment_is_a_string(self) -> None:
        assert self.refuse_body(endpoint_ids=["a"], comment=5) == (
            "[request body.comment]: expected value of type [string] but got [number]"
        )

    def test_the_agent_types_an_action_can_target(self) -> None:
        for agent_type in ("endpoint", "sentinel_one", "crowdstrike"):
            validate_config_schema(
                {"endpoint_ids": ["a"], "agent_type": agent_type},
                ENDPOINT_ACTION_BODY, where="request body",
            )

    def test_a_body_key_the_schema_has_no_definition_for(self) -> None:
        assert self.refuse_body(endpoint_ids=["a"], nosuch=1) == (
            "[request body.nosuch]: definition for this key is missing"
        )

    def test_action_status_needs_its_agent_ids(self) -> None:
        with pytest.raises(ConfigSchemaError) as caught:
            validate_config_schema(
                {}, ENDPOINT_ACTION_STATUS_QUERY, where="request query", from_query=True,
            )
        assert str(caught.value) == (
            "[request query.agent_ids]: expected at least one defined value but got "
            "[undefined]"
        )
