"""A filter the swagger types must refuse a value that type cannot hold.

The 2.1 swagger declares forty-odd filters ``integer`` or ``boolean``; this
mock took every one of them as text and compared whatever arrived.
``?resolved=maybe`` was read as false and answered 200 with every unresolved
threat, and ``?coreCount__lt=abc`` answered 200 with the whole estate — in
both cases a client with a formatting bug was handed a filtered-looking
result and never told the filter had not been applied. That is the silent
wrongness this project exists to prevent, and it hid because
``param_drift.py`` compared parameter *names* and not their types.

``?limit=abc`` on this same mount has always answered 400 in SentinelOne's
validation envelope. These tests hold the typed filters to that same rule.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

BASE = "/web/api/v2.1"


def _errors(response) -> dict:  # noqa: ANN001
    body = response.json()
    assert "errors" in body, body
    return body["errors"][0]


class TestATypedFilterRefusesWhatItsTypeCannotHold:
    @pytest.mark.parametrize(
        ("query", "wording"),
        [
            ("coreCount__lt=abc", "valid integer"),
            ("cpuCount__gte=not-a-number", "valid integer"),
            ("totalMemory__gt=lots", "valid integer"),
        ],
    )
    def test_an_integer_filter_refuses_a_non_integer(
        self, client: TestClient, auth_headers: dict, query: str, wording: str,
    ) -> None:
        response = client.get(f"{BASE}/agents?{query}", headers=auth_headers)
        assert response.status_code == 400, response.text
        error = _errors(response)
        assert error["code"] == 4000010
        assert error["title"] == "Validation Error"
        assert wording in error["detail"]
        assert query.split("=")[0] in error["detail"]

    @pytest.mark.parametrize(
        ("path", "query"),
        [
            ("/threats", "resolved=maybe"),
            ("/agents", "infected=sometimes"),
            ("/users", "twoFaEnabled=perhaps"),
        ],
    )
    def test_a_boolean_filter_refuses_a_non_boolean(
        self, client: TestClient, auth_headers: dict, path: str, query: str,
    ) -> None:
        response = client.get(f"{BASE}{path}?{query}", headers=auth_headers)
        assert response.status_code == 400, response.text
        assert "valid boolean" in _errors(response)["detail"]

    def test_it_is_the_envelope_the_page_size_already_used(
        self, client: TestClient, auth_headers: dict,
    ) -> None:
        """The refusal a client already parses, not a second shape beside it."""
        page_size = client.get(f"{BASE}/agents?limit=abc", headers=auth_headers)
        filter_ = client.get(f"{BASE}/agents?coreCount__lt=abc", headers=auth_headers)
        assert page_size.status_code == filter_.status_code == 400
        one, other = _errors(page_size), _errors(filter_)
        assert one.keys() == other.keys()
        assert one["code"] == other["code"]
        assert one["title"] == other["title"]


class TestTheValuesTheTypeDoesHoldStillFilter:
    def test_a_boolean_filter_still_narrows_both_ways(
        self, client: TestClient, auth_headers: dict,
    ) -> None:
        everything = client.get(f"{BASE}/threats?limit=100", headers=auth_headers)
        total = len(everything.json()["data"])
        resolved = client.get(f"{BASE}/threats?resolved=true&limit=100", headers=auth_headers)
        unresolved = client.get(f"{BASE}/threats?resolved=false&limit=100", headers=auth_headers)
        assert resolved.status_code == unresolved.status_code == 200
        assert len(resolved.json()["data"]) + len(unresolved.json()["data"]) == total

    def test_an_integer_filter_still_compares_as_a_number(
        self, client: TestClient, auth_headers: dict,
    ) -> None:
        """Ten is more than eight — the comparison must not become textual."""
        response = client.get(f"{BASE}/agents?coreCount__lt=10&limit=100", headers=auth_headers)
        assert response.status_code == 200, response.text
        cores = {a["coreCount"] for a in response.json()["data"]}
        assert cores and all(c < 10 for c in cores), cores

    def test_an_absent_filter_is_not_a_type_error(
        self, client: TestClient, auth_headers: dict,
    ) -> None:
        """An empty value has always meant "unset" here, and still does."""
        response = client.get(f"{BASE}/threats?resolved=", headers=auth_headers)
        assert response.status_code == 200, response.text


class TestTheClassStaysClosed:
    """Every typed parameter this mock takes, not the three that were found."""

    def test_no_typed_filter_accepts_a_value_its_type_cannot_hold(
        self, client: TestClient, auth_headers: dict,
    ) -> None:
        """Sourced from the mock itself: the swagger is fetched, not committed."""
        from application.documented_filters import DOCUMENTED_FILTERS

        silent = []
        for route, specs in DOCUMENTED_FILTERS.items():
            for spec in specs:
                if spec.kind == "string":
                    continue
                response = client.get(
                    f"{BASE}{route}", headers=auth_headers,
                    params={spec.param: "zzz-garbage"},
                )
                if response.status_code != 400:
                    silent.append(f"{route}?{spec.param} ({spec.kind}) -> {response.status_code}")
        assert not silent, f"typed filters that swallow garbage: {silent}"

    def test_no_typed_query_parameter_the_mock_declares_accepts_garbage(
        self, client: TestClient, auth_headers: dict,
    ) -> None:
        """The ones declared in a route signature rather than derived."""
        silent = []
        for path, operations in client.app.openapi()["paths"].items():
            operation = operations.get("get")
            if not operation or not path.startswith(BASE) or "{" in path:
                continue
            for parameter in operation.get("parameters", []):
                if parameter.get("in") != "query":
                    continue
                schema = parameter.get("schema", {})
                kinds = {member.get("type") for member in schema.get("anyOf", [schema])}
                if not kinds & {"integer", "boolean"}:
                    continue
                response = client.get(
                    path, headers=auth_headers, params={parameter["name"]: "zzz-garbage"},
                )
                if response.status_code != 400:
                    silent.append(f"{path}?{parameter['name']} -> {response.status_code}")
        assert not silent, f"typed parameters that swallow garbage: {silent}"

    def test_the_mock_advertises_the_type_it_enforces(self) -> None:
        """A blanket ``string`` told every reader the opposite of the rule.

        `date-time` is a JSON Schema *format* over `string`, not a type of its
        own — writing it as a type made 85 of this mock's own parameter
        schemas invalid, which a client generating code from `/openapi.json`
        would choke on. The kind is spelled the way JSON Schema spells it.
        """
        from application.documented_filters import DOCUMENTED_FILTERS
        from utils.documented_params import documented_openapi

        expected = {
            "date-time": {"type": "string", "format": "date-time"},
            "integer": {"type": "integer"},
            "boolean": {"type": "boolean"},
            "string": {"type": "string"},
        }
        wrong = []
        for route, specs in DOCUMENTED_FILTERS.items():
            declared = {
                p["name"]: p["schema"]
                for p in documented_openapi(route).get("parameters", [])
            }
            wrong += [
                f"{route}?{spec.param}: says {declared[spec.param]}, "
                f"enforces {spec.kind}"
                for spec in specs
                if declared.get(spec.param) != expected[spec.kind]
            ]
        assert not wrong, wrong

    def test_no_parameter_schema_uses_a_type_json_schema_does_not_know(self) -> None:
        """The seven JSON Schema types, and `date-time` is not one of them."""
        from main import app

        known = {"string", "number", "integer", "boolean", "object", "array", "null"}
        bad = []
        for path, operations in app.openapi()["paths"].items():
            for verb, operation in operations.items():
                if not isinstance(operation, dict):
                    continue
                for parameter in operation.get("parameters", []) or []:
                    schema = parameter.get("schema", {})
                    for node in [schema, *schema.get("anyOf", []),
                                 *schema.get("oneOf", [])]:
                        kind = node.get("type")
                        if isinstance(kind, str) and kind not in known:
                            bad.append(f"{verb.upper()} {path} {parameter['name']}: {kind}")
        assert not bad, bad
