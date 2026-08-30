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

import json
import pathlib

import pytest
from fastapi.testclient import TestClient

BASE = "/web/api/v2.1"
SWAGGER = pathlib.Path(__file__).resolve().parents[4] / "data" / "swagger_2_1.json"


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

    def test_no_declared_integer_or_boolean_filter_accepts_garbage(
        self, client: TestClient, auth_headers: dict,
    ) -> None:
        swagger = json.loads(SWAGGER.read_text())
        mock = client.app.openapi()
        silent = []
        for path, operations in swagger["paths"].items():
            documented = operations.get("get")
            mocked = mock["paths"].get(path, {}).get("get")
            if not documented or not mocked or "{" in path:
                continue
            takes = {p["name"] for p in mocked.get("parameters", []) if p.get("in") == "query"}
            for parameter in documented.get("parameters", []):
                name, kind = parameter["name"], parameter.get("type")
                if parameter.get("in") != "query" or kind not in ("integer", "boolean"):
                    continue
                if name not in takes:
                    # Not taken at all: `scripts/param_drift.py` counts these,
                    # and a parameter that is dropped cannot be validated.
                    continue
                response = client.get(path, headers=auth_headers, params={name: "zzz-garbage"})
                if response.status_code != 400:
                    silent.append(f"{path}?{name} -> {response.status_code}")
        assert not silent, f"typed parameters that swallow garbage: {silent}"

    def test_the_mock_advertises_the_type_it_enforces(self) -> None:
        """A blanket ``string`` told every reader the opposite of the rule."""
        from application.documented_filters import DOCUMENTED_FILTERS
        from utils.documented_params import documented_openapi

        wrong = []
        for route, specs in DOCUMENTED_FILTERS.items():
            declared = {
                p["name"]: p["schema"]["type"]
                for p in documented_openapi(route).get("parameters", [])
            }
            wrong += [
                f"{route}?{spec.param}: says {declared[spec.param]}, enforces {spec.kind}"
                for spec in specs
                if declared.get(spec.param) != spec.kind
            ]
        assert not wrong, wrong
