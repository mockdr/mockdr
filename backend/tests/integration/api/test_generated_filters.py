"""Every filter derived from the swagger narrows the way its operator says.

``scripts/gen_documented_filters.py`` turns each documented query parameter
whose field this mock's records carry into a ``FilterSpec`` — 343 of them.
Generated code needs generated proof: this walks every spec, takes a value
out of a real record, sends the filter, and holds the result to the
operator's own rule. A filter that quietly returns everything is the failure
this project exists to prevent, and it is exactly what these parameters did
before they were implemented.
"""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

from application.documented_filters import DOCUMENTED_FILTERS
from utils.filtering import FilterSpec, _parse_dt
from utils.nested import get_nested

BASE = "/web/api/v2.1"
#: Routes whose payload is not a plain ``data`` list.
_ENVELOPE = {"/sites": "sites"}


def _records(client: TestClient, route: str, headers: dict, **params: str) -> list[dict]:
    response = client.get(f"{BASE}{route}", headers=headers, params={"limit": "100", **params})
    assert response.status_code == 200, f"{route}: {response.text[:200]}"
    data = response.json()["data"]
    if isinstance(data, dict):
        return data.get(_ENVELOPE.get(route, ""), []) or []
    return data


def _holds(spec: FilterSpec, record: dict, sent: str) -> bool:
    """Whether ``record`` satisfies the filter that was sent."""
    value = get_nested(record, spec.field)
    if isinstance(value, list):
        value = ", ".join(str(v) for v in value)
    text = str(value if value is not None else "").lower()
    wanted = sent.lower()
    if spec.type == "contains":
        return wanted in text
    if spec.type == "nin":
        return text != wanted
    if spec.type == "bool":
        return bool(value) is (wanted in ("true", "1", "yes"))
    if spec.type in ("gt", "gte", "lt", "lte", "between"):
        return True  # ordering is checked separately, where the value is numeric
    return wanted in {v.strip() for v in text.split(",")} or text == wanted


def _cases() -> list[tuple[str, FilterSpec]]:
    return [(route, spec) for route, specs in DOCUMENTED_FILTERS.items() for spec in specs]


class TestGeneratedFiltersNarrow:
    @pytest.mark.parametrize(("route", "spec"), _cases(), ids=lambda x: getattr(x, "param", x))
    def test_filter_answers_and_holds_its_rule(
        self, route: str, spec: FilterSpec, client: TestClient, auth_headers: dict
    ) -> None:
        everything = _records(client, route, auth_headers)
        if not everything:
            pytest.skip(f"{route} has no seeded records")

        sample: Any = next(
            (get_nested(r, spec.field) for r in everything if get_nested(r, spec.field)), None
        )
        if sample is None or isinstance(sample, (dict, list)):
            pytest.skip(f"{route} {spec.param}: no scalar value to filter by")

        sent = str(sample)
        if spec.type == "contains":
            sent = sent[: max(3, len(sent) // 2)]
        elif spec.type == "bool":
            sent = "true"
        elif spec.type == "between":
            # The vendor spells a range as `<from>-<to>`, and for a dated one
            # both halves are epoch milliseconds — joining two ISO timestamps
            # with a hyphen is a value it never documents, and reads as
            # `2026` to `07-21T08:22:15.000Z` to anything that splits on the
            # separator. Send what the swagger's own examples send.
            if spec.kind == "date-time":
                moment = _parse_dt(str(sample))
                assert moment is not None, f"{route} {spec.param}: {sample!r} is not a timestamp"
                stamp = int(moment.timestamp() * 1000)
                sent = f"{stamp}-{stamp}"
            else:
                sent = f"{sample}-{sample}"

        narrowed = _records(client, route, auth_headers, **{spec.param: sent})
        assert len(narrowed) <= len(everything), f"{route} {spec.param} widened the result"
        for record in narrowed:
            assert _holds(spec, record, sent), (
                f"{route} {spec.param}={sent} returned a record whose "
                f"{spec.field} is {get_nested(record, spec.field)!r}"
            )
