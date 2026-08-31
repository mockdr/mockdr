"""A negated FQL list excludes; it does not select.

`_classify_operator` tested for brackets before it tested for the `!`, so
`platform_name:!['Windows','Linux']` produced the same clause as
`platform_name:['Windows','Linux']`. A client asking Falcon for the hosts
*outside* a set was handed exactly the hosts inside it — 200, well-formed,
and the precise opposite of the question.

The invariant is cheap to state and hard to get wrong twice: for any field
and any set of values, `in` and `!in` must partition the collection.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

CS_PREFIX = "/cs"
HOSTS = f"{CS_PREFIX}/devices/queries/devices/v1"


@pytest.fixture
def cs_headers(client: TestClient) -> dict[str, str]:
    resp = client.post(f"{CS_PREFIX}/oauth2/token", data={
        "client_id": "cs-mock-admin-client",
        "client_secret": "cs-mock-admin-secret"})
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


def _ids(client: TestClient, headers: dict, fql: str | None = None) -> set[str]:
    params: dict[str, object] = {"limit": 200}
    if fql is not None:
        params["filter"] = fql
    resp = client.get(HOSTS, headers=headers, params=params)
    assert resp.status_code == 200, resp.text
    return set(resp.json()["resources"])


#: One field per shape: a plain string column and a status column.
PARTITIONS = [
    ("platform_name", ["Windows", "Linux"]),
    ("platform_name", ["Mac"]),
    ("status", ["normal"]),
]


class TestInAndNotInPartition:
    @pytest.mark.parametrize(("field", "values"), PARTITIONS)
    def test_the_two_halves_are_the_whole(
        self, client: TestClient, cs_headers: dict, field: str, values: list[str],
    ) -> None:
        listed = ",".join(f"'{v}'" for v in values)
        everything = _ids(client, cs_headers)
        inside = _ids(client, cs_headers, f"{field}:[{listed}]")
        outside = _ids(client, cs_headers, f"{field}:![{listed}]")

        assert inside | outside == everything
        assert inside & outside == set()
        assert inside, f"{field} in {values} matched nothing — nothing to invert"

    def test_a_negated_list_is_not_the_list(
        self, client: TestClient, cs_headers: dict,
    ) -> None:
        """The defect itself: the two answered identically."""
        inside = _ids(client, cs_headers, "platform_name:['Windows','Linux']")
        outside = _ids(client, cs_headers, "platform_name:!['Windows','Linux']")
        assert inside != outside

    def test_a_negated_scalar_still_works(
        self, client: TestClient, cs_headers: dict,
    ) -> None:
        """`!'x'` was already right, and must stay so."""
        everything = _ids(client, cs_headers)
        equal = _ids(client, cs_headers, "platform_name:'Windows'")
        unequal = _ids(client, cs_headers, "platform_name:!'Windows'")
        assert equal | unequal == everything
        assert equal & unequal == set()


class TestTheParserSaysWhichOperator:
    """Stated at the parser, so a reader sees the two spellings differ."""

    def test_the_bracket_and_the_bang(self) -> None:
        from utils.cs_fql import parse_fql

        plain = parse_fql("platform_name:['Windows','Linux']")
        negated = parse_fql("platform_name:!['Windows','Linux']")
        assert plain[0].operator == "in"
        assert negated[0].operator == "nin"
        assert plain[0].values == negated[0].values == ["Windows", "Linux"]
