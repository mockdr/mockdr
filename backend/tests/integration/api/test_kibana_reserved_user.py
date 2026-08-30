"""`elastic` is a reserved account, and reserved accounts have no profile.

Elasticsearch answers `GET /_security/user/elastic` with
`"full_name": null, "email": null, "metadata": {"_reserved": true}`, and
Kibana carries that through everywhere it names a user. `utils.es_case_serde`
already held the measured shape; the case seeder wrote an invented
`"Elastic Admin" <elastic-admin@acmecorp.internal>` beside it, so every
case's `created_by`, `updated_by` and `closed_by` carried a name and an
address no Elastic install serves — and `/api/cases/reporters` published
them to the filter drop-down. The live comparison against Kibana 8.15 is
what caught it.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from utils.es_case_serde import KIBANA_USER

AUTH = ("elastic", "mock-elastic-password")


class TestTheReservedUserHasNoProfile:
    def test_reporters_names_the_user_and_nothing_else(self, client: TestClient) -> None:
        response = client.get("/kibana/api/cases/reporters", auth=AUTH)
        assert response.status_code == 200, response.text
        reporters = response.json()
        assert reporters, "no reporter to check"
        for reporter in reporters:
            assert reporter["username"] == "elastic"
            assert reporter["full_name"] is None
            assert reporter["email"] is None

    def test_every_case_names_its_users_the_same_way(self, client: TestClient) -> None:
        response = client.get("/kibana/api/cases/_find", auth=AUTH, params={"perPage": "100"})
        assert response.status_code == 200, response.text
        cases = response.json()["cases"]
        assert cases, "no case to check"
        for case in cases:
            for field in ("created_by", "updated_by", "closed_by"):
                user = case.get(field)
                if user is None:
                    continue
                assert user.get("full_name") is None, f"{field}: {user}"
                assert user.get("email") is None, f"{field}: {user}"

    def test_a_comment_names_its_author_the_same_way(self, client: TestClient) -> None:
        cases = client.get(
            "/kibana/api/cases/_find", auth=AUTH, params={"perPage": "100"},
        ).json()["cases"]
        checked = 0
        for case in cases:
            body = client.get(f"/kibana/api/cases/{case['id']}/comments", auth=AUTH)
            if body.status_code != 200:
                continue
            comments = body.json()
            comments = comments if isinstance(comments, list) else comments.get("comments", [])
            for comment in comments:
                for field in ("created_by", "updated_by"):
                    user = comment.get(field)
                    if isinstance(user, dict):
                        checked += 1
                        assert user.get("full_name") is None, user
                        assert user.get("email") is None, user
        assert checked, "no comment author was checked"

    def test_the_seeder_and_the_serialiser_agree(self) -> None:
        """Two copies of one measured fact is how they came apart."""
        from infrastructure.seeders.es_cases import _MOCK_USER

        assert _MOCK_USER is KIBANA_USER
