"""Integration tests for Kibana Cases API.

Verifies case CRUD, comments, tags, and Kibana pagination at
``/kibana/api/cases``.
"""
import base64
import json

import pytest
from fastapi.testclient import TestClient

ES_AUTH = {
    "Authorization": "Basic " + base64.b64encode(b"elastic:mock-elastic-password").decode(),
}

KBN_WRITE_HEADERS = {
    **ES_AUTH,
    "kbn-xsrf": "true",
}


def _get_first_case_id(client: TestClient) -> str:
    """Return the ID of the first seeded case."""
    body = client.get(
        "/kibana/api/cases/_find",
        headers=ES_AUTH,
        params={"perPage": 1},
    ).json()
    return body["cases"][0]["id"]


class TestFindCases:
    """Tests for GET /kibana/api/cases/_find."""

    def test_find_returns_200(self, client: TestClient) -> None:
        """Find endpoint should return 200."""
        resp = client.get("/kibana/api/cases/_find", headers=ES_AUTH)
        assert resp.status_code == 200

    def test_find_has_kibana_pagination(self, client: TestClient) -> None:
        """Response must match CasesFindResponseRt.

        Kibana names the collection ``cases`` and carries per-status counts
        alongside it; ``data`` belongs to other Kibana list APIs, not this one.
        """
        body = client.get("/kibana/api/cases/_find", headers=ES_AUTH).json()
        assert "page" in body
        assert "per_page" in body
        assert "total" in body
        assert "cases" in body
        assert "data" not in body
        for key in ("count_open_cases", "count_in_progress_cases", "count_closed_cases"):
            assert key in body, f"missing status count: {key}"

    def test_find_returns_8_seeded_cases(self, client: TestClient) -> None:
        """Seeder creates 8 cases from _CASE_TITLES."""
        body = client.get(
            "/kibana/api/cases/_find",
            headers=ES_AUTH,
            params={"perPage": 50},
        ).json()
        assert body["total"] == 8

    def test_find_with_status_filter(self, client: TestClient) -> None:
        """Filtering by status should return only matching cases."""
        body = client.get(
            "/kibana/api/cases/_find",
            headers=ES_AUTH,
            params={"status": "open", "perPage": 50},
        ).json()
        for case in body["cases"]:
            assert case["status"] == "open"

    def test_case_has_required_fields(self, client: TestClient) -> None:
        """Each case must include key fields matching the Kibana Cases schema."""
        body = client.get(
            "/kibana/api/cases/_find",
            headers=ES_AUTH,
            params={"perPage": 1},
        ).json()
        case = body["cases"][0]
        required = [
            "id", "title", "description", "status", "severity",
            "tags", "owner", "created_at", "created_by", "updated_at",
        ]
        for field in required:
            assert field in case, f"Missing case field: {field}"


class TestGetCaseTags:
    """Tests for GET /kibana/api/cases/tags."""

    def test_get_tags_returns_list(self, client: TestClient) -> None:
        """Tags endpoint should return a sorted list of unique case tags."""
        resp = client.get("/kibana/api/cases/tags", headers=ES_AUTH)
        assert resp.status_code == 200
        tags = resp.json()
        assert isinstance(tags, list)
        assert len(tags) > 0
        assert tags == sorted(tags)


class TestCreateCase:
    """Tests for POST /kibana/api/cases."""

    def test_create_case_returns_200(self, client: TestClient) -> None:
        """Creating a case with valid data should return 200."""
        resp = client.post(
            "/kibana/api/cases",
            headers=KBN_WRITE_HEADERS,
            json={
                "title": "Test Integration Case",
                "description": "Created by integration test.",
                "tags": ["test", "integration"],
                "severity": "medium",
                "owner": "securitySolution",
                "connector": {"id": "none", "name": "none", "type": ".none", "fields": None},
                "settings": {"syncAlerts": True},
            },
        )
        assert resp.status_code == 200

    def test_create_case_response_has_id(self, client: TestClient) -> None:
        """Newly created case should have an assigned ID and default fields."""
        body = client.post(
            "/kibana/api/cases",
            headers=KBN_WRITE_HEADERS,
            json={
                "title": "ID Check Case",
                "description": "Test.",
                "tags": [],
                "owner": "securitySolution",
                "connector": {"id": "none", "name": "none", "type": ".none", "fields": None},
                "settings": {"syncAlerts": True},
            },
        ).json()
        assert "id" in body
        assert body["title"] == "ID Check Case"
        assert body["status"] == "open"

    def test_create_case_without_kbn_xsrf_returns_400(self, client: TestClient) -> None:
        """Missing kbn-xsrf header should return 400."""
        resp = client.post(
            "/kibana/api/cases",
            headers=ES_AUTH,
            json={"title": "No XSRF", "description": "Test."},
        )
        assert resp.status_code == 400

    def test_created_case_appears_in_find(self, client: TestClient) -> None:
        """A created case should increase the total in _find."""
        before = client.get(
            "/kibana/api/cases/_find",
            headers=ES_AUTH,
            params={"perPage": 100},
        ).json()["total"]

        client.post(
            "/kibana/api/cases",
            headers=KBN_WRITE_HEADERS,
            json={"title": "Findable Case", "description": "Test.", "tags": [],
                  "owner": "securitySolution",
                  "connector": {"id": "none", "name": "none", "type": ".none", "fields": None},
                  "settings": {"syncAlerts": True}},
        )

        after = client.get(
            "/kibana/api/cases/_find",
            headers=ES_AUTH,
            params={"perPage": 100},
        ).json()["total"]
        assert after == before + 1


class TestGetCase:
    """Tests for GET /kibana/api/cases/{case_id}."""

    def test_get_case_by_id(self, client: TestClient) -> None:
        """Getting a case by its ID should return the full case."""
        case_id = _get_first_case_id(client)
        resp = client.get(f"/kibana/api/cases/{case_id}", headers=ES_AUTH)
        assert resp.status_code == 200
        assert resp.json()["id"] == case_id

    def test_get_nonexistent_case_returns_404(self, client: TestClient) -> None:
        """Non-existent case ID should return 404."""
        resp = client.get("/kibana/api/cases/nonexistent-id", headers=ES_AUTH)
        assert resp.status_code == 404


class TestUpdateCase:
    """Tests for PATCH /kibana/api/cases.

    Kibana updates cases only through the collection endpoint, with
    ``{"cases": [{id, version, ...}]}``. The mock had this inverted: the real
    bulk path 405'd while ``PATCH /api/cases/{id}`` — a route Kibana does not
    have — worked, and no version was checked.
    """

    @staticmethod
    def _case(client: TestClient) -> dict:
        return dict(client.get(
            "/kibana/api/cases/_find", headers=ES_AUTH, params={"perPage": 1},
        ).json()["cases"][0])

    def _patch(self, client: TestClient, case: dict, **changes: object) -> object:
        return client.patch(
            "/kibana/api/cases",
            headers=KBN_WRITE_HEADERS,
            json={"cases": [{
                "id": case["id"], "version": case["version"], **changes,
            }]},
        )

    def test_update_case_title(self, client: TestClient) -> None:
        resp = self._patch(client, self._case(client), title="Updated Case Title")

        assert resp.status_code == 200
        assert resp.json()[0]["title"] == "Updated Case Title"

    def test_update_case_status_to_closed(self, client: TestClient) -> None:
        resp = self._patch(client, self._case(client), status="closed")

        body = resp.json()[0]
        assert body["status"] == "closed"
        assert body["closed_at"] is not None

    def test_reopen_case_clears_closed_fields(self, client: TestClient) -> None:
        closed = self._patch(client, self._case(client), status="closed").json()[0]
        reopened = self._patch(client, closed, status="open")

        assert reopened.status_code == 200
        assert reopened.json()[0]["closed_at"] is None

    def test_version_changes_on_every_write(self, client: TestClient) -> None:
        case = self._case(client)
        updated = self._patch(client, case, title="v2").json()[0]

        assert updated["version"] != case["version"]

    def test_stale_version_is_a_conflict(self, client: TestClient) -> None:
        case = self._case(client)
        self._patch(client, case, title="first")

        # Same version again — the case has moved on underneath.
        conflict = self._patch(client, case, title="second")
        assert conflict.status_code == 409

    def test_update_nonexistent_case_returns_404(self, client: TestClient) -> None:
        resp = client.patch(
            "/kibana/api/cases",
            headers=KBN_WRITE_HEADERS,
            json={"cases": [{"id": "nonexistent-id", "version": "WzEsMV0=",
                             "title": "Ghost"}]},
        )
        assert resp.status_code == 404

    def test_missing_version_is_rejected(self, client: TestClient) -> None:
        case = self._case(client)
        resp = client.patch(
            "/kibana/api/cases",
            headers=KBN_WRITE_HEADERS,
            json={"cases": [{"id": case["id"], "title": "no version"}]},
        )
        assert resp.status_code == 400

    def test_per_id_route_is_not_served(self, client: TestClient) -> None:
        # This route exists in no Kibana; it used to be the only one that did.
        # Kibana registers a route per method, so a verb it does not take is
        # simply no route: 404 with the body it sends for any path it cannot
        # reach, and no Allow header (measured on 8.15).
        resp = client.patch(
            f"/kibana/api/cases/{self._case(client)['id']}",
            headers=KBN_WRITE_HEADERS,
            json={"title": "x"},
        )
        assert resp.status_code == 404
        assert resp.json() == {
            "statusCode": 404, "error": "Not Found", "message": "Not Found",
        }
        assert "allow" not in {k.lower() for k in resp.headers}


class TestCaseComments:
    """Tests for case comment endpoints."""

    def test_list_comments(self, client: TestClient) -> None:
        """Listing comments for a seeded case should return a non-empty list."""
        case_id = _get_first_case_id(client)
        resp = client.get(
            f"/kibana/api/cases/{case_id}/comments",
            headers=ES_AUTH,
        )
        assert resp.status_code == 200
        comments = resp.json()
        assert isinstance(comments, list)
        # Seeded cases have 2-5 comments each
        assert len(comments) >= 2

    def test_add_comment(self, client: TestClient) -> None:
        """Adding a comment is answered with the case, comments and all.

        Measured against Kibana 8.15: the answer to a comment write is the
        case object — the comment is inside its ``comments`` array, and the
        case's own ``updated_at`` and ``updated_by`` have moved.
        """
        case_id = _get_first_case_id(client)
        resp = client.post(
            f"/kibana/api/cases/{case_id}/comments",
            headers=KBN_WRITE_HEADERS,
            json={"comment": "New investigation note.", "type": "user"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["id"] == case_id
        added = [c for c in body["comments"] if c["comment"] == "New investigation note."]
        assert len(added) == 1
        # No real comment object carries case_id — the case is in the path.
        assert "case_id" not in added[0]
        assert added[0]["owner"] == "securitySolution"
        # A comment nobody has edited carries neither an update time nor an editor.
        assert added[0]["updated_at"] is None
        assert added[0]["updated_by"] is None
        assert body["updated_by"] == {"email": None, "full_name": None, "username": "elastic"}

    def test_add_comment_increases_count(self, client: TestClient) -> None:
        """Adding a comment should increase the comment count on the case."""
        case_id = _get_first_case_id(client)
        before = len(client.get(
            f"/kibana/api/cases/{case_id}/comments",
            headers=ES_AUTH,
        ).json())

        client.post(
            f"/kibana/api/cases/{case_id}/comments",
            headers=KBN_WRITE_HEADERS,
            json={"comment": "Another note.", "type": "user"},
        )

        after = len(client.get(
            f"/kibana/api/cases/{case_id}/comments",
            headers=ES_AUTH,
        ).json())
        assert after == before + 1

    def test_comment_has_required_fields(self, client: TestClient) -> None:
        """Each comment matches Kibana's CommentResponse."""
        case_id = _get_first_case_id(client)
        comments = client.get(
            f"/kibana/api/cases/{case_id}/comments",
            headers=ES_AUTH,
        ).json()
        comment = comments[0]
        required = [
            "id", "version", "comment", "type", "owner",
            "created_at", "created_by", "updated_at", "updated_by",
            "pushed_at", "pushed_by",
        ]
        for field in required:
            assert field in comment, f"Missing comment field: {field}"

    def test_list_comments_for_nonexistent_case_is_an_empty_list(
        self, client: TestClient,
    ) -> None:
        """Measured on 8.15: the comments route never resolves the case.

        A client listing the comments of a case it had just failed to create
        was told the wrong call had gone wrong.
        """
        resp = client.get(
            "/kibana/api/cases/nonexistent-id/comments",
            headers=ES_AUTH,
        )
        assert resp.status_code == 200
        assert resp.json() == []

    def test_add_comment_without_kbn_xsrf_returns_400(self, client: TestClient) -> None:
        """Missing kbn-xsrf header on POST comment should return 400."""
        case_id = _get_first_case_id(client)
        resp = client.post(
            f"/kibana/api/cases/{case_id}/comments",
            headers=ES_AUTH,
            json={"comment": "No XSRF.", "type": "user"},
        )
        assert resp.status_code == 400


class TestDeleteCase:
    """Tests for DELETE /kibana/api/cases."""

    def test_delete_case(self, client: TestClient) -> None:
        """Deleting a case should remove it from the store."""
        case_id = _get_first_case_id(client)
        resp = client.request(
            "DELETE",
            "/kibana/api/cases",
            headers=KBN_WRITE_HEADERS,
            params={"ids": json.dumps([case_id])},
        )
        # DELETE returns 204 (no content)
        assert resp.status_code == 204

        # Verify it is gone
        get_resp = client.get(f"/kibana/api/cases/{case_id}", headers=ES_AUTH)
        assert get_resp.status_code == 404

    def test_delete_case_reduces_total(self, client: TestClient) -> None:
        """Deleting a case should decrease the total count."""
        before = client.get(
            "/kibana/api/cases/_find",
            headers=ES_AUTH,
            params={"perPage": 100},
        ).json()["total"]

        case_id = _get_first_case_id(client)
        client.request(
            "DELETE",
            "/kibana/api/cases",
            headers=KBN_WRITE_HEADERS,
            params={"ids": json.dumps([case_id])},
        )

        after = client.get(
            "/kibana/api/cases/_find",
            headers=ES_AUTH,
            params={"perPage": 100},
        ).json()["total"]
        assert after == before - 1


class TestCaseObjectShape:
    """Every member Kibana's ``CaseRt`` declares, and nothing it does not.

    Measured against Kibana 8.15 by reading a case back from a real instance.
    A client reading `case.comments` or `case.customFields` found nothing
    here, and `alert_ids` — mockdr's own bookkeeping behind `totalAlerts` —
    was exposed as though it were part of the API.
    """

    def test_the_members_a_real_case_carries(self, client: TestClient) -> None:
        case = client.get(
            "/kibana/api/cases/_find", headers=ES_AUTH, params={"perPage": 1},
        ).json()["cases"][0]
        assert set(case) == {
            "assignees", "category", "closed_at", "closed_by", "comments",
            "connector", "created_at", "created_by", "customFields",
            "description", "duration", "external_service", "id", "owner",
            "settings", "severity", "status", "tags", "title", "totalAlerts",
            "totalComment", "updated_at", "updated_by", "version",
        }

    def test_the_bookkeeping_behind_total_alerts_stays_internal(
        self, client: TestClient,
    ) -> None:
        case = client.get(
            "/kibana/api/cases/_find", headers=ES_AUTH, params={"perPage": 1},
        ).json()["cases"][0]
        assert "alert_ids" not in case
        # The count derived from it is what Kibana exposes.
        assert isinstance(case["totalAlerts"], int)


class TestFindQueryIsValidated:
    """Kibana refuses a query before it looks at any data; so does this."""

    @pytest.mark.parametrize(("params", "message"), [
        ({"severity": "nonsense"}, 'Invalid value "nonsense" supplied to "severity"'),
        ({"sortField": "nope"}, 'Invalid value "nope" supplied to "sortField"'),
        ({"sortOrder": "sideways"}, 'Invalid value "sideways" supplied to "sortOrder"'),
        ({"perPage": "101"},
         "The provided perPage value is too high. The maximum allowed perPage value is 100."),
        ({"nosuchparam": "1"}, 'invalid keys "nosuchparam"'),
    ])
    def test_a_refused_query_carries_kibanas_wording(
        self, client: TestClient, params: dict, message: str,
    ) -> None:
        response = client.get("/kibana/api/cases/_find", headers=ES_AUTH, params=params)
        assert response.status_code == 400
        assert response.json()["message"] == message

    def test_a_usable_query_still_runs(self, client: TestClient) -> None:
        response = client.get(
            "/kibana/api/cases/_find", headers=ES_AUTH,
            params={"sortField": "title", "sortOrder": "asc", "perPage": "5"},
        )
        assert response.status_code == 200


class TestDeleteTakesIdsInTheQuery:
    """The ids belong in the query string, and a missing case is a 404."""

    def test_no_ids_is_refused(self, client: TestClient) -> None:
        response = client.delete("/kibana/api/cases", headers=KBN_WRITE_HEADERS)
        assert response.status_code == 400
        assert response.json()["message"] == (
            "[request query.ids]: expected value of type [array] but got [undefined]"
        )

    def test_an_unknown_id_is_a_404_naming_it(self, client: TestClient) -> None:
        response = client.delete(
            "/kibana/api/cases", headers=KBN_WRITE_HEADERS,
            params={"ids": json.dumps(["no-such-case"])},
        )
        assert response.status_code == 404
        assert response.json()["message"] == "Saved object [cases/no-such-case] not found"

    @pytest.mark.parametrize(("value", "named"), [
        ('"x"', "string"), ("5", "number"), ('{"a":1}', "Object"), ("true", "boolean"),
    ])
    def test_ids_that_are_not_an_array_name_their_json_type(
        self, client: TestClient, value: str, named: str,
    ) -> None:
        response = client.delete(
            "/kibana/api/cases", headers=KBN_WRITE_HEADERS, params={"ids": value},
        )
        assert response.status_code == 400
        assert response.json()["message"] == (
            f"[request query.ids]: expected value of type [array] but got [{named}]"
        )
