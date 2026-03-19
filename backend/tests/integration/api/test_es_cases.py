"""Integration tests for Kibana Cases API.

Verifies case CRUD, comments, tags, and Kibana pagination at
``/kibana/api/cases``.
"""
import base64

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
    return body["data"][0]["id"]


class TestFindCases:
    """Tests for GET /kibana/api/cases/_find."""

    def test_find_returns_200(self, client: TestClient) -> None:
        """Find endpoint should return 200."""
        resp = client.get("/kibana/api/cases/_find", headers=ES_AUTH)
        assert resp.status_code == 200

    def test_find_has_kibana_pagination(self, client: TestClient) -> None:
        """Response must include page, per_page, total, and data."""
        body = client.get("/kibana/api/cases/_find", headers=ES_AUTH).json()
        assert "page" in body
        assert "per_page" in body
        assert "total" in body
        assert "data" in body

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
        for case in body["data"]:
            assert case["status"] == "open"

    def test_case_has_required_fields(self, client: TestClient) -> None:
        """Each case must include key fields matching the Kibana Cases schema."""
        body = client.get(
            "/kibana/api/cases/_find",
            headers=ES_AUTH,
            params={"perPage": 1},
        ).json()
        case = body["data"][0]
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
            params={"perPage": 200},
        ).json()["total"]

        client.post(
            "/kibana/api/cases",
            headers=KBN_WRITE_HEADERS,
            json={"title": "Findable Case", "description": "Test."},
        )

        after = client.get(
            "/kibana/api/cases/_find",
            headers=ES_AUTH,
            params={"perPage": 200},
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
    """Tests for PATCH /kibana/api/cases/{case_id}."""

    def test_update_case_title(self, client: TestClient) -> None:
        """Updating a case title should persist the change."""
        case_id = _get_first_case_id(client)
        resp = client.patch(
            f"/kibana/api/cases/{case_id}",
            headers=KBN_WRITE_HEADERS,
            json={"title": "Updated Case Title"},
        )
        assert resp.status_code == 200
        assert resp.json()["title"] == "Updated Case Title"

    def test_update_case_status_to_closed(self, client: TestClient) -> None:
        """Closing a case should set closed_at and closed_by."""
        case_id = _get_first_case_id(client)
        resp = client.patch(
            f"/kibana/api/cases/{case_id}",
            headers=KBN_WRITE_HEADERS,
            json={"status": "closed"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "closed"
        assert body["closed_at"] is not None

    def test_reopen_case_clears_closed_fields(self, client: TestClient) -> None:
        """Reopening a case should clear closed_at and closed_by."""
        case_id = _get_first_case_id(client)
        # Close first
        client.patch(
            f"/kibana/api/cases/{case_id}",
            headers=KBN_WRITE_HEADERS,
            json={"status": "closed"},
        )
        # Then reopen
        resp = client.patch(
            f"/kibana/api/cases/{case_id}",
            headers=KBN_WRITE_HEADERS,
            json={"status": "open"},
        )
        assert resp.status_code == 200
        assert resp.json()["closed_at"] is None

    def test_update_nonexistent_case_returns_404(self, client: TestClient) -> None:
        """Updating a non-existent case should return 404."""
        resp = client.patch(
            "/kibana/api/cases/nonexistent-id",
            headers=KBN_WRITE_HEADERS,
            json={"title": "Ghost"},
        )
        assert resp.status_code == 404


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
        """Adding a comment should return the new comment with an ID."""
        case_id = _get_first_case_id(client)
        resp = client.post(
            f"/kibana/api/cases/{case_id}/comments",
            headers=KBN_WRITE_HEADERS,
            json={"comment": "New investigation note.", "type": "user"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "id" in body
        assert body["comment"] == "New investigation note."
        assert body["case_id"] == case_id

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
        """Each comment should have id, case_id, comment, type, and timestamps."""
        case_id = _get_first_case_id(client)
        comments = client.get(
            f"/kibana/api/cases/{case_id}/comments",
            headers=ES_AUTH,
        ).json()
        comment = comments[0]
        required = ["id", "case_id", "comment", "type", "created_at", "created_by"]
        for field in required:
            assert field in comment, f"Missing comment field: {field}"

    def test_list_comments_for_nonexistent_case_returns_404(self, client: TestClient) -> None:
        """Listing comments for a non-existent case should return 404."""
        resp = client.get(
            "/kibana/api/cases/nonexistent-id/comments",
            headers=ES_AUTH,
        )
        assert resp.status_code == 404

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
            json=[case_id],
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
            params={"perPage": 200},
        ).json()["total"]

        case_id = _get_first_case_id(client)
        client.request(
            "DELETE",
            "/kibana/api/cases",
            headers=KBN_WRITE_HEADERS,
            json=[case_id],
        )

        after = client.get(
            "/kibana/api/cases/_find",
            headers=ES_AUTH,
            params={"perPage": 200},
        ).json()["total"]
        assert after == before - 1
