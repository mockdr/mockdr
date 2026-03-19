"""Integration tests for playbook dev endpoints.

GET    /_dev/playbooks              — list all built-in playbooks
GET    /_dev/playbooks/status       — current run status
GET    /_dev/playbooks/{id}         — single playbook detail
POST   /_dev/playbooks/{id}/run     — start execution
DELETE /_dev/playbooks/cancel       — cancel running execution
"""

from fastapi.testclient import TestClient

from repository.agent_repo import agent_repo

BASE = "/web/api/v2.1"


# ── List playbooks ─────────────────────────────────────────────────────────────

class TestListPlaybooks:
    """Tests for GET /_dev/playbooks."""

    def test_returns_200(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.get(f"{BASE}/_dev/playbooks", headers=auth_headers)
        assert resp.status_code == 200

    def test_returns_data_list(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.get(f"{BASE}/_dev/playbooks", headers=auth_headers)
        body = resp.json()
        assert "data" in body
        assert isinstance(body["data"], list)

    def test_contains_builtin_playbooks(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.get(f"{BASE}/_dev/playbooks", headers=auth_headers)
        ids = [p["id"] for p in resp.json()["data"]]
        assert "phishing_excel_macro" in ids
        assert "ransomware_outbreak" in ids
        assert "lateral_movement" in ids
        assert "quiet_day_reset" in ids

    def test_each_playbook_has_required_fields(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        resp = client.get(f"{BASE}/_dev/playbooks", headers=auth_headers)
        for pb in resp.json()["data"]:
            assert "id" in pb
            assert "title" in pb
            assert "description" in pb
            assert "severity" in pb


# ── Playbook status ────────────────────────────────────────────────────────────

class TestPlaybookStatus:
    """Tests for GET /_dev/playbooks/status."""

    def test_returns_200(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.get(f"{BASE}/_dev/playbooks/status", headers=auth_headers)
        assert resp.status_code == 200

    def test_returns_status_field(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.get(f"{BASE}/_dev/playbooks/status", headers=auth_headers)
        body = resp.json()
        # Either a run object or a null/idle response
        assert body is not None

    def test_status_with_active_run_returns_run_data(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        """After starting a playbook the status endpoint must return the run object."""
        from repository.agent_repo import agent_repo
        agent_id = agent_repo.list_all()[0].id
        client.post(
            f"{BASE}/_dev/playbooks/quiet_day_reset/run",
            headers=auth_headers,
            json={"agentId": agent_id},
        )
        status = client.get(f"{BASE}/_dev/playbooks/status", headers=auth_headers).json()
        assert "data" in status
        assert status["data"]["playbookId"] == "quiet_day_reset"


# ── Playbook detail ────────────────────────────────────────────────────────────

class TestPlaybookDetail:
    """Tests for GET /_dev/playbooks/{id}."""

    def test_returns_200_for_known_playbook(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        resp = client.get(
            f"{BASE}/_dev/playbooks/phishing_excel_macro", headers=auth_headers
        )
        assert resp.status_code == 200

    def test_returns_404_for_unknown_playbook(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        resp = client.get(
            f"{BASE}/_dev/playbooks/does_not_exist", headers=auth_headers
        )
        assert resp.status_code == 404

    def test_detail_contains_steps(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.get(
            f"{BASE}/_dev/playbooks/ransomware_outbreak", headers=auth_headers
        )
        body = resp.json()["data"]
        assert "steps" in body
        assert len(body["steps"]) > 0

    def test_each_step_has_step_id_and_action(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        resp = client.get(
            f"{BASE}/_dev/playbooks/phishing_excel_macro", headers=auth_headers
        )
        for step in resp.json()["data"]["steps"]:
            assert "stepId" in step
            assert "action" in step


# ── Run playbook ───────────────────────────────────────────────────────────────

class TestRunPlaybook:
    """Tests for POST /_dev/playbooks/{id}/run."""

    def _first_agent_id(self) -> str:
        return agent_repo.list_all()[0].id

    def test_run_requires_agent_id(self, client: TestClient, auth_headers: dict) -> None:
        """Missing agentId must return 422."""
        resp = client.post(
            f"{BASE}/_dev/playbooks/quiet_day_reset/run",
            headers=auth_headers,
            json={},
        )
        assert resp.status_code == 422

    def test_run_returns_200_with_valid_agent(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        agent_id = self._first_agent_id()
        resp = client.post(
            f"{BASE}/_dev/playbooks/quiet_day_reset/run",
            headers=auth_headers,
            json={"agentId": agent_id},
        )
        assert resp.status_code == 200

    def test_run_response_contains_playbook_id(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        agent_id = self._first_agent_id()
        resp = client.post(
            f"{BASE}/_dev/playbooks/quiet_day_reset/run",
            headers=auth_headers,
            json={"agentId": agent_id},
        )
        body = resp.json()
        assert "data" in body
        assert body["data"]["playbookId"] == "quiet_day_reset"

    def test_run_response_contains_status(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        agent_id = self._first_agent_id()
        resp = client.post(
            f"{BASE}/_dev/playbooks/quiet_day_reset/run",
            headers=auth_headers,
            json={"agentId": agent_id},
        )
        assert "status" in resp.json()["data"]

    def test_run_unknown_playbook_still_handled(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        """Running a non-existent playbook should not crash the server."""
        agent_id = self._first_agent_id()
        resp = client.post(
            f"{BASE}/_dev/playbooks/ghost_playbook/run",
            headers=auth_headers,
            json={"agentId": agent_id},
        )
        # Either 404 or 200 with error in body — must not be 500
        assert resp.status_code != 500


# ── Cancel playbook ────────────────────────────────────────────────────────────

class TestCancelPlaybook:
    """Tests for DELETE /_dev/playbooks/cancel."""

    def test_cancel_returns_200(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.delete(f"{BASE}/_dev/playbooks/cancel", headers=auth_headers)
        assert resp.status_code == 200

    def test_cancel_returns_data_key(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.delete(f"{BASE}/_dev/playbooks/cancel", headers=auth_headers)
        assert "data" in resp.json()


# ── Playbook CRUD ───────────────────────────────────────────────────────────────

class TestPlaybookCRUD:
    """Tests for POST / PUT / DELETE /_dev/playbooks.

    Each test is isolated — ``fresh_seed`` (autouse) calls ``reset_registry()``
    via ``generate_all()`` before every test, so created/deleted playbooks
    never leak between cases.
    """

    _PAYLOAD: dict = {
        "title": "Custom Test Playbook",
        "description": "A user-defined playbook for testing.",
        "category": "custom",
        "severity": "LOW",
        "estimatedDurationMs": 5000,
        "steps": [
            {
                "stepId": "s1",
                "label": "Log activity",
                "delayMs": 0,
                "action": "activity",
                "activityType": 2,
                "description": "Test step on {agentName}",
            }
        ],
    }

    # ── Create ────────────────────────────────────────────────────────────────

    def test_create_returns_200(self, client: TestClient, auth_headers: dict) -> None:
        """POST must succeed and return HTTP 200."""
        resp = client.post(f"{BASE}/_dev/playbooks", headers=auth_headers, json=self._PAYLOAD)
        assert resp.status_code == 200

    def test_create_returns_data_envelope(self, client: TestClient, auth_headers: dict) -> None:
        """Response must contain the standard ``data`` envelope."""
        resp = client.post(f"{BASE}/_dev/playbooks", headers=auth_headers, json=self._PAYLOAD)
        body = resp.json()
        assert "data" in body
        assert isinstance(body["data"], dict)

    def test_create_response_contains_required_fields(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        """The created record must echo back title, category, severity, steps."""
        resp = client.post(f"{BASE}/_dev/playbooks", headers=auth_headers, json=self._PAYLOAD)
        data = resp.json()["data"]
        assert data["title"] == self._PAYLOAD["title"]
        assert data["category"] == self._PAYLOAD["category"]
        assert data["severity"] == self._PAYLOAD["severity"]
        assert len(data["steps"]) == len(self._PAYLOAD["steps"])

    def test_create_assigns_id(self, client: TestClient, auth_headers: dict) -> None:
        """The created record must have a non-empty ``id`` field."""
        resp = client.post(f"{BASE}/_dev/playbooks", headers=auth_headers, json=self._PAYLOAD)
        data = resp.json()["data"]
        assert "id" in data
        assert data["id"] != ""

    def test_create_marks_builtin_false(self, client: TestClient, auth_headers: dict) -> None:
        """User-created playbooks must have ``builtin: false``."""
        resp = client.post(f"{BASE}/_dev/playbooks", headers=auth_headers, json=self._PAYLOAD)
        assert resp.json()["data"]["builtin"] is False

    def test_create_appears_in_list(self, client: TestClient, auth_headers: dict) -> None:
        """After creation the new playbook must appear in GET /_dev/playbooks."""
        new_id = client.post(
            f"{BASE}/_dev/playbooks", headers=auth_headers, json=self._PAYLOAD
        ).json()["data"]["id"]
        listing = client.get(f"{BASE}/_dev/playbooks", headers=auth_headers).json()["data"]
        assert any(p["id"] == new_id for p in listing)

    def test_create_does_not_remove_builtins(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        """Creating a custom playbook must not affect the four built-in ones."""
        client.post(f"{BASE}/_dev/playbooks", headers=auth_headers, json=self._PAYLOAD)
        listing = client.get(f"{BASE}/_dev/playbooks", headers=auth_headers).json()["data"]
        builtin_ids = {p["id"] for p in listing if p.get("builtin", True)}
        assert "phishing_excel_macro" in builtin_ids
        assert "ransomware_outbreak" in builtin_ids

    def test_create_with_explicit_id(self, client: TestClient, auth_headers: dict) -> None:
        """When a caller supplies an ``id`` it must be used as-is."""
        payload = {**self._PAYLOAD, "id": "my_custom_id"}
        resp = client.post(f"{BASE}/_dev/playbooks", headers=auth_headers, json=payload)
        assert resp.json()["data"]["id"] == "my_custom_id"

    # ── Update ────────────────────────────────────────────────────────────────

    def test_update_returns_200(self, client: TestClient, auth_headers: dict) -> None:
        """PUT on an existing ID must return HTTP 200."""
        pid = client.post(
            f"{BASE}/_dev/playbooks", headers=auth_headers, json=self._PAYLOAD
        ).json()["data"]["id"]
        resp = client.put(
            f"{BASE}/_dev/playbooks/{pid}", headers=auth_headers, json={"title": "Updated"}
        )
        assert resp.status_code == 200

    def test_update_changes_title(self, client: TestClient, auth_headers: dict) -> None:
        """A PUT with a new ``title`` must persist the new value."""
        pid = client.post(
            f"{BASE}/_dev/playbooks", headers=auth_headers, json=self._PAYLOAD
        ).json()["data"]["id"]
        client.put(
            f"{BASE}/_dev/playbooks/{pid}", headers=auth_headers, json={"title": "Renamed"}
        )
        detail = client.get(
            f"{BASE}/_dev/playbooks/{pid}", headers=auth_headers
        ).json()["data"]
        assert detail["title"] == "Renamed"

    def test_update_preserves_unmentioned_fields(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        """Fields absent from the PUT body must keep their original values."""
        pid = client.post(
            f"{BASE}/_dev/playbooks", headers=auth_headers, json=self._PAYLOAD
        ).json()["data"]["id"]
        client.put(f"{BASE}/_dev/playbooks/{pid}", headers=auth_headers, json={"title": "X"})
        detail = client.get(
            f"{BASE}/_dev/playbooks/{pid}", headers=auth_headers
        ).json()["data"]
        assert detail["severity"] == self._PAYLOAD["severity"]
        assert len(detail["steps"]) == len(self._PAYLOAD["steps"])

    def test_update_unknown_id_returns_404(self, client: TestClient, auth_headers: dict) -> None:
        """PUT on a non-existent ID must return HTTP 404."""
        resp = client.put(
            f"{BASE}/_dev/playbooks/does_not_exist",
            headers=auth_headers,
            json={"title": "X"},
        )
        assert resp.status_code == 404

    def test_update_builtin_playbook(self, client: TestClient, auth_headers: dict) -> None:
        """Built-in playbooks are mutable in the registry (intentional dev-tool behaviour)."""
        resp = client.put(
            f"{BASE}/_dev/playbooks/quiet_day_reset",
            headers=auth_headers,
            json={"title": "Silent Day"},
        )
        assert resp.status_code == 200
        assert resp.json()["data"]["title"] == "Silent Day"

    # ── Delete ────────────────────────────────────────────────────────────────

    def test_delete_returns_200(self, client: TestClient, auth_headers: dict) -> None:
        """DELETE on an existing ID must return HTTP 200."""
        pid = client.post(
            f"{BASE}/_dev/playbooks", headers=auth_headers, json=self._PAYLOAD
        ).json()["data"]["id"]
        resp = client.delete(f"{BASE}/_dev/playbooks/{pid}", headers=auth_headers)
        assert resp.status_code == 200

    def test_delete_affected_is_1_on_success(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        """``data.affected`` must equal 1 when a playbook is deleted."""
        pid = client.post(
            f"{BASE}/_dev/playbooks", headers=auth_headers, json=self._PAYLOAD
        ).json()["data"]["id"]
        resp = client.delete(f"{BASE}/_dev/playbooks/{pid}", headers=auth_headers)
        assert resp.json()["data"]["affected"] == 1

    def test_delete_removes_from_list(self, client: TestClient, auth_headers: dict) -> None:
        """After deletion the playbook must no longer appear in GET /_dev/playbooks."""
        pid = client.post(
            f"{BASE}/_dev/playbooks", headers=auth_headers, json=self._PAYLOAD
        ).json()["data"]["id"]
        client.delete(f"{BASE}/_dev/playbooks/{pid}", headers=auth_headers)
        listing = client.get(f"{BASE}/_dev/playbooks", headers=auth_headers).json()["data"]
        assert not any(p["id"] == pid for p in listing)

    def test_delete_unknown_id_affected_is_0(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        """``data.affected`` must equal 0 for a non-existent ID (no 404)."""
        resp = client.delete(f"{BASE}/_dev/playbooks/nonexistent_xyz", headers=auth_headers)
        assert resp.status_code == 200
        assert resp.json()["data"]["affected"] == 0

    def test_delete_does_not_shadow_cancel_endpoint(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        """DELETE /cancel must still resolve to the cancel handler, not delete."""
        resp = client.delete(f"{BASE}/_dev/playbooks/cancel", headers=auth_headers)
        assert resp.status_code == 200
        # Cancel returns {"cancelled": bool}, not {"affected": int}
        assert "cancelled" in resp.json()["data"]
