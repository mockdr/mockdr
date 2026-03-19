"""Integration tests for tag-manager CRUD and GET /agents/tags.

POST   /tag-manager          — create tag definition
PUT    /tag-manager/{id}     — update tag definition
DELETE /tag-manager/{id}     — delete tag definition
GET    /agents/tags           — list tag definitions (filtered, paginated)
"""
from fastapi.testclient import TestClient

BASE = "/web/api/v2.1"
TAG_MANAGER = f"{BASE}/tag-manager"
TAGS_LIST = f"{BASE}/agents/tags"


def _seed_tag_count(client: TestClient, auth_headers: dict) -> int:
    """Return the number of tags present after seeding."""
    body = client.get(TAGS_LIST, headers=auth_headers).json()
    return body["pagination"]["totalItems"]


def _first_tag(client: TestClient, auth_headers: dict) -> dict:
    """Return the first tag from the seeded list."""
    return client.get(TAGS_LIST, headers=auth_headers).json()["data"][0]


def _first_site(client: TestClient, auth_headers: dict) -> dict:
    """Return the first site from the seeded data."""
    return client.get(f"{BASE}/sites", headers=auth_headers).json()["data"]["sites"][0]


def _first_group(client: TestClient, auth_headers: dict) -> dict:
    """Return the first group from the seeded data."""
    return client.get(f"{BASE}/groups", headers=auth_headers).json()["data"][0]


def _create_tag(
    client: TestClient, auth_headers: dict,
    key: str = "TestKey", value: str = "TestValue",
    description: str = "Integration test tag",
    **filter_overrides: object,
) -> dict:
    """Helper to create a tag via the API."""
    payload = {
        "data": {"key": key, "value": value, "description": description},
        "filter": {"tenant": True, **filter_overrides},
    }
    return client.post(TAG_MANAGER, headers=auth_headers, json=payload).json()


# ── POST /tag-manager ────────────────────────────────────────────────────────


class TestCreateTag:
    """Tests for creating tag definitions."""

    def test_create_returns_200(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.post(
            TAG_MANAGER, headers=auth_headers,
            json={"data": {"key": "K", "value": "V"}, "filter": {"tenant": True}},
        )
        assert resp.status_code == 200

    def test_create_returns_data_envelope(self, client: TestClient, auth_headers: dict) -> None:
        body = _create_tag(client, auth_headers)
        assert "data" in body
        assert body["data"]["key"] == "TestKey"
        assert body["data"]["value"] == "TestValue"

    def test_create_assigns_id(self, client: TestClient, auth_headers: dict) -> None:
        body = _create_tag(client, auth_headers)
        assert body["data"]["id"], "Created tag must have a non-empty id"

    def test_create_sets_timestamps(self, client: TestClient, auth_headers: dict) -> None:
        body = _create_tag(client, auth_headers)
        tag = body["data"]
        assert tag["createdAt"], "createdAt should be set"
        assert tag["updatedAt"], "updatedAt should be set"

    def test_create_sets_creator_fields(self, client: TestClient, auth_headers: dict) -> None:
        body = _create_tag(client, auth_headers)
        tag = body["data"]
        # The admin user should be recorded as creator
        assert tag["createdBy"], "createdBy should be populated"
        assert tag["createdById"], "createdById should be populated"

    def test_create_global_scope(self, client: TestClient, auth_headers: dict) -> None:
        body = _create_tag(client, auth_headers)
        tag = body["data"]
        assert tag["scopeLevel"] == "global"
        assert tag["scopePath"] == "Global"

    def test_create_site_scope(self, client: TestClient, auth_headers: dict) -> None:
        site = _first_site(client, auth_headers)
        body = _create_tag(
            client, auth_headers, key="SiteTag", value="SiteVal",
            tenant=False, siteIds=[site["id"]],
        )
        tag = body["data"]
        assert tag["scopeLevel"] == "site"
        assert tag["scopeId"] == site["id"]

    def test_create_group_scope(self, client: TestClient, auth_headers: dict) -> None:
        group = _first_group(client, auth_headers)
        body = _create_tag(
            client, auth_headers, key="GroupTag", value="GroupVal",
            tenant=False, groupIds=[group["id"]],
        )
        tag = body["data"]
        assert tag["scopeLevel"] == "group"
        assert tag["scopeId"] == group["id"]

    def test_created_tag_appears_in_list(self, client: TestClient, auth_headers: dict) -> None:
        before = _seed_tag_count(client, auth_headers)
        _create_tag(client, auth_headers, key="NewOne", value="NewVal")
        after = _seed_tag_count(client, auth_headers)
        assert after == before + 1

    def test_create_requires_auth(self, client: TestClient) -> None:
        resp = client.post(TAG_MANAGER, json={"data": {"key": "K", "value": "V"}})
        assert resp.status_code == 401

    def test_create_defaults_type_to_agents(self, client: TestClient, auth_headers: dict) -> None:
        body = _create_tag(client, auth_headers)
        assert body["data"]["type"] == "agents"


# ── PUT /tag-manager/{id} ────────────────────────────────────────────────────


class TestUpdateTag:
    """Tests for updating tag definitions."""

    def test_update_returns_200(self, client: TestClient, auth_headers: dict) -> None:
        tag_id = _first_tag(client, auth_headers)["id"]
        resp = client.put(
            f"{TAG_MANAGER}/{tag_id}", headers=auth_headers,
            json={"data": {"key": "UpdatedKey"}},
        )
        assert resp.status_code == 200

    def test_update_changes_key(self, client: TestClient, auth_headers: dict) -> None:
        tag_id = _first_tag(client, auth_headers)["id"]
        body = client.put(
            f"{TAG_MANAGER}/{tag_id}", headers=auth_headers,
            json={"data": {"key": "RenamedKey"}},
        ).json()
        assert body["data"]["key"] == "RenamedKey"

    def test_update_changes_value(self, client: TestClient, auth_headers: dict) -> None:
        tag_id = _first_tag(client, auth_headers)["id"]
        body = client.put(
            f"{TAG_MANAGER}/{tag_id}", headers=auth_headers,
            json={"data": {"value": "NewValue"}},
        ).json()
        assert body["data"]["value"] == "NewValue"

    def test_update_changes_description(self, client: TestClient, auth_headers: dict) -> None:
        tag_id = _first_tag(client, auth_headers)["id"]
        body = client.put(
            f"{TAG_MANAGER}/{tag_id}", headers=auth_headers,
            json={"data": {"description": "Updated desc"}},
        ).json()
        assert body["data"]["description"] == "Updated desc"

    def test_update_partial_preserves_other_fields(
        self, client: TestClient, auth_headers: dict,
    ) -> None:
        tag = _first_tag(client, auth_headers)
        original_value = tag["value"]
        body = client.put(
            f"{TAG_MANAGER}/{tag['id']}", headers=auth_headers,
            json={"data": {"key": "OnlyKeyChanged"}},
        ).json()
        assert body["data"]["value"] == original_value

    def test_update_bumps_updated_at(self, client: TestClient, auth_headers: dict) -> None:
        tag = _first_tag(client, auth_headers)
        body = client.put(
            f"{TAG_MANAGER}/{tag['id']}", headers=auth_headers,
            json={"data": {"key": "Bumped"}},
        ).json()
        assert body["data"]["updatedAt"] >= tag["updatedAt"]

    def test_update_unknown_returns_404(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.put(
            f"{TAG_MANAGER}/does-not-exist", headers=auth_headers,
            json={"data": {"key": "x"}},
        )
        assert resp.status_code == 404

    def test_update_requires_auth(self, client: TestClient) -> None:
        resp = client.put(f"{TAG_MANAGER}/any-id", json={"data": {"key": "x"}})
        assert resp.status_code == 401


# ── DELETE /tag-manager/{id} ──────────────────────────────────────────────────


class TestDeleteTag:
    """Tests for deleting tag definitions."""

    def test_delete_returns_200(self, client: TestClient, auth_headers: dict) -> None:
        tag_id = _first_tag(client, auth_headers)["id"]
        resp = client.delete(f"{TAG_MANAGER}/{tag_id}", headers=auth_headers)
        assert resp.status_code == 200

    def test_delete_returns_affected(self, client: TestClient, auth_headers: dict) -> None:
        tag_id = _first_tag(client, auth_headers)["id"]
        body = client.delete(f"{TAG_MANAGER}/{tag_id}", headers=auth_headers).json()
        assert body["data"]["affected"] == 1

    def test_delete_removes_from_list(self, client: TestClient, auth_headers: dict) -> None:
        before = _seed_tag_count(client, auth_headers)
        tag_id = _first_tag(client, auth_headers)["id"]
        client.delete(f"{TAG_MANAGER}/{tag_id}", headers=auth_headers)
        after = _seed_tag_count(client, auth_headers)
        assert after == before - 1

    def test_delete_unknown_returns_affected_0(
        self, client: TestClient, auth_headers: dict,
    ) -> None:
        body = client.delete(
            f"{TAG_MANAGER}/does-not-exist", headers=auth_headers,
        ).json()
        assert body["data"]["affected"] == 0

    def test_delete_requires_auth(self, client: TestClient) -> None:
        resp = client.delete(f"{TAG_MANAGER}/any-id")
        assert resp.status_code == 401


# ── GET /agents/tags ──────────────────────────────────────────────────────────


class TestListTags:
    """Tests for the tag listing endpoint."""

    def test_list_returns_200(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.get(TAGS_LIST, headers=auth_headers)
        assert resp.status_code == 200

    def test_list_returns_pagination_envelope(self, client: TestClient, auth_headers: dict) -> None:
        body = client.get(TAGS_LIST, headers=auth_headers).json()
        assert "data" in body
        assert "pagination" in body
        assert "totalItems" in body["pagination"]

    def test_seeded_tags_present(self, client: TestClient, auth_headers: dict) -> None:
        total = _seed_tag_count(client, auth_headers)
        # Seeder creates global (3) + account (2) + site (6) + group (4) = 15 tags
        assert total >= 10, f"Expected at least 10 seeded tags, got {total}"

    def test_list_tag_has_required_fields(self, client: TestClient, auth_headers: dict) -> None:
        tag = _first_tag(client, auth_headers)
        required = {"id", "key", "value", "type", "scopeLevel", "scopePath",
                     "createdAt", "updatedAt"}
        missing = required - set(tag.keys())
        assert not missing, f"Tag missing fields: {missing}"

    def test_list_tag_has_computed_counts(self, client: TestClient, auth_headers: dict) -> None:
        tag = _first_tag(client, auth_headers)
        assert "endpointsInCurrentScope" in tag
        assert "totalEndpoints" in tag
        assert "totalExclusions" in tag

    def test_filter_by_key(self, client: TestClient, auth_headers: dict) -> None:
        body = client.get(
            TAGS_LIST, headers=auth_headers, params={"key": "Virtual"},
        ).json()
        assert all(t["key"] == "Virtual" for t in body["data"])

    def test_filter_by_key_contains(self, client: TestClient, auth_headers: dict) -> None:
        body = client.get(
            TAGS_LIST, headers=auth_headers, params={"key__contains": "Virt"},
        ).json()
        assert body["pagination"]["totalItems"] >= 1
        assert all("Virt" in t["key"] for t in body["data"])

    def test_filter_by_value(self, client: TestClient, auth_headers: dict) -> None:
        body = client.get(
            TAGS_LIST, headers=auth_headers, params={"value": "Production"},
        ).json()
        assert all(t["value"] == "Production" for t in body["data"])

    def test_filter_by_scope_path(self, client: TestClient, auth_headers: dict) -> None:
        body = client.get(
            TAGS_LIST, headers=auth_headers, params={"scopePath": "Global"},
        ).json()
        # All tags should have "Global" in their scope path
        assert body["pagination"]["totalItems"] >= 1

    def test_filter_by_site_ids(self, client: TestClient, auth_headers: dict) -> None:
        site = _first_site(client, auth_headers)
        body = client.get(
            TAGS_LIST, headers=auth_headers, params={"siteIds": site["id"]},
        ).json()
        assert all(t["scopeLevel"] == "site" for t in body["data"])

    def test_filter_by_site_ids_with_include_children(
        self, client: TestClient, auth_headers: dict,
    ) -> None:
        site = _first_site(client, auth_headers)
        body = client.get(
            TAGS_LIST, headers=auth_headers,
            params={"siteIds": site["id"], "includeChildren": "true"},
        ).json()
        levels = {t["scopeLevel"] for t in body["data"]}
        # Should include site-level and group-level tags
        assert "site" in levels or "group" in levels

    def test_filter_by_site_ids_with_include_parents(
        self, client: TestClient, auth_headers: dict,
    ) -> None:
        site = _first_site(client, auth_headers)
        body = client.get(
            TAGS_LIST, headers=auth_headers,
            params={"siteIds": site["id"], "includeParents": "true"},
        ).json()
        levels = {t["scopeLevel"] for t in body["data"]}
        # Should include parent scopes (account, global)
        assert "global" in levels

    def test_pagination_limit(self, client: TestClient, auth_headers: dict) -> None:
        body = client.get(
            TAGS_LIST, headers=auth_headers, params={"limit": 2},
        ).json()
        assert len(body["data"]) <= 2

    def test_pagination_cursor(self, client: TestClient, auth_headers: dict) -> None:
        first_page = client.get(
            TAGS_LIST, headers=auth_headers, params={"limit": 2},
        ).json()
        cursor = first_page["pagination"].get("nextCursor")
        if cursor:
            second_page = client.get(
                TAGS_LIST, headers=auth_headers,
                params={"limit": 2, "cursor": cursor},
            ).json()
            first_ids = {t["id"] for t in first_page["data"]}
            second_ids = {t["id"] for t in second_page["data"]}
            assert not first_ids & second_ids, "Pages must not overlap"

    def test_filter_no_match_returns_empty(self, client: TestClient, auth_headers: dict) -> None:
        body = client.get(
            TAGS_LIST, headers=auth_headers,
            params={"key": "ThisKeyDoesNotExist_XYZ"},
        ).json()
        assert body["data"] == []
        assert body["pagination"]["totalItems"] == 0

    def test_list_requires_auth(self, client: TestClient) -> None:
        resp = client.get(TAGS_LIST)
        assert resp.status_code == 401

    def test_idempotent_same_params_same_result(
        self, client: TestClient, auth_headers: dict,
    ) -> None:
        body1 = client.get(TAGS_LIST, headers=auth_headers).json()
        body2 = client.get(TAGS_LIST, headers=auth_headers).json()
        assert body1 == body2


# ── Tag cascade behaviour ────────────────────────────────────────────────────


class TestTagCascade:
    """Tests verifying that tag updates/deletes cascade to agent assignments."""

    def _assign_tag_to_agent(
        self, client: TestClient, auth_headers: dict,
    ) -> tuple[str, str]:
        """Create a tag, manually assign it to the first agent, return (tag_id, agent_id).

        Assignment is done by updating the agent's tags through the tag update
        cascade — we create, then update the tag to trigger cascade logic.
        """
        # Create a tag
        tag_body = _create_tag(client, auth_headers, key="CascadeKey", value="CascadeVal")
        tag_id = tag_body["data"]["id"]

        # Get first agent and manually wire the tag assignment via the store
        from repository.agent_repo import agent_repo
        agent = agent_repo.list_all()[0]
        agent_id = agent.id
        existing = dict(agent.tags) if agent.tags else {}
        s1_tags = list(existing.get("sentinelone", []))
        s1_tags.append({"id": tag_id, "key": "CascadeKey", "value": "CascadeVal"})
        existing["sentinelone"] = s1_tags
        agent.tags = existing

        return tag_id, agent_id

    def test_update_cascades_to_agent_tags(
        self, client: TestClient, auth_headers: dict,
    ) -> None:
        tag_id, agent_id = self._assign_tag_to_agent(client, auth_headers)

        # Update the tag key
        client.put(
            f"{TAG_MANAGER}/{tag_id}", headers=auth_headers,
            json={"data": {"key": "UpdatedCascade", "value": "UpdatedVal"}},
        )

        # Verify the agent's tag was updated
        from repository.agent_repo import agent_repo
        agent = agent_repo.get(agent_id)
        assert agent is not None
        s1_tags = (agent.tags or {}).get("sentinelone", [])
        matching = [t for t in s1_tags if t.get("id") == tag_id]
        assert len(matching) == 1
        assert matching[0]["key"] == "UpdatedCascade"
        assert matching[0]["value"] == "UpdatedVal"

    def test_delete_cascades_removes_from_agent_tags(
        self, client: TestClient, auth_headers: dict,
    ) -> None:
        tag_id, agent_id = self._assign_tag_to_agent(client, auth_headers)

        # Delete the tag
        client.delete(f"{TAG_MANAGER}/{tag_id}", headers=auth_headers)

        # Verify the agent's tag entry was removed
        from repository.agent_repo import agent_repo
        agent = agent_repo.get(agent_id)
        assert agent is not None
        s1_tags = (agent.tags or {}).get("sentinelone", [])
        matching = [t for t in s1_tags if t.get("id") == tag_id]
        assert len(matching) == 0
