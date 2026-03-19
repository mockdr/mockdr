"""Integration tests for GET /hashes/{hash}/verdict endpoint."""

from fastapi.testclient import TestClient

BASE = "/web/api/v2.1/hashes"


class TestHashVerdict:
    def test_unknown_hash_returns_undefined(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.get(f"{BASE}/aabbccddee1122334455/verdict", headers=auth_headers)
        assert resp.status_code == 200
        body = resp.json()
        assert body["data"]["verdict"] == "undefined"
        assert body["data"]["source"] == "cloud"

    def test_blocklisted_hash_returns_blacklisted(self, client: TestClient, auth_headers: dict) -> None:
        sha256 = "a" * 64
        client.post(
            "/web/api/v2.1/restrictions",
            headers=auth_headers,
            json={"data": {"type": "black_hash", "value": sha256, "description": "test hash"}},
        )
        resp = client.get(f"{BASE}/{sha256}/verdict", headers=auth_headers)
        assert resp.status_code == 200
        assert resp.json()["data"]["verdict"] == "blacklisted"

    def test_response_contains_required_fields(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.get(f"{BASE}/deadbeefdeadbeef/verdict", headers=auth_headers)
        body = resp.json()["data"]
        assert "verdict" in body
        assert "confidence" in body
        assert "source" in body

    def test_hash_lookup_is_case_insensitive(self, client: TestClient, auth_headers: dict) -> None:
        sha256 = "b" * 64
        client.post(
            "/web/api/v2.1/restrictions",
            headers=auth_headers,
            json={"data": {"type": "black_hash", "value": sha256.upper(), "description": "test"}},
        )
        resp = client.get(f"{BASE}/{sha256.lower()}/verdict", headers=auth_headers)
        assert resp.json()["data"]["verdict"] == "blacklisted"

    def test_unknown_hash_confidence_is_na(self, client: TestClient, auth_headers: dict) -> None:
        body = client.get(f"{BASE}/0000000000000000/verdict", headers=auth_headers).json()
        assert body["data"]["confidence"] == "n/a"

    def test_blocklisted_hash_source_is_user(self, client: TestClient, auth_headers: dict) -> None:
        sha256 = "c" * 64
        client.post(
            "/web/api/v2.1/restrictions",
            headers=auth_headers,
            json={"data": {"type": "black_hash", "value": sha256, "description": "src test"}},
        )
        body = client.get(f"{BASE}/{sha256}/verdict", headers=auth_headers).json()
        assert body["data"]["source"] == "user"

    def test_different_unknown_hashes_all_undefined(
        self, client: TestClient, auth_headers: dict,
    ) -> None:
        for h in ("d" * 64, "e" * 64, "f" * 40):
            body = client.get(f"{BASE}/{h}/verdict", headers=auth_headers).json()
            assert body["data"]["verdict"] == "undefined"

    def test_verdict_data_envelope(self, client: TestClient, auth_headers: dict) -> None:
        body = client.get(f"{BASE}/1234567890abcdef/verdict", headers=auth_headers).json()
        assert "data" in body
        assert isinstance(body["data"], dict)
