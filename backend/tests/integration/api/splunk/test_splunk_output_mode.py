"""Integration tests for Splunk's ``output_mode`` handling.

These use a plain TestClient rather than the SDK-style fixture, because the
point is what happens when ``output_mode`` is *not* supplied.
"""
from xml.etree import ElementTree

import pytest
from fastapi.testclient import TestClient

import main

SPLUNK_PREFIX = "/splunk"
_ATOM = "{http://www.w3.org/2005/Atom}"


@pytest.fixture()
def raw_client(fresh_seed: None) -> TestClient:
    """Client that adds nothing to the request, unlike the Splunk SDKs."""
    return TestClient(main.app)


def _session_key(client: TestClient) -> str:
    """Log in and return a session key."""
    resp = client.post(
        f"{SPLUNK_PREFIX}/services/auth/login?output_mode=json",
        data={"username": "admin", "password": "mockdr-admin"},
    )
    return str(resp.json()["sessionKey"])


class TestDefaultOutputIsXml:
    """splunkd answers in Atom XML unless JSON is requested."""

    def test_login_returns_xml_session_key(self, raw_client: TestClient) -> None:
        """The documented login response is ``<response><sessionKey>``."""
        resp = raw_client.post(f"{SPLUNK_PREFIX}/services/auth/login", data={
            "username": "admin", "password": "mockdr-admin",
        })
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("text/xml")
        root = ElementTree.fromstring(resp.text)
        assert root.tag == "response"
        assert root.findtext("sessionKey")

    def test_endpoint_returns_atom_feed(self, raw_client: TestClient) -> None:
        """Entry-shaped endpoints render as an Atom feed."""
        resp = raw_client.get(
            f"{SPLUNK_PREFIX}/services/data/indexes",
            headers={"Authorization": f"Splunk {_session_key(raw_client)}"},
        )
        assert resp.status_code == 200
        root = ElementTree.fromstring(resp.text)
        assert root.tag == f"{_ATOM}feed"
        assert root.findall(f"{_ATOM}entry")

    def test_explicit_xml_matches_the_default(self, raw_client: TestClient) -> None:
        """``output_mode=xml`` is the default spelled out."""
        headers = {"Authorization": f"Splunk {_session_key(raw_client)}"}
        default = raw_client.get(f"{SPLUNK_PREFIX}/services/server/info", headers=headers)
        explicit = raw_client.get(
            f"{SPLUNK_PREFIX}/services/server/info?output_mode=xml", headers=headers,
        )
        assert default.headers["content-type"] == explicit.headers["content-type"]
        assert ElementTree.fromstring(explicit.text).tag == f"{_ATOM}feed"

    def test_error_body_renders_as_xml_messages(self, raw_client: TestClient) -> None:
        """Failures use ``<response><messages><msg>``, not JSON."""
        resp = raw_client.post(f"{SPLUNK_PREFIX}/services/auth/login", data={
            "username": "admin", "password": "wrong-password",
        })
        assert resp.status_code == 401
        root = ElementTree.fromstring(resp.text)
        assert root.find("messages/msg") is not None

    def test_json_is_served_when_requested(self, raw_client: TestClient) -> None:
        resp = raw_client.get(
            f"{SPLUNK_PREFIX}/services/server/info?output_mode=json",
            headers={"Authorization": f"Splunk {_session_key(raw_client)}"},
        )
        assert resp.headers["content-type"].startswith("application/json")
        assert "entry" in resp.json()

    def test_hec_always_answers_json(self, raw_client: TestClient) -> None:
        """HEC is a separate service that ignores output_mode."""
        resp = raw_client.post(
            f"{SPLUNK_PREFIX}/services/collector/event",
            headers={"Authorization": "Splunk not-a-real-token"},
            json={"event": "hello"},
        )
        assert resp.headers["content-type"].startswith("application/json")
        assert "text" in resp.json()
