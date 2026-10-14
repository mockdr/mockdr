"""The Atom documents splunklib reads, parsed the way splunklib parses them.

splunklib asks for Atom XML -- it passes no ``output_mode`` on entity and
collection reads -- and walks the document with its own loader
(``splunklib.data.load``), so these tests parse each answer with
``xml.etree`` and look where the SDK looks. Each class names the SDK call
that failed against the mock.
"""
from __future__ import annotations

from xml.etree import ElementTree

import pytest
from fastapi.testclient import TestClient

import main

ATOM = "{http://www.w3.org/2005/Atom}"
REST = "{http://dev.splunk.com/ns/rest}"


@pytest.fixture()
def raw() -> TestClient:
    """A client that adds nothing -- no output_mode, so Atom comes back."""
    return TestClient(main.app)


@pytest.fixture()
def auth(raw: TestClient) -> dict[str, str]:
    response = raw.post("/splunk/services/auth/login",
                        data={"username": "admin", "password": "mockdr-admin"})
    key = ElementTree.fromstring(response.text).findtext("sessionKey")
    return {"Authorization": f"Splunk {key}"}


def _dispatch(raw: TestClient, auth: dict[str, str]) -> str:
    response = raw.post("/splunk/services/search/jobs", headers=auth,
                        data={"search": "search index=* | head 5"})
    assert response.status_code == 201, response.text
    sid = ElementTree.fromstring(response.text).findtext("sid")
    assert sid
    return sid


class TestJobsCreateAnswersASid:
    """``jobs.create()`` reads ``<response><sid>`` -- ``_load_sid``.

    splunkd answers a dispatch with ``<response><sid>…</sid></response>``,
    and splunklib reads it as ``_load_atom(response).response.sid``. The
    mock wrapped the sid in ``<s:dict>`` under an ``s:`` prefix the document
    never declares, so the answer was not well-formed XML and every
    ``jobs.create()`` died in the parser (``unbound prefix``).
    """

    def test_the_answer_is_a_bare_sid(self, raw: TestClient, auth: dict[str, str]) -> None:
        response = raw.post("/splunk/services/search/jobs", headers=auth,
                            data={"search": "search index=* | head 5"})
        assert response.status_code == 201, response.text
        root = ElementTree.fromstring(response.text)  # well-formed, or this raises
        assert root.tag == "response"
        assert [child.tag for child in root] == ["sid"]
        assert root.findtext("sid")
