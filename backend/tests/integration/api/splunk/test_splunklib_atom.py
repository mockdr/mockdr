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


class TestCollectionEntriesCarryTheirLinks:
    """``Collection.list()`` builds every entity from ``links.alternate``.

    splunkd's entry carries its ``<link>`` elements -- ``alternate`` first,
    then ``<author>``, then the rest -- and the entity's ACL inside its
    content as ``eai:acl``. The mock rendered title, id, updated and content
    alone, so ``service.indexes.list()``, ``saved_searches``, ``users``,
    ``apps``, ``kvstore`` -- every collection splunklib reads -- raised
    ``AttributeError: alternate`` on the first entry.
    """

    @pytest.mark.parametrize("collection", [
        "data/indexes", "saved/searches", "authentication/users", "apps/local",
    ])
    def test_every_entry_links_its_alternate(
        self, raw: TestClient, auth: dict[str, str], collection: str,
    ) -> None:
        response = raw.get(f"/splunk/services/{collection}", headers=auth)
        assert response.status_code == 200, response.text
        entries = ElementTree.fromstring(response.text).findall(f"{ATOM}entry")
        assert entries
        for entry in entries:
            links = entry.findall(f"{ATOM}link")
            assert links and links[0].get("rel") == "alternate", collection
            assert links[0].get("href", "").startswith("/services")
            assert entry.findtext(f"{ATOM}author/{ATOM}name")

    def test_the_acl_is_inside_the_content(self, raw: TestClient, auth: dict[str, str]) -> None:
        response = raw.get("/splunk/services/data/indexes", headers=auth)
        entry = ElementTree.fromstring(response.text).find(f"{ATOM}entry")
        assert entry is not None
        keys = entry.findall(f"{ATOM}content/{REST}dict/{REST}key")
        acl = next(k for k in keys if k.get("name") == "eai:acl")
        names = {k.get("name") for k in acl.findall(f"{REST}dict/{REST}key")}
        assert {"app", "owner", "sharing", "perms"} <= names

    def test_the_json_form_is_unchanged(self, raw: TestClient, auth: dict[str, str]) -> None:
        """JSON keeps ``acl`` beside the content and ``eai:acl`` null in it."""
        body = raw.get("/splunk/services/data/indexes?output_mode=json", headers=auth).json()
        entry = body["entry"][0]
        assert entry["acl"]["owner"]
        assert entry["content"].get("eai:acl") is None
