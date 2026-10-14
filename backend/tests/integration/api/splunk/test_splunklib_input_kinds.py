"""``data/inputs`` lists the input kinds, the way ``service.inputs`` walks them.

splunklib's ``Inputs.kinds`` reads ``GET data/inputs`` as Atom, takes every
entry whose links include ``create`` as a kind of input, and descends into
each entry that has none -- ``tcp`` is a namespace over ``raw``, ``cooked``
and ``ssl`` (``client.py``, ``Inputs._get_kind_list``); ``inputs.list()``
then reads each kind's collection. The mock served the collections
(``data/inputs/http``, ``monitor``, ``tcp/raw``) but not the listing above
them, so ``service.inputs.list()`` raised ``HTTPError 404`` before it
reached any of them.

The walk below is splunklib's, over the Atom it reads.
"""
from __future__ import annotations

from xml.etree import ElementTree

import pytest
from fastapi.testclient import TestClient

import main

ATOM = "{http://www.w3.org/2005/Atom}"
AUTH = ("admin", "mockdr-admin")


@pytest.fixture()
def raw(fresh_seed: None) -> TestClient:
    return TestClient(main.app)


def _kinds(raw: TestClient, subpath: list[str]) -> list[str]:
    """``Inputs._get_kind_list``, transcribed."""
    path = "/splunk/services/data/inputs" + "".join(f"/{p}" for p in subpath)
    response = raw.get(path, auth=AUTH)
    assert response.status_code == 200, (path, response.text[:200])
    kinds: list[str] = []
    for entry in ElementTree.fromstring(response.text).findall(f"{ATOM}entry"):
        title = entry.findtext(f"{ATOM}title") or ""
        this = [*subpath, title]
        if title == "all" or this == ["tcp", "ssl"]:
            continue
        if "create" in [link.get("rel") for link in entry.findall(f"{ATOM}link")]:
            kinds.append("/".join(this))
        else:
            kinds.extend(_kinds(raw, this))
    return kinds


class TestTheKindsWalk:
    """Every kind the walk finds is a collection the mock serves."""

    def test_the_walk_finds_the_served_kinds(self, raw: TestClient) -> None:
        assert sorted(_kinds(raw, [])) == ["http", "monitor", "tcp/raw"]

    def test_every_kind_found_lists(self, raw: TestClient) -> None:
        for kind in _kinds(raw, []):
            response = raw.get(f"/splunk/services/data/inputs/{kind}", auth=AUTH)
            assert response.status_code == 200, (kind, response.text[:200])
            assert ElementTree.fromstring(response.text).tag == f"{ATOM}feed"

    def test_the_namespaced_form_answers_too(self, raw: TestClient) -> None:
        response = raw.get("/splunk/servicesNS/nobody/search/data/inputs", auth=AUTH)
        assert response.status_code == 200, response.text[:200]
