"""The `Link` back to a job, on both spellings of the path.

`SplunkJobLinkMiddleware`'s own comment says it sits inside the namespace
rewrite, so that a job addressed as `/servicesNS/{owner}/{app}/search/jobs/
{sid}` is seen by its `/services/...` path. It was added *after* the
rewrite, and `add_middleware` prepends — so it ran outside, saw the
original path, matched nothing, and every answer through `/servicesNS/`
carried no `Link` at all.

splunkd sends one on both spellings, identical (measured on 10.4.2 against
a job that exists):

    /services/search/jobs/{sid}                       <{sid}>; rel=info
    /servicesNS/admin/search/search/jobs/{sid}        <{sid}>; rel=info
    /services/search/jobs/{sid}/results               <../{sid}>; rel=info
    /servicesNS/admin/search/search/jobs/{sid}/results  <../{sid}>; rel=info

The link is relative to the request, not to the mount, which is why the
sub-resource climbs one level.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

AUTH = {"Authorization": "Basic YWRtaW46bW9ja2RyLWFkbWlu"}  # admin:mockdr-admin
_NS = "/splunk/servicesNS/admin/search/search/jobs"
_PLAIN = "/splunk/services/search/jobs"


@pytest.fixture
def sid(client: TestClient) -> str:
    resp = client.post(_PLAIN, headers=AUTH,
                       data={"search": "search index=sentinelone | head 1"})
    assert resp.status_code in (200, 201), resp.text
    return str(resp.json()["sid"])


class TestBothSpellingsCarryIt:
    def test_the_job_itself(self, client: TestClient, sid: str) -> None:
        for base in (_PLAIN, _NS):
            resp = client.get(f"{base}/{sid}", headers=AUTH)
            assert resp.status_code == 200, base
            assert resp.headers.get("link") == f"<{sid}>; rel=info", base

    def test_a_sub_resource_climbs_one_level(
        self, client: TestClient, sid: str,
    ) -> None:
        for base in (_PLAIN, _NS):
            resp = client.get(f"{base}/{sid}/results", headers=AUTH)
            assert resp.status_code == 200, base
            assert resp.headers.get("link") == f"<../{sid}>; rel=info", base

    def test_a_refusal_carries_it_too(self, client: TestClient) -> None:
        """Which is the whole reason it is middleware and not a router."""
        missing = client.get(f"{_NS}/nosuchsid", headers=AUTH)
        assert missing.status_code == 404
        assert missing.headers.get("link") == "<nosuchsid>; rel=info"

        wrong_verb = client.put(f"{_NS}/nosuchsid/results", headers=AUTH)
        assert wrong_verb.status_code == 405
        assert wrong_verb.headers.get("link") == "<../nosuchsid>; rel=info"


class TestWhatCarriesNone:
    def test_the_collection_and_export(self, client: TestClient) -> None:
        """Neither is a job, and neither gets a link to one."""
        for path in (_PLAIN, _NS, f"{_NS}/export"):
            resp = client.get(path, headers=AUTH)
            assert "link" not in resp.headers, path
