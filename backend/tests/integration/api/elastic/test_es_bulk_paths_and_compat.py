"""Bulk as the official clients send it, and the compatibility version they name.

Three defects in the write path a client reaches first, and the header check
that sits in front of all of it.
"""
from __future__ import annotations

import base64

from fastapi.testclient import TestClient

AUTH = {"Authorization": "Basic " + base64.b64encode(
    b"elastic:mock-elastic-password").decode()}

#: What elasticsearch-py 8.15 sends on `_bulk` and `_msearch`: `_base.py`
#: rewrites `application/x-ndjson` through `_COMPAT_MIMETYPE_RE` into the
#: vendor type, and asks for `compatible-with=8` on the answer too.
CLIENT_8 = {
    **AUTH,
    "Content-Type": "application/vnd.elasticsearch+x-ndjson; compatible-with=8",
    "Accept": "application/vnd.elasticsearch+json; compatible-with=8",
}


def _ndjson(*lines: str) -> str:
    return "".join(f"{line}\n" for line in lines)


class TestTheOfficialClientsNdjsonIsRead:
    """`application/vnd.elasticsearch+x-ndjson` was answered with a 406.

    `XContentType.VND_JSON` registers both `vnd.elasticsearch+json` and
    `vnd.elasticsearch+x-ndjson` (v8.15.0), and every 8.x client sends the
    second on bulk and msearch — so `helpers.bulk` against the mock failed on
    its first request, with an error about a header the real cluster reads.
    """

    def test_bulk_under_the_vendor_ndjson_type(self, client: TestClient) -> None:
        resp = client.post(
            "/elastic/_bulk", headers=CLIENT_8, params={"refresh": "true"},
            content=_ndjson('{"index":{"_index":"zzz-vnd","_id":"1"}}', '{"v":1}'),
        )
        assert resp.status_code == 200, resp.text
        assert resp.json()["items"][0]["index"]["result"] == "created"

    def test_msearch_under_the_vendor_ndjson_type(self, client: TestClient) -> None:
        resp = client.post(
            "/elastic/_msearch", headers=CLIENT_8,
            content=_ndjson('{"index":"logs-endpoint"}', '{"size":0}'),
        )
        assert resp.status_code == 200, resp.text
        assert resp.json()["responses"][0]["status"] == 200

    def test_the_other_vendor_types_are_read_too(self, client: TestClient) -> None:
        for kind in ("yaml", "cbor", "smile"):
            resp = client.post(
                "/elastic/logs-endpoint/_search",
                headers={**AUTH,
                         "Content-Type": f"application/vnd.elasticsearch+{kind}"},
                content='{"size":0}',
            )
            assert resp.status_code == 200, kind


class TestBulkUnderAnIndex:
    """`/{index}/_bulk` had no route, so the mock said "no handler found".

    The bulk reference (docs-bulk.html, 8.15) documents `POST /<target>/_bulk`
    and `PUT` alike: the path names the index for every action that does not
    name its own. An action left with no index at all fails the whole request
    in `BulkRequest.validate()` before anything is written, with one
    "index is missing" per action.
    """

    def test_the_path_index_is_the_default(self, client: TestClient) -> None:
        resp = client.post(
            "/elastic/zzz-bulk-path/_bulk", headers=CLIENT_8,
            params={"refresh": "true"},
            content=_ndjson('{"index":{"_id":"a"}}', '{"v":1}',
                            '{"index":{"_index":"zzz-bulk-other","_id":"b"}}', '{"v":2}'),
        )
        assert resp.status_code == 200, resp.text
        items = resp.json()["items"]
        assert items[0]["index"]["_index"] == "zzz-bulk-path"
        assert items[1]["index"]["_index"] == "zzz-bulk-other"
        got = client.get("/elastic/zzz-bulk-path/_doc/a", headers=AUTH)
        assert got.json()["_source"] == {"v": 1}

    def test_put_takes_the_same_path(self, client: TestClient) -> None:
        resp = client.put(
            "/elastic/zzz-bulk-put/_bulk", headers=CLIENT_8,
            content=_ndjson('{"create":{"_id":"a"}}', '{"v":1}'),
        )
        assert resp.status_code == 200, resp.text
        assert resp.json()["items"][0]["create"]["_index"] == "zzz-bulk-put"

    def test_an_action_with_no_index_anywhere_fails_the_request(
        self, client: TestClient,
    ) -> None:
        resp = client.post(
            "/elastic/_bulk", headers=CLIENT_8,
            content=_ndjson('{"index":{"_index":"zzz-bulk-none","_id":"a"}}', '{"v":1}',
                            '{"index":{"_id":"b"}}', '{"v":2}',
                            '{"delete":{}}'),
        )
        assert resp.status_code == 400
        error = resp.json()["error"]
        assert error["type"] == "action_request_validation_exception"
        assert error["reason"] == (
            "Validation Failed: 1: index is missing;2: index is missing;"
            "3: id is missing;"
        )
        # Validated before anything is written: the first action, which was
        # fine, did not happen either.
        assert client.get("/elastic/zzz-bulk-none/_doc/a", headers=AUTH).status_code == 404


class TestADeleteOfNothingIsNotAnError:
    """`errors` was true when the only "failure" was a delete that found nothing.

    The bulk reference's own example (docs-bulk.html, 8.15) answers a delete
    of a missing document with `status: 404, result: not_found` and no
    `error` object, beside `"errors": false`. A client that retries a batch
    whenever `errors` is set retried one that had worked.
    """

    def test_errors_stays_false(self, client: TestClient) -> None:
        resp = client.post(
            "/elastic/_bulk", headers=CLIENT_8,
            content=_ndjson('{"index":{"_index":"zzz-bulk-del","_id":"a"}}', '{"v":1}',
                            '{"delete":{"_index":"zzz-bulk-del","_id":"never-was"}}'),
        )
        body = resp.json()
        assert body["items"][1]["delete"]["status"] == 404
        assert body["items"][1]["delete"]["result"] == "not_found"
        assert "error" not in body["items"][1]["delete"]
        assert body["errors"] is False


class TestTheCompatibilityVersionIsRead:
    """`compatible-with` was stripped and never looked at.

    `RestCompatibleVersionHelper.getCompatibleVersion` (v8.15.0) serves 7
    and 8 and refuses anything else before a handler runs, as a 400
    `media_type_header_exception` caused by a `status_exception` — which is
    what a 9.x client meeting an 8.x cluster sees
    (elastic/elasticsearch-net#8512, uken/fluent-plugin-elasticsearch#1061).
    A mock that served it hid the upgrade that would break.
    """

    def test_seven_and_eight_are_served(self, client: TestClient) -> None:
        for version in (7, 8):
            resp = client.post(
                "/elastic/logs-endpoint/_search", content='{"size":0}', headers={
                    **AUTH,
                    "Content-Type": f"application/vnd.elasticsearch+json; compatible-with={version}",
                    "Accept": f"application/vnd.elasticsearch+json; compatible-with={version}",
                })
            assert resp.status_code == 200, version

    def test_nine_on_accept_is_refused(self, client: TestClient) -> None:
        accept = "application/vnd.elasticsearch+json; compatible-with=9"
        resp = client.get("/elastic/_cluster/health", headers={**AUTH, "Accept": accept})
        assert resp.status_code == 400
        assert resp.json() == {
            "error": {
                "root_cause": [{
                    "type": "media_type_header_exception",
                    "reason": "Invalid media-type value on headers [Content-Type, Accept]",
                }],
                "type": "media_type_header_exception",
                "reason": "Invalid media-type value on headers [Content-Type, Accept]",
                "caused_by": {
                    "type": "status_exception",
                    "reason": "Accept version must be either version 8 or 7, but "
                              f"found 9. Accept={accept}",
                },
            },
            "status": 400,
        }

    def test_nine_on_a_body_is_refused(self, client: TestClient) -> None:
        content_type = "application/vnd.elasticsearch+x-ndjson; compatible-with=9"
        resp = client.post("/elastic/_bulk", headers={
            **AUTH, "Content-Type": content_type,
            "Accept": "application/vnd.elasticsearch+json; compatible-with=8",
        }, content=_ndjson('{"index":{"_index":"zzz-nine"}}', "{}"))
        assert resp.status_code == 400
        assert resp.json()["error"]["caused_by"]["reason"] == (
            "Content-Type version must be either version 8 or 7, but found 9. "
            f"Content-Type={content_type}"
        )

    def test_a_version_on_only_one_header_is_refused(self, client: TestClient) -> None:
        content_type = "application/vnd.elasticsearch+json; compatible-with=8"
        resp = client.post("/elastic/logs-endpoint/_search", content='{"size":0}',
                           headers={**AUTH, "Content-Type": content_type})
        assert resp.status_code == 400
        assert resp.json()["error"]["caused_by"]["reason"] == (
            "A compatible version is required on both Content-Type and Accept "
            "headers if either one has requested a compatible version. "
            f"Accept=null, Content-Type={content_type}"
        )

    def test_versions_that_differ_are_refused(self, client: TestClient) -> None:
        resp = client.post("/elastic/logs-endpoint/_search", content='{"size":0}', headers={
            **AUTH,
            "Content-Type": "application/vnd.elasticsearch+json; compatible-with=7",
            "Accept": "application/vnd.elasticsearch+json; compatible-with=8",
        })
        assert resp.status_code == 400
        assert "the compatible versions must match" in (
            resp.json()["error"]["caused_by"]["reason"])

    def test_without_a_body_only_accept_counts(self, client: TestClient) -> None:
        resp = client.get("/elastic/_cluster/health", headers={
            **AUTH, "Content-Type": "application/vnd.elasticsearch+json; compatible-with=9",
        })
        assert resp.status_code == 200

    def test_an_anonymous_caller_still_gets_its_401(self, client: TestClient) -> None:
        """The authentication failure wins; the header one is only suppressed."""
        resp = client.get("/elastic/_cluster/health", headers={
            "Accept": "application/vnd.elasticsearch+json; compatible-with=9",
        })
        assert resp.status_code == 401
