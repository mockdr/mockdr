"""RFC 9110 §6.6.1: an origin server sends `Date` on the answers it generates.

mockdr sent none, on any mount. uvicorn 0.52.4 adds neither `Date` nor
`Server` by default and nothing here made up the difference, so a client
that caches, computes an age, or measures clock skew against the server had
nothing to read -- while splunkd 10.4.2 and Kibana 8.15 both answer with one
every time.

Elasticsearch 8.15 is the measured exception: `/_cluster/health` and
`/_cat/indices` come back without a `Date` on 200 and on 401 alike. That
mount reproduces the product, departure and all; the departure belongs in a
conformance report rather than in an answer no real client would receive.
"""
from email.utils import parsedate_to_datetime

from fastapi.testclient import TestClient

S1_AUTH = {"Authorization": "ApiToken admin-token-0000-0000-000000000001"}
SPLUNK_AUTH = {"Authorization": "Basic YWRtaW46bW9ja2RyLWFkbWlu"}
ES_AUTH = {"Authorization": "Basic ZWxhc3RpYzptb2NrLWVsYXN0aWMtcGFzc3dvcmQ="}

_MOUNTS = [
    ("/web/api/v2.1/threats", S1_AUTH),
    ("/splunk/services/data/indexes", SPLUNK_AUTH),
    ("/kibana/api/features", ES_AUTH),
    ("/mde/api/machines", {}),          # a 401 is an answer too
    ("/graph/v1.0/users", {}),
    ("/xdr/public_api/v1/incidents/get_incidents", {}),
]


class TestEveryAnswerIsDated:
    def test_each_mount_sends_one(self, client: TestClient) -> None:
        undated = [
            path for path, headers in _MOUNTS
            if "date" not in {k.lower() for k in client.get(path, headers=headers).headers}
        ]

        assert not undated, f"answers with no Date: {undated}"

    def test_it_is_imf_fixdate(self, client: TestClient) -> None:
        """§5.6.7 admits one form, and `formatdate` without `usegmt` is not it."""
        raw = client.get("/web/api/v2.1/threats", headers=S1_AUTH).headers["date"]

        assert raw.endswith(" GMT"), raw
        # Parsing it back is the other half: a malformed date is worse than none.
        assert parsedate_to_datetime(raw).tzinfo is not None

    def test_it_is_sent_once(self, client: TestClient) -> None:
        raw = client.get("/web/api/v2.1/threats", headers=S1_AUTH).headers.get_list("date")

        assert len(raw) == 1, f"{len(raw)} Date headers"

    def test_elasticsearch_stays_silent_as_the_product_does(
        self, client: TestClient
    ) -> None:
        """Measured on 8.15: no `Date` on `/_cluster/health`, 200 or 401."""
        for path in ("/elastic/_cluster/health", "/elastic/_cat/indices"):
            resp = client.get(path, headers=ES_AUTH)

            assert "date" not in {k.lower() for k in resp.headers}, path
