"""`Accept-Encoding` is a negotiation, not a substring search for "gzip".

The middleware asked whether the header contained "gzip" anywhere. So
`Accept-Encoding: gzip;q=0` — which says *do not send me gzip* — was
answered with gzip, and nothing downstream of a client that cannot inflate
recovers from that. `deflate` and `*` were never offered at all, and the
name's case was folded for every product.

Each cell below was measured against the live product, one header at a
time, on Elasticsearch 8.15, Kibana 8.15 and splunkd 10.4.2. They agree
about `q=0` and about nothing else:

    header        Elasticsearch   splunkd   Kibana
    gzip          gzip            gzip      gzip
    gzip;q=0      --              --        --
    GZIP          --              gzip      gzip
    deflate       deflate         --        deflate
    *             deflate         --        --

Only the encoding each one *chooses* is measured here, not the byte format
it wraps the payload in.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

ES_AUTH = {"Authorization": "Basic ZWxhc3RpYzptb2NrLWVsYXN0aWMtcGFzc3dvcmQ="}
SPL_AUTH = {"Authorization": "Basic YWRtaW46bW9ja2RyLWFkbWlu"}

#: (path, auth, header, the encoding the live product chose)
MEASURED = [
    ("/elastic/_cluster/health", ES_AUTH, "gzip", "gzip"),
    ("/elastic/_cluster/health", ES_AUTH, "gzip;q=0", ""),
    ("/elastic/_cluster/health", ES_AUTH, "GZIP", ""),
    ("/elastic/_cluster/health", ES_AUTH, "Gzip", ""),
    ("/elastic/_cluster/health", ES_AUTH, "deflate", "deflate"),
    ("/elastic/_cluster/health", ES_AUTH, "*", "deflate"),
    ("/elastic/_cluster/health", ES_AUTH, "gzip;q=0.5", "gzip"),
    ("/splunk/services/server/info", SPL_AUTH, "gzip", "gzip"),
    ("/splunk/services/server/info", SPL_AUTH, "gzip;q=0", ""),
    ("/splunk/services/server/info", SPL_AUTH, "GZIP", "gzip"),
    ("/splunk/services/server/info", SPL_AUTH, "deflate", ""),
    ("/splunk/services/server/info", SPL_AUTH, "*", ""),
    ("/splunk/services/server/info", SPL_AUTH, "deflate, gzip;q=0", ""),
]

#: Kibana's threshold is 1024 bytes, so its cases need a body over it.
KIBANA = [
    ("gzip", "gzip"),
    ("gzip;q=0", ""),
    ("GZIP", "gzip"),
    ("deflate", "deflate"),
    ("*", ""),
    ("gzip;q=0.001", "gzip"),
]
_KIBANA_PATH = "/kibana/api/detection_engine/rules/_find"


@pytest.mark.parametrize(("path", "auth", "header", "expected"), MEASURED)
def test_the_mock_chooses_what_the_product_chose(
    client: TestClient, path: str, auth: dict, header: str, expected: str,
) -> None:
    # splunkd answers Atom XML unless asked for JSON; Elasticsearch refuses
    # the parameter outright, which is its own guard doing its job.
    params = {"output_mode": "json"} if path.startswith("/splunk") else {}
    resp = client.get(path, headers={**auth, "accept-encoding": header},
                      params=params)
    assert resp.status_code == 200, resp.text
    assert resp.headers.get("content-encoding", "") == expected


@pytest.mark.parametrize(("header", "expected"), KIBANA)
def test_kibana_above_its_threshold(
    client: TestClient, header: str, expected: str,
) -> None:
    resp = client.get(_KIBANA_PATH, headers={**ES_AUTH, "accept-encoding": header},
                      params={"per_page": 20})
    assert resp.status_code == 200, resp.text
    assert len(resp.content) > 1024, "body under Kibana's threshold; nothing to negotiate"
    assert resp.headers.get("content-encoding", "") == expected


def test_the_compressed_body_is_still_the_body(client: TestClient) -> None:
    """Negotiating the encoding must not change what was said."""
    plain = client.get(_KIBANA_PATH, headers={**ES_AUTH, "accept-encoding": "identity"},
                       params={"per_page": 20})
    for header in ("gzip", "deflate"):
        packed = client.get(_KIBANA_PATH, params={"per_page": 20},
                            headers={**ES_AUTH, "accept-encoding": header})
        assert packed.headers["content-encoding"] == header
        assert packed.json() == plain.json(), header
