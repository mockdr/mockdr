"""Bodies built to break a parser, and credentials a client puts in a query.

A body nested past Python's recursion limit answered 500 on the routes that
parse JSON themselves — the unauthenticated webhook sink among them — and an
OAuth client secret sent in a query string sat in the request log in full,
readable by every holder of the documented admin token.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

ES_AUTH = ("elastic", "mock-elastic-password")
DEEP = b"[" * 100_000 + b"]" * 100_000


def test_the_public_webhook_sink_refuses_a_too_deep_body(client: TestClient) -> None:
    resp = client.post("/web/api/v2.1/_dev/webhook-sink", content=DEEP,
                       headers={"content-type": "application/json"})
    assert resp.status_code == 400


def test_the_public_webhook_sink_survives_a_non_numeric_content_length() -> None:
    """A malformed Content-Length used to raise ValueError and answer 500.

    Driven below the client, which otherwise recomputes the header.
    """
    from api.routers.webhook_sink import receive_webhook

    scope = {
        "type": "http", "method": "POST", "path": "/_dev/webhook-sink",
        "headers": [(b"content-length", b"not-a-number")],
    }

    async def receive() -> dict:
        return {"type": "http.request", "body": b"{}", "more_body": False}

    import anyio
    from starlette.requests import Request

    result = anyio.run(receive_webhook, Request(scope, receive))
    assert "data" in result


@pytest.mark.parametrize("path", ["/elastic/_bulk", "/elastic/_msearch"])
def test_ndjson_routes_refuse_a_too_deep_line(client: TestClient, path: str) -> None:
    body = DEEP + b"\n" + b"{}\n"
    resp = client.post(path, content=body, auth=ES_AUTH,
                       headers={"content-type": "application/x-ndjson"})
    assert resp.status_code == 400
    assert "error" in resp.json()


def test_an_oauth_secret_in_the_query_is_masked_in_the_request_log(
    client: TestClient, auth_headers: dict,
) -> None:
    client.post("/mde/oauth2/v2.0/token?client_secret=SUPERSECRET123", data={})
    entries = client.get("/web/api/v2.1/_dev/requests", headers=auth_headers).json()["data"]
    logged = next(e for e in entries if e["path"] == "/mde/oauth2/v2.0/token")
    assert "SUPERSECRET123" not in logged["query_string"]
    assert logged["query_string"] == "client_secret=***T123"
