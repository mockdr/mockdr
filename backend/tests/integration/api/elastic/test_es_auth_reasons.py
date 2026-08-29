"""One 401, five reasons — and a client that logs the reason can act on it.

Measured on Elasticsearch 8.15, header by header.  The cluster tells apart a
request that carried no credentials from one whose header it could not read
from one whose credentials were wrong, and it words the two unreadable
`Basic` cases differently again: bytes that are not base64 are an *encoding*
failure, base64 without a colon a *value* failure.  `ApiKey` and `Bearer`
share a wording of their own that names neither user nor path.

mockdr answered `unable to authenticate user for REST request [...]` to five
of the six, so a connector with a mangled header was told its credentials
were wrong.
"""
from __future__ import annotations

import base64

from fastapi.testclient import TestClient

PATH = "/elastic/logs-endpoint/_count"
GOOD = base64.b64encode(b"elastic:mock-elastic-password").decode()
WRONG = base64.b64encode(b"elastic:wrongpassword").decode()
NO_COLON = base64.b64encode(b"nocolonhere").decode()


def _reason(response) -> str:
    error = response.json()["error"]
    return str(error["reason"] if isinstance(error, dict) else error)


def _ask(client: TestClient, header: str | None):
    return client.get(PATH, headers={"Authorization": header} if header else {})


class TestWhyTheClusterSaysNo:
    def test_nothing_at_all_is_missing_credentials(self, client: TestClient) -> None:
        assert _reason(_ask(client, None)) == (
            f"missing authentication credentials for REST request [{PATH}]"
        )

    def test_a_scheme_with_nothing_after_it_is_missing_too(
        self, client: TestClient,
    ) -> None:
        for header in ("Basic", "ApiKey", "Bearer"):
            assert _reason(_ask(client, header)) == (
                f"missing authentication credentials for REST request [{PATH}]"
            ), header

    def test_a_scheme_it_does_not_know_is_missing_as_well(
        self, client: TestClient,
    ) -> None:
        assert _reason(_ask(client, "Zzz abc")) == (
            f"missing authentication credentials for REST request [{PATH}]"
        )

    def test_basic_that_is_not_base64_is_an_encoding_failure(
        self, client: TestClient,
    ) -> None:
        assert _reason(_ask(client, "Basic !!!!")) == (
            "invalid basic authentication header encoding"
        )

    def test_basic_without_a_colon_is_a_value_failure(
        self, client: TestClient,
    ) -> None:
        assert _reason(_ask(client, f"Basic {NO_COLON}")) == (
            "invalid basic authentication header value"
        )

    def test_basic_with_wrong_credentials_names_the_user(
        self, client: TestClient,
    ) -> None:
        assert _reason(_ask(client, f"Basic {WRONG}")) == (
            f"unable to authenticate user [elastic] for REST request [{PATH}]"
        )

    def test_apikey_and_bearer_share_a_wording_of_their_own(
        self, client: TestClient,
    ) -> None:
        """It names neither the user nor the path."""
        for header in ("Bearer zzz", "ApiKey !!!!", f"ApiKey {NO_COLON}"):
            assert _reason(_ask(client, header)) == (
                "unable to authenticate with provided credentials and anonymous "
                "access is not allowed for this request"
            ), header

    def test_every_one_of_them_is_a_401(self, client: TestClient) -> None:
        for header in (None, "Basic", "Basic !!!!", f"Basic {NO_COLON}",
                       f"Basic {WRONG}", "Bearer zzz", "ApiKey", "Zzz abc"):
            assert _ask(client, header).status_code == 401, header

    def test_the_scheme_is_case_insensitive(self, client: TestClient) -> None:
        assert _ask(client, f"basic {GOOD}").status_code == 200
        assert _ask(client, f"BASIC {GOOD}").status_code == 200
