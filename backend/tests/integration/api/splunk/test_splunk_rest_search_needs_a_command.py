"""Over REST a search string has to open with a command.

Only Splunk Web prepends the implicit ``search``; the REST ``search`` parameter
is the SPL itself. Measured on splunkd with the conformance stack, on oneshot,
normal, export and v2 alike: ``index=main | head 1`` answers 400
``{"messages":[{"type":"FATAL","text":"Unknown search command 'index'."}]}``,
while ``search index=main | head 1`` and ``| makeresults`` run. mockdr ran all
three, so a client that forgot the leading ``search`` passed against the mock
and failed against the product (probe spl-rest-search-without-the-search-command).
"""
import base64

import pytest
from fastapi.testclient import TestClient

_AUTH = {"Authorization": "Basic " + base64.b64encode(b"admin:mockdr-admin").decode()}

_ROUTES = [
    ("/splunk/services/search/jobs", {"exec_mode": "normal"}),
    ("/splunk/services/search/jobs", {"exec_mode": "oneshot"}),
    ("/splunk/services/search/v2/jobs", {"exec_mode": "oneshot"}),
    ("/splunk/services/search/jobs/export", {}),
]


class TestARestSearchOpensWithACommand:
    """A bare search is splunkd's 400; a command-led one runs."""

    @pytest.mark.parametrize(("path", "extra"), _ROUTES)
    @pytest.mark.parametrize(("search", "named"), [
        ("index=main | head 1", "index"),
        ("host=x", "host"),
    ])
    def test_a_bare_search_is_refused(
        self, client: TestClient, path: str, extra: dict, search: str, named: str,
    ) -> None:
        resp = client.post(path, headers=_AUTH, data={
            "search": search, "output_mode": "json", **extra,
        })
        assert resp.status_code == 400
        assert resp.json() == {"messages": [
            {"type": "FATAL", "text": f"Unknown search command '{named}'."},
        ]}

    @pytest.mark.parametrize(("path", "extra"), _ROUTES)
    @pytest.mark.parametrize("search", [
        "search index=main | head 1", "SEARCH index=main | head 1", "| makeresults",
    ])
    def test_a_command_led_search_runs(
        self, client: TestClient, path: str, extra: dict, search: str,
    ) -> None:
        resp = client.post(path, headers=_AUTH, data={
            "search": search, "output_mode": "json", **extra,
        })
        assert resp.status_code in (200, 201), resp.text

    def test_a_saved_search_still_dispatches_its_stored_text(self, client: TestClient) -> None:
        """Saved searches are stored without the leading `search`; dispatch adds it."""
        name = client.get(
            "/splunk/services/saved/searches", headers=_AUTH, params={"output_mode": "json"},
        ).json()["entry"][0]["name"]
        resp = client.post(
            f"/splunk/services/saved/searches/{name}/dispatch",
            headers=_AUTH, data={"output_mode": "json"},
        )
        assert resp.status_code < 400, resp.text
        assert resp.json()["sid"]
