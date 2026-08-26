"""Contract checks against what ``splunk-sdk-python`` actually reads.

splunkd renders every Atom content value as a string — booleans as ``"1"`` /
``"0"`` — and the SDK depends on it rather than coercing. ``Job.is_done()`` is
literally ``self._state.content["isDone"] is True``, so a JSON boolean makes
that comparison permanently False and the documented polling loop
(``while not job.is_done(): sleep(.2)``) never terminates against the mock.
"""
import base64
import json

from fastapi.testclient import TestClient

SPLUNK_PREFIX = "/splunk"


def _auth() -> dict[str, str]:
    encoded = base64.b64encode(b"admin:mockdr-admin").decode()
    return {"Authorization": f"Basic {encoded}"}


def _create_job(client: TestClient) -> str:
    resp = client.post(
        f"{SPLUNK_PREFIX}/services/search/jobs",
        data={"search": "search index=sentinelone"},
        headers=_auth(),
        params={"output_mode": "json"},
    )
    return str(resp.json()["sid"])


def _job_content(client: TestClient, sid: str) -> dict:
    resp = client.get(
        f"{SPLUNK_PREFIX}/services/search/jobs/{sid}",
        headers=_auth(),
        params={"output_mode": "json"},
    )
    return dict(resp.json()["entry"][0]["content"])


class TestJobStatusValuesAreNative:
    """Job content carries native JSON types, not strings.

    2.0.1 asserted the opposite — "1"/"0" for booleans, strings for counts —
    reasoning from splunklib's `content["isDone"] == "1"`. That comparison is
    right for the Atom XML splunklib requests, where everything is text.
    Measured on Splunk 10.4.2, output_mode=json carries real booleans and
    integers, on the job list and the single job alike; doneProgress is the
    integer 1 once done.
    """

    def test_is_done_uses_the_sdk_sentinel(self, client: TestClient) -> None:
        content = _job_content(client, _create_job(client))

        # This is the exact expression splunklib.client.Job.is_done() evaluates.
        assert content["isDone"] is True

    def test_boolean_fields_are_json_bools(self, client: TestClient) -> None:
        content = _job_content(client, _create_job(client))
        for field in ("isDone", "isFailed", "isPaused", "isSaved"):
            assert isinstance(content[field], bool), f"{field} is {content[field]!r}"

    def test_numeric_fields_are_numbers(self, client: TestClient) -> None:
        content = _job_content(client, _create_job(client))
        for field in ("eventCount", "resultCount", "scanCount", "ttl"):
            assert isinstance(content[field], int) and not isinstance(content[field], bool), field
        assert content["doneProgress"] == 1  # the integer, once done (measured)

    def test_job_listing_agrees_with_job_detail(self, client: TestClient) -> None:
        sid = _create_job(client)
        listed = client.get(
            f"{SPLUNK_PREFIX}/services/search/jobs",
            headers=_auth(), params={"output_mode": "json"},
        ).json()["entry"]

        entry = next(e for e in listed if e["content"]["sid"] == sid)
        assert entry["content"]["isDone"] is True


class TestSdkPollingLoopTerminates:
    """The loop the SDK docs prescribe must exit."""

    def test_documented_poll_loop_exits(self, client: TestClient) -> None:
        sid = _create_job(client)

        for _ in range(20):
            if _job_content(client, sid)["isDone"] is True:
                break
        else:
            msg = "polling loop never saw isDone == '1'"
            raise AssertionError(msg)


class TestBothSdkApiModesAreServed:
    """splunk-sdk-python drives v2 by default and v1 with disable_v2_api.

    The mock registered job create/status/control/summary under v1 while
    results/events lived only under v2 — a combination no real Splunk has, so
    neither SDK mode completed a search end to end.
    """

    def _lifecycle(self, client: TestClient, base: str) -> None:
        created = client.post(
            f"{SPLUNK_PREFIX}{base}",
            data={"search": "search index=sentinelone"},
            headers=_auth(), params={"output_mode": "json"},
        )
        assert created.status_code in (200, 201), f"{base} create"
        sid = created.json()["sid"]

        status = client.get(
            f"{SPLUNK_PREFIX}{base}/{sid}", headers=_auth(),
            params={"output_mode": "json"},
        )
        assert status.status_code == 200, f"{base}/{{sid}} status"

        for verb in ("get", "post"):
            for sub in ("results", "events"):
                resp = getattr(client, verb)(
                    f"{SPLUNK_PREFIX}{base}/{sid}/{sub}",
                    headers=_auth(), params={"output_mode": "json"},
                )
                assert resp.status_code == 200, f"{verb.upper()} {base}/{{sid}}/{sub}"

        for sub in ("summary", "timeline"):
            resp = client.get(
                f"{SPLUNK_PREFIX}{base}/{sid}/{sub}",
                headers=_auth(), params={"output_mode": "json"},
            )
            assert resp.status_code == 200, f"{base}/{{sid}}/{sub}"

        control = client.post(
            f"{SPLUNK_PREFIX}{base}/{sid}/control",
            data={"action": "finalize"}, headers=_auth(),
            params={"output_mode": "json"},
        )
        assert control.status_code == 200, f"{base}/{{sid}}/control"

    def test_v2_lifecycle(self, client: TestClient) -> None:
        self._lifecycle(client, "/services/search/v2/jobs")

    def test_v1_lifecycle(self, client: TestClient) -> None:
        self._lifecycle(client, "/services/search/jobs")

    def test_job_listing_is_served_on_both(self, client: TestClient) -> None:
        for base in ("/services/search/jobs", "/services/search/v2/jobs"):
            resp = client.get(
                f"{SPLUNK_PREFIX}{base}", headers=_auth(),
                params={"output_mode": "json"},
            )
            assert resp.status_code == 200, base


class TestJobLifecycleStatusCodes:
    """Statuses and bodies splunkd returns for the job lifecycle."""

    def test_create_returns_201(self, client: TestClient) -> None:
        resp = client.post(
            f"{SPLUNK_PREFIX}/services/search/jobs",
            data={"search": "search index=sentinelone"},
            headers=_auth(), params={"output_mode": "json"},
        )
        assert resp.status_code == 201

    def test_oneshot_returns_results_not_a_sid(self, client: TestClient) -> None:
        # splunklib refuses exec_mode="oneshot" in Jobs.create() precisely
        # because the endpoint answers with results; returning a sid left the
        # caller polling a job it was never handed.
        resp = client.post(
            f"{SPLUNK_PREFIX}/services/search/jobs",
            data={"search": "search index=sentinelone | head 3", "exec_mode": "oneshot"},
            headers=_auth(), params={"output_mode": "json"},
        )
        body = resp.json()

        assert resp.status_code == 200
        assert "sid" not in body
        assert "results" in body

    def test_export_streams_ndjson(self, client: TestClient) -> None:
        # POST: splunkd answers 405 `Allow: POST` to a GET here, whatever
        # query string it carries (measured on 10.4.2).
        resp = client.post(
            f"{SPLUNK_PREFIX}/services/search/jobs/export",
            params={"search": "search index=sentinelone | head 3", "output_mode": "json"},
            headers=_auth(),
        )
        lines = [line for line in resp.text.splitlines() if line.strip()]

        assert len(lines) == 3, "one JSON object per line, not one envelope"
        for offset, line in enumerate(lines):
            row = json.loads(line)
            # JSONResultsReader keys off `preview`; its absence left
            # reader.is_preview as None where the SDK asserts False.
            assert row["preview"] is False
            assert row["offset"] == offset
            assert "result" in row


class TestJobControl:
    """Control actions change observable state and reject nonsense."""

    def _sid(self, client: TestClient) -> str:
        return str(client.post(
            f"{SPLUNK_PREFIX}/services/search/jobs",
            data={"search": "search index=sentinelone"},
            headers=_auth(), params={"output_mode": "json"},
        ).json()["sid"])

    def test_pause_is_observable(self, client: TestClient) -> None:
        sid = self._sid(client)
        client.post(
            f"{SPLUNK_PREFIX}/services/search/jobs/{sid}/control",
            data={"action": "pause"}, headers=_auth(),
            params={"output_mode": "json"},
        )

        content = _job_content(client, sid)
        assert content["isPaused"] is True
        assert content["dispatchState"] == "PAUSED"

    def test_unpause_reverses_it(self, client: TestClient) -> None:
        sid = self._sid(client)
        for action in ("pause", "unpause"):
            client.post(
                f"{SPLUNK_PREFIX}/services/search/jobs/{sid}/control",
                data={"action": action}, headers=_auth(),
                params={"output_mode": "json"},
            )
        assert _job_content(client, sid)["isPaused"] is False

    def test_unknown_action_is_rejected(self, client: TestClient) -> None:
        sid = self._sid(client)
        resp = client.post(
            f"{SPLUNK_PREFIX}/services/search/jobs/{sid}/control",
            data={"action": "definitely_not_an_action"}, headers=_auth(),
            params={"output_mode": "json"},
        )
        assert resp.status_code == 400

    def test_control_on_a_missing_job_is_404(self, client: TestClient) -> None:
        resp = client.post(
            f"{SPLUNK_PREFIX}/services/search/jobs/no-such-sid/control",
            data={"action": "cancel"}, headers=_auth(),
            params={"output_mode": "json"},
        )
        assert resp.status_code == 404


class TestResultValuesAreStrings:
    """Every value in a Splunk result row is a string.

    JSON numbers and booleans leaked the mock's internal types through, so a
    client comparing ``row["count"] == "38"`` — which is what real Splunk
    returns — did not match while ``int(row["count"])`` did.
    """

    def _results(self, client: TestClient, spl: str) -> list[dict]:
        sid = client.post(
            f"{SPLUNK_PREFIX}/services/search/jobs",
            data={"search": spl}, headers=_auth(),
            params={"output_mode": "json"},
        ).json()["sid"]
        return list(client.get(
            f"{SPLUNK_PREFIX}/services/search/v2/jobs/{sid}/results",
            headers=_auth(), params={"output_mode": "json", "count": 0},
        ).json()["results"])

    def test_aggregate_counts_are_strings(self, client: TestClient) -> None:
        rows = self._results(client, "search index=sentinelone | stats count")
        assert rows
        assert isinstance(rows[0]["count"], str)

    def test_every_scalar_is_a_string(self, client: TestClient) -> None:
        rows = self._results(client, "search index=sentinelone | head 5")
        for row in rows:
            for name, value in row.items():
                assert isinstance(value, (str, list)), f"{name} is {type(value).__name__}"

    def test_multivalue_fields_are_lists_of_strings(self, client: TestClient) -> None:
        rows = self._results(
            client, "search index=sentinelone | stats values(sourcetype) as types",
        )
        assert rows
        types = rows[0]["types"]
        assert isinstance(types, list)
        assert all(isinstance(t, str) for t in types)


class TestDispatchLifecycle:
    """A search job can walk the states real Splunk walks.

    The search runs synchronously, so by default a job reports DONE at once and
    every response stays deterministic. With a dispatch window configured the
    job passes through QUEUED, PARSING, RUNNING and FINALIZING — without which
    the SDK's polling loop is never actually exercised, only short-circuited.
    """

    def test_default_reports_done_immediately(self, client: TestClient) -> None:
        content = _job_content(client, _create_job(client))
        assert content["dispatchState"] == "DONE"
        assert content["isDone"] is True

    def test_states_are_observable_with_a_dispatch_window(
        self, client: TestClient, monkeypatch: object,
    ) -> None:
        import time

        from application.splunk.queries import search as search_queries

        monkeypatch.setattr(search_queries, "SPLUNK_DISPATCH_SECONDS", 1.0)  # type: ignore[attr-defined]
        sid = _create_job(client)

        seen: list[str] = []
        for _ in range(30):
            content = _job_content(client, sid)
            state = str(content["dispatchState"])
            if not seen or seen[-1] != state:
                seen.append(state)
            if content["isDone"] is True:
                break
            time.sleep(0.1)

        assert seen[0] != "DONE", "the job was done before it started"
        assert seen[-1] == "DONE"
        assert set(seen) <= {"QUEUED", "PARSING", "RUNNING", "FINALIZING", "DONE"}

    def test_results_are_available_regardless_of_state(
        self, client: TestClient, monkeypatch: object,
    ) -> None:
        from application.splunk.queries import search as search_queries

        monkeypatch.setattr(search_queries, "SPLUNK_DISPATCH_SECONDS", 30.0)  # type: ignore[attr-defined]
        sid = _create_job(client)

        # Still QUEUED, but the search itself already ran.
        assert _job_content(client, sid)["isDone"] is False
        results = client.get(
            f"{SPLUNK_PREFIX}/services/search/v2/jobs/{sid}/results",
            headers=_auth(), params={"output_mode": "json", "count": 0},
        ).json()["results"]
        assert results

    def test_blocking_exec_mode_ignores_the_window(
        self, client: TestClient, monkeypatch: object,
    ) -> None:
        from application.splunk.queries import search as search_queries

        monkeypatch.setattr(search_queries, "SPLUNK_DISPATCH_SECONDS", 30.0)  # type: ignore[attr-defined]
        sid = client.post(
            f"{SPLUNK_PREFIX}/services/search/jobs",
            data={"search": "search index=sentinelone", "exec_mode": "blocking"},
            headers=_auth(), params={"output_mode": "json"},
        ).json()["sid"]

        # blocking waits for completion, so it is done when it returns.
        assert _job_content(client, sid)["isDone"] is True
