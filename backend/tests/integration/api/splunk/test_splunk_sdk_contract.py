"""Contract checks against what ``splunk-sdk-python`` actually reads.

splunkd renders every Atom content value as a string — booleans as ``"1"`` /
``"0"`` — and the SDK depends on it rather than coercing. ``Job.is_done()`` is
literally ``self._state.content["isDone"] == "1"``, so a JSON boolean makes
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


class TestJobStatusValuesAreStrings:
    """Every content value splunkd emits is a string."""

    def test_is_done_uses_the_sdk_sentinel(self, client: TestClient) -> None:
        content = _job_content(client, _create_job(client))

        # This is the exact expression splunklib.client.Job.is_done() evaluates.
        assert content["isDone"] == "1"

    def test_boolean_fields_are_not_json_bools(self, client: TestClient) -> None:
        content = _job_content(client, _create_job(client))

        for field in ("isDone", "isFailed", "isPaused", "isSaved"):
            assert isinstance(content[field], str), f"{field} is not a string"
            assert content[field] in ("0", "1"), f"{field} is {content[field]!r}"

    def test_numeric_fields_are_strings(self, client: TestClient) -> None:
        content = _job_content(client, _create_job(client))

        for field in ("eventCount", "resultCount", "scanCount", "ttl", "doneProgress"):
            assert isinstance(content[field], str), f"{field} is not a string"

    def test_job_listing_agrees_with_job_detail(self, client: TestClient) -> None:
        sid = _create_job(client)
        listed = client.get(
            f"{SPLUNK_PREFIX}/services/search/jobs",
            headers=_auth(), params={"output_mode": "json"},
        ).json()["entry"]

        entry = next(e for e in listed if e["content"]["sid"] == sid)
        assert entry["content"]["isDone"] == "1"


class TestSdkPollingLoopTerminates:
    """The loop the SDK docs prescribe must exit."""

    def test_documented_poll_loop_exits(self, client: TestClient) -> None:
        sid = _create_job(client)

        for _ in range(20):
            if _job_content(client, sid)["isDone"] == "1":
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
        resp = client.get(
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
        assert content["isPaused"] == "1"
        assert content["dispatchState"] == "PAUSED"

    def test_unpause_reverses_it(self, client: TestClient) -> None:
        sid = self._sid(client)
        for action in ("pause", "unpause"):
            client.post(
                f"{SPLUNK_PREFIX}/services/search/jobs/{sid}/control",
                data={"action": action}, headers=_auth(),
                params={"output_mode": "json"},
            )
        assert _job_content(client, sid)["isPaused"] == "0"

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
