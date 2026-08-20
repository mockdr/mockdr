"""Contract checks against what ``splunk-sdk-python`` actually reads.

splunkd renders every Atom content value as a string — booleans as ``"1"`` /
``"0"`` — and the SDK depends on it rather than coercing. ``Job.is_done()`` is
literally ``self._state.content["isDone"] == "1"``, so a JSON boolean makes
that comparison permanently False and the documented polling loop
(``while not job.is_done(): sleep(.2)``) never terminates against the mock.
"""
import base64

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
