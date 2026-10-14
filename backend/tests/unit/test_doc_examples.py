"""`scripts/doc_examples.py` has to fail on a broken example, or it checks nothing.

The harness gates CI on every curl line the documentation prints. A harness
that cannot fail is worse than none -- it turns "nobody ran the README" into
"the README is verified". Each test plants one kind of broken example and
asserts the harness names it, and one plants a correct example of each
directive to show it is not failing everything.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest

_SCRIPT = Path(__file__).resolve().parents[3] / "scripts" / "doc_examples.py"


@pytest.fixture(scope="module")
def harness() -> ModuleType:
    spec = importlib.util.spec_from_file_location("doc_examples", _SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["doc_examples"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture()
def mock(harness: ModuleType):
    return harness.Mock(None)


def _run(harness: ModuleType, mock, text: str, lang: str = "bash",
         marker: tuple[str, str] | None = None,
         env: dict[str, str] | None = None) -> tuple[str, list[str]]:
    block = harness.Block("planted.md", 1, lang, text, marker)
    return harness.run_block(block, mock, {} if env is None else env)


S1 = 'curl -H "Authorization: ApiToken admin-token-0000-0000-000000000001" '


class TestAWorkingExamplePasses:
    def test_a_plain_request(self, harness, mock) -> None:
        assert _run(harness, mock, S1 + "http://localhost:8001/web/api/v2.1/agents") == (
            "run", [])

    def test_a_documented_refusal_after_the_command(self, harness, mock) -> None:
        text = ("curl http://localhost:8001/web/api/v2.1/agents\n"
                "# → 401 Unauthorized")
        assert _run(harness, mock, text)[1] == []

    def test_a_documented_refusal_before_the_command(self, harness, mock) -> None:
        text = ("# 400, in SentinelOne's own validation envelope\n"
                + S1 + "'localhost:5001/web/api/v2.1/agents?coreCount__lt=abc'")
        assert _run(harness, mock, text)[1] == []

    def test_a_token_carried_through_a_pipe(self, harness, mock) -> None:
        text = (
            'TOKEN=$(curl -s -X POST http://localhost:8001/cs/oauth2/token \\\n'
            '  -d "client_id=cs-mock-admin-client&client_secret=cs-mock-admin-secret" \\\n'
            '  | jq -r .access_token)\n'
            'curl -H "Authorization: Bearer $TOKEN" '
            'http://localhost:8001/cs/devices/queries/devices/v1'
        )
        assert _run(harness, mock, text)[1] == []

    def test_a_documented_value(self, harness, mock) -> None:
        text = (S1 + "'http://localhost:8001/web/api/v2.1/agents?limit=1'\n"
                "# pagination.totalItems: 60")
        assert _run(harness, mock, text)[1] == []

    def test_a_continued_block_keeps_the_variables(self, harness, mock) -> None:
        env: dict[str, str] = {}
        _run(harness, mock, "T=admin-token-0000-0000-000000000001\n" + S1
             + "http://localhost:8001/web/api/v2.1/agents", env=env)
        text = ('curl -H "Authorization: ApiToken $T" '
                "http://localhost:8001/web/api/v2.1/sites")
        assert _run(harness, mock, text, marker=("continue", ""), env=env)[1] == []


class TestABrokenExampleFails:
    def test_an_error_status_the_doc_does_not_announce(self, harness, mock) -> None:
        _, problems = _run(harness, mock, "curl http://localhost:8001/web/api/v2.1/agents")
        assert problems and "401" in problems[0]

    def test_a_status_other_than_the_one_announced(self, harness, mock) -> None:
        text = S1 + "http://localhost:8001/web/api/v2.1/agents\n# → 403 Forbidden"
        _, problems = _run(harness, mock, text)
        assert problems and "the doc says 403" in problems[0]

    def test_a_value_other_than_the_one_documented(self, harness, mock) -> None:
        text = (S1 + "'http://localhost:8001/web/api/v2.1/agents?limit=1'\n"
                "# pagination.totalItems: 61")
        _, problems = _run(harness, mock, text)
        assert problems and "the doc says 61" in problems[0]

    def test_a_variable_nothing_set(self, harness, mock) -> None:
        text = 'curl -H "Authorization: ApiToken $TOKEN" http://localhost:8001/web/api/v2.1/agents'
        _, problems = _run(harness, mock, text)
        assert problems and "$TOKEN" in problems[0]

    def test_a_block_does_not_inherit_without_saying_so(self, harness, mock) -> None:
        env = {"T": "admin-token-0000-0000-000000000001"}
        text = 'curl -H "Authorization: ApiToken $T" http://localhost:8001/web/api/v2.1/sites'
        _, problems = _run(harness, mock, text, env=env)
        assert problems and "$T" in problems[0]

    def test_a_request_to_a_real_product(self, harness, mock) -> None:
        _, problems = _run(harness, mock, "curl https://api.crowdstrike.com/oauth2/token")
        assert problems and "not the mock" in problems[0]

    def test_a_shell_block_nobody_marked(self, harness, mock) -> None:
        _, problems = _run(harness, mock, "docker compose up -d")
        assert problems and "mark it skip" in problems[0]

    def test_a_skip_without_a_reason(self, harness, mock) -> None:
        _, problems = _run(harness, mock, "docker compose up -d", marker=("skip", ""))
        assert problems and "reason" in problems[0]

    def test_json_that_is_not(self, harness, mock) -> None:
        _, problems = _run(harness, mock, '{"reply": [...]}', lang="json")
        assert problems

    def test_python_that_does_not_compile(self, harness, mock) -> None:
        _, problems = _run(harness, mock, 'x = {"a": {}, ...}', lang="python")
        assert problems

    def test_a_query_that_finds_nothing(self, harness, mock) -> None:
        text = "search index=sentinelone | where nosuchfield=\"x\""
        _, problems = _run(harness, mock, text, lang="spl")
        assert problems and "returns nothing" in problems[0]

    def test_a_query_splunkd_refuses(self, harness, mock) -> None:
        _, problems = _run(harness, mock, "index=sentinelone | head 1", lang="spl")
        assert problems and "Unknown search command" in problems[0]

    def test_a_kql_query_that_does_not_run(self, harness, mock) -> None:
        _, problems = _run(harness, mock, "NoSuchTable | take 1", lang="kql")
        assert problems


class TestADirectiveDoesNotLeak:
    def test_an_announced_status_ends_at_the_blank_line(self, harness, mock) -> None:
        text = ("# 400, refused\n"
                + S1 + "'localhost:5001/web/api/v2.1/agents?coreCount__lt=abc'\n"
                "\n"
                + S1 + "http://localhost:8001/web/api/v2.1/agents")
        assert _run(harness, mock, text)[1] == []
