"""Guard against catastrophic backtracking in the Graph ``$filter`` parser.

``_LAMBDA_RE`` was unanchored, so the engine retried the match at every offset
inside a long word run and each retry scanned to the end — quadratic. A 32KB
filter took ~2.8s to reject, and a handful of concurrent requests could stall
a worker while looking like ordinary traffic.
"""
import time

import pytest
from fastapi.testclient import TestClient

# How much dearer a hostile filter may be than an ordinary one, measured in
# the same conditions rather than against the clock.
#
# This was an absolute budget of one second, chosen as "well under the old
# cost (~2.8s) and far above the fixed one (~1ms)". It failed anyway, once,
# under twenty parallel workers — because a wall-clock budget measures the
# machine as much as the code, and raising it is no answer either: the broken
# version took 2.8s, so any budget loose enough to survive load would let the
# regression through.
#
# A ratio does not care how loaded the machine is. Quadratic cost me a
# factor of roughly 2 800 here; linear costs a small multiple of a normal
# request, and the floor keeps timer noise on a fast reject from mattering.
_HOSTILE_COST_LIMIT = 50
_NOISE_FLOOR_SECONDS = 0.05


class TestHostileFilterIsRejectedQuickly:
    """A pathological filter must not cost more than a normal one."""

    @pytest.mark.parametrize("size", [8_000, 32_000])
    def test_long_lambda_prefix_returns_promptly(
        self, client: TestClient, graph_admin_headers: dict, size: int,
    ) -> None:
        def ask(expression: str) -> tuple[float, int]:
            start = time.perf_counter()
            answer = client.get(
                "/graph/v1.0/users",
                params={"$filter": expression},
                headers=graph_admin_headers,
            )
            return time.perf_counter() - start, answer.status_code

        ordinary_filter = "assignedLicenses/any(l: l/skuId eq 'not-a-real-sku')"
        ask(ordinary_filter)  # warm up; route setup is not this test's subject
        ordinary, _ = ask(ordinary_filter)
        elapsed, status = ask("assignedLicenses/any(" + "a" * size)

        allowed = ordinary * _HOSTILE_COST_LIMIT + _NOISE_FLOOR_SECONDS
        assert elapsed < allowed, (
            f"{size}-byte filter cost {elapsed:.3f}s against {ordinary:.3f}s for an "
            f"ordinary one — {elapsed / max(ordinary, 1e-6):.0f}x, and backtracking "
            f"has regressed"
        )
        assert status in (200, 400)

    def test_cost_grows_linearly_not_quadratically(
        self, client: TestClient, graph_admin_headers: dict,
    ) -> None:
        def cost(size: int) -> float:
            start = time.perf_counter()
            client.get(
                "/graph/v1.0/users",
                params={"$filter": "assignedLicenses/any(" + "a" * size},
                headers=graph_admin_headers,
            )
            return time.perf_counter() - start

        cost(4_000)  # warm up, so import/route setup is not charged to the first call
        small = cost(4_000)
        large = cost(16_000)

        # Quadratic would be ~16x for 4x the input; linear is ~4x. Allow ample
        # slack for timer noise while still failing on quadratic growth.
        assert large < small * 10 + 0.05, (
            f"4x the input cost {large / max(small, 1e-6):.1f}x the time"
        )


class TestLegitimateLambdaFiltersStillWork:
    """The anchor must not change what the parser accepts."""

    def test_lambda_filter_is_still_applied(
        self, client: TestClient, graph_admin_headers: dict,
    ) -> None:
        resp = client.get(
            "/graph/v1.0/users",
            params={"$filter": "assignedLicenses/any(l: l/skuId eq 'not-a-real-sku')"},
            headers=graph_admin_headers,
        )

        assert resp.status_code == 200
        assert resp.json()["value"] == [], "filter was ignored, not applied"

    def test_lambda_filter_matches_a_real_sku(
        self, client: TestClient, graph_admin_headers: dict,
    ) -> None:
        users = client.get(
            "/graph/v1.0/users", headers=graph_admin_headers,
        ).json()["value"]
        sku = next(
            (
                lic["skuId"]
                for user in users
                for lic in user.get("assignedLicenses", [])
                if lic.get("skuId")
            ),
            None,
        )
        if sku is None:
            pytest.skip("no seeded user holds a licence")

        resp = client.get(
            "/graph/v1.0/users",
            params={"$filter": f"assignedLicenses/any(l: l/skuId eq '{sku}')"},
            headers=graph_admin_headers,
        )

        assert resp.status_code == 200
        assert resp.json()["value"], "lambda filter matched nothing for a real sku"
