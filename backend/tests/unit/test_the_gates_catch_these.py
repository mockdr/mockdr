"""Five behaviours nothing was checking, found by injecting the defect.

A suite that reports no failures says nothing about the defects it would
miss. Ten were injected into representative modules -- a comparison flipped,
a sort reversed, a boundary loosened -- and five went through 4975 tests and
32 audits without a murmur. These are those five, each pinned by the
behaviour a client actually depends on rather than by the line that was
mutated.
"""
import base64
import json

from fastapi.testclient import TestClient

from application.sentinel.commands.edr_bridge import _extract_entities_from_payload
from repository.sentinel.entity_repo import sentinel_entity_repo
from utils.graph_response import graph_page
from utils.pagination import THREAT_CURSOR, paginate

S1_AUTH = {"Authorization": "ApiToken admin-token-0000-0000-000000000001"}


class TestACursorResumesWhereThePageEnded:
    """`utils/pagination.py`: the cursor finds its record by id.

    Inverting that comparison left every audit green -- the collection still
    came back a page at a time, just cut in the wrong place.
    """

    def test_the_second_page_follows_the_first(self) -> None:
        items = [{"id": str(n), "threatInfo": {"createdAt": f"2026-01-{n:02d}"}}
                 for n in range(1, 10)]

        first, cursor, total = paginate(items, None, 3, THREAT_CURSOR)

        assert [i["id"] for i in first] == ["1", "2", "3"]
        assert total == 9
        assert cursor

        second, _, _ = paginate(items, cursor, 3, THREAT_CURSOR)

        assert [i["id"] for i in second] == ["4", "5", "6"], (
            "the cursor resumed somewhere other than after the first page"
        )

    def test_a_cursor_without_a_tiebreak_still_resumes(self) -> None:
        """The fallback path, which is the whole reason it exists.

        A cursor issued before the tiebreaker existed carries only the
        identity column, and `_resume_index` falls through to matching on
        that. Nothing exercised the fallback, so inverting its comparison
        left every gate green while an older client's cursor resumed at the
        wrong record -- exactly the compatibility this branch is for.
        """
        items = [{"id": str(n), "threatInfo": {"createdAt": f"2026-01-{n:02d}"}}
                 for n in range(1, 8)]
        legacy = base64.b64encode(json.dumps({
            "id_column": THREAT_CURSOR.id_column,
            "id_value": "3",
            "id_sort_order": THREAT_CURSOR.id_sort_order,
            "sort_by_column": THREAT_CURSOR._sort_by_column,
            "sort_by_value": "3",
            "sort_order": THREAT_CURSOR.sort_order,
        }, separators=(",", ":")).encode()).decode()

        page, _, _ = paginate(items, legacy, 2, THREAT_CURSOR)

        assert [i["id"] for i in page] == ["4", "5"], (
            "a tiebreak-less cursor resumed somewhere other than after id 3"
        )

    def test_no_record_is_seen_twice_or_skipped(self) -> None:
        items = [{"id": str(n), "threatInfo": {"createdAt": f"2026-01-{n:02d}"}}
                 for n in range(1, 12)]

        seen: list[str] = []
        cursor = None
        for _ in range(10):
            page, cursor, _ = paginate(items, cursor, 4, THREAT_CURSOR)
            seen.extend(i["id"] for i in page)
            if not cursor:
                break

        assert seen == [i["id"] for i in items]


class TestThreatsComeBackNewestFirst:
    """`application/threats/queries.py`: the documented default order.

    Reversing the sort is invisible to every shape check -- the same thirty
    threats come back, in the order an analyst reads last.
    """

    def test_the_default_listing_is_newest_first(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        data = client.get("/web/api/v2.1/threats", headers=auth_headers,
                          params={"limit": 30}).json()["data"]

        stamps = [t["threatInfo"]["createdAt"] for t in data]

        assert stamps == sorted(stamps, reverse=True), "oldest first"
        assert stamps[0] > stamps[-1], "the whole page is one timestamp"


class TestAMachineAnswersForItself:
    """`application/mde_machines/queries.py`: the vulnerabilities are *its*.

    The lookup that finds a machine's index by id was inverted and nothing
    noticed: the route still answered a list of vulnerabilities, just
    another machine's.
    """

    def test_two_machines_do_not_share_one_answer(self, client: TestClient) -> None:
        token = client.post("/mde/oauth2/v2.0/token", data={
            "grant_type": "client_credentials", "client_id": "mde-mock-admin-client",
            "client_secret": "mde-mock-admin-secret",
            "scope": "https://api.securitycenter.microsoft.com/.default",
        }).json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        machines = client.get("/mde/api/machines", headers=headers,
                              params={"$top": 3}).json()["value"]

        # The join a client makes: a machine's CVE must list that machine
        # back. Inverting the lookup hands each machine a *neighbour's*
        # vulnerabilities -- still a plausible list, still all different from
        # one another, and no longer about the machine that was asked.
        for machine in machines:
            vulns = client.get(f"/mde/api/machines/{machine['id']}/vulnerabilities",
                               headers=headers).json()["value"]
            assert vulns, machine["id"]
            for vuln in vulns[:1]:
                refs = client.get(
                    f"/mde/api/vulnerabilities/{vuln['id']}/machineReferences",
                    headers=headers).json()["value"]

                assert machine["id"] in {r.get("id") for r in refs}, (
                    f"{machine['computerDnsName']} reported {vuln['id']}, "
                    "which does not list it back"
                )


class TestEachVendorsEntitiesAreReadItsOwnWay:
    """`application/sentinel/commands/edr_bridge.py`: the CrowdStrike branch.

    Each vendor names the user differently -- `relatedUser.userName`,
    `threatInfo.processUser`, `user_name`. Losing one branch loses that
    vendor's entities, and the incident is still created, just emptier.
    """

    def test_a_crowdstrike_payload_yields_its_account(self) -> None:
        before = {e.entity_id for e in sentinel_entity_repo.list_all()}

        ids = _extract_entities_from_payload(
            {"user_name": "zzz-falcon-user", "hostname": "zzz-falcon-host",
             "local_ip": "10.11.12.13"}, "cs")

        assert ids, "no entity came out of a CrowdStrike payload"
        made = [e for e in sentinel_entity_repo.list_all()
                if e.entity_id in set(ids) - before or e.entity_id in ids]
        accounts = [e for e in made if str(e.kind) == "Account"]
        assert accounts, "the account branch produced nothing"
        assert accounts[0].properties["accountName"] == "zzz-falcon-user"


class TestTheLastGraphPageSaysItIsTheLast:
    """`utils/graph_response.py`: the boundary, not the interior.

    `>=` loosened to `>` publishes a `@odata.nextLink` pointing one past the
    end -- a client follows it and gets an empty page it was told to expect
    records in. Every collection in the middle of a walk behaves the same
    either way, which is why nothing saw it.
    """

    def test_an_exact_fit_has_no_next_link(self) -> None:
        records = [{"id": str(n)} for n in range(6)]

        page, next_link = graph_page(records, top=6, skip=0, resource="teams")

        assert len(page) == 6
        assert next_link is None, "a full page that is also the last announced more"

    def test_the_last_page_of_a_walk_has_no_next_link(self) -> None:
        records = [{"id": str(n)} for n in range(6)]

        _, first = graph_page(records, top=4, skip=0, resource="teams")
        page, last = graph_page(records, top=4, skip=4, resource="teams")

        assert first, "the first of two pages should announce the second"
        assert len(page) == 2
        assert last is None

    def test_a_short_collection_announces_nothing(self) -> None:
        page, next_link = graph_page([{"id": "1"}], top=100, skip=0, resource="teams")

        assert len(page) == 1
        assert next_link is None
