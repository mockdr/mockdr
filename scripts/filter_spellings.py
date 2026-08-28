# ruff: noqa: ANN001, ANN201, ANN202, D103, S101, T201
# A release tool, not library code: every function is local to this file.
"""Ask whether two spellings of one filter select the same records.

`param_effect.py` asks whether a filter narrows at all and `filter_effect.py`
asks the same of the filters that travel in a body. Both are satisfied by a
filter that narrows *wrongly*, and that is what was found: CrowdStrike's FQL
groups terms with parentheses — Falcon's own documentation and console write
`(status:'normal')+platform_name:'Windows'` — and the parser did not know the
character. A group beside another term was dropped in silence, so that query
answered thirty-five Windows hosts where the plain spelling answered the
thirty-three normal ones. A wider set than the caller asked for, with a 200,
and no audit could see it: the filter *did* narrow, just not to the right
thing.

Each pair below is two ways of writing one filter that the vendor's own
language treats as equal. The records they select must match, exactly.

    backend/.venv/bin/python scripts/filter_spellings.py

Exit status 1 when anything is flagged.
"""

from __future__ import annotations

import logging
import sys
import warnings
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
logging.disable(logging.CRITICAL)
warnings.filterwarnings("ignore")

#: mount -> route, the parameter the filter travels in, and where the
#: records sit in the answer.
_SURFACES = {
    "cs": ("/cs/devices/queries/devices/v1", "filter", "resources"),
    "cs-alerts": ("/cs/alerts/queries/alerts/v2", "filter", "resources"),
    "mde": ("/mde/api/machines", "$filter", "value"),
    "graph": ("/graph/v1.0/security/alerts_v2", "$filter", "value"),
}

#: Pairs the vendor's language treats as one filter. The first spelling is
#: the plain one, the second the one the vendor's own console writes.
_PAIRS = {
    "cs": [
        ("platform_name:'Windows'", "(platform_name:'Windows')"),
        ("status:'normal'+platform_name:'Windows'",
         "(status:'normal')+platform_name:'Windows'"),
        ("status:'normal'+platform_name:'Windows'",
         "(status:'normal')+(platform_name:'Windows')"),
    ],
    "cs-alerts": [
        ("status:'new'", "(status:'new')"),
    ],
    "mde": [
        ("healthStatus eq 'Active'", "(healthStatus eq 'Active')"),
        ("healthStatus eq 'Active' and osPlatform eq 'Windows10'",
         "(healthStatus eq 'Active') and osPlatform eq 'Windows10'"),
    ],
    "graph": [
        ("severity eq 'high'", "(severity eq 'high')"),
        ("severity eq 'high' and status eq 'new'",
         "(severity eq 'high') and (status eq 'new')"),
    ],
}


def _identities(client):
    """A usable set of credentials per mount."""
    def bearer(path, data):
        return {"Authorization": "Bearer " + client.post(path, data=data).json()["access_token"]}

    falcon = bearer("/cs/oauth2/token", {
        "client_id": "cs-mock-admin-client", "client_secret": "cs-mock-admin-secret",
    })
    return {
        "cs": falcon,
        "cs-alerts": falcon,
        "mde": bearer("/mde/oauth2/v2.0/token", {
            "client_id": "mde-mock-admin-client",
            "client_secret": "mde-mock-admin-secret",
            "grant_type": "client_credentials",
            "scope": "https://api.securitycenter.microsoft.com/.default",
        }),
        "graph": bearer("/graph/oauth2/v2.0/token", {
            "client_id": "graph-mock-admin-client",
            "client_secret": "graph-mock-admin-secret",
            "grant_type": "client_credentials",
            "scope": "https://graph.microsoft.com/.default",
        }),
    }


def _selected(client, headers, route, parameter, collection, value):
    """What one spelling selects: the ids, or the failure that stopped it."""
    answer = client.get(route, headers=headers, params={parameter: value, "limit": 500})
    if answer.status_code != 200:
        return f"HTTP {answer.status_code}"
    records = answer.json().get(collection)
    if not isinstance(records, list):
        return "no collection in the answer"
    return sorted(
        str(r if isinstance(r, str) else r.get("id") or r.get("device_id") or r)
        for r in records
    )


def main():
    """Report every pair of spellings that select differently."""
    from fastapi.testclient import TestClient  # noqa: PLC0415
    from main import app  # noqa: PLC0415

    flags, compared = [], 0
    with TestClient(app) as client:
        identities = _identities(client)
        for mount, pairs in _PAIRS.items():
            route, parameter, collection = _SURFACES[mount]
            headers = identities[mount]
            for plain, grouped in pairs:
                compared += 1
                one = _selected(client, headers, route, parameter, collection, plain)
                other = _selected(client, headers, route, parameter, collection, grouped)
                if one != other:
                    flags.append((mount, plain, grouped, one, other))

    print(f"=== FILTER SPELLINGS === {compared} pair(s) compared")
    for mount, plain, grouped, one, other in flags:
        print(f"  {mount}: {plain!r}")
        print(f"      selects {len(one) if isinstance(one, list) else one}")
        print(f"           {grouped!r}")
        print(f"      selects {len(other) if isinstance(other, list) else other}")
    print(f"\n  {len(flags)} pair(s) that select differently")
    return 1 if flags else 0


if __name__ == "__main__":
    sys.exit(main())
