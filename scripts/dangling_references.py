# ruff: noqa: ANN001, ANN201, ANN202, D103, S101, T201
# A release tool, not library code: every function is local to this file.
"""Find a record that names a record this install does not have.

The audits that read answers check one answer at a time, and this defect
needs two: a Cortex incident assigned to somebody the tenant's user list has
never heard of, a Defender alert reporting an investigation
`/api/investigations/{id}` answers 404 for. Each single reply is plausible.
The client that follows the id it was just given is the one that finds out.

The sweep reads the seeded store rather than the routes. For every id-shaped
field it collects the values, and asks whether they resolve to a record some
collection holds. A field whose values resolve *nowhere at all* is not
flagged: plenty of them are identifiers of things this mock does not model —
a CrowdStrike customer id, a behaviour id, a correlation id — and inventing
records for those would be worse than leaving them opaque. What is flagged is
the field that resolves for some of its values and not for others, which is
what a broken link looks like when the same seeder writes both kinds.

Two were found the first time this ran, both on Defender alerts:
`investigationId` was a `random.randint(1, 50)` and `incidentId` a
`random.randint(1, 100)`.

    backend/.venv/bin/python scripts/dangling_references.py

Exit status 1 when anything is flagged.
"""

from __future__ import annotations

import collections
import dataclasses
import logging
import re
import sys
import warnings
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

#: A field that names something: `agentId`, `rule_ids`, `assigned_user_mail`.
_NAMES_SOMETHING = re.compile(r"([Ii]ds?|_ids?|_mail|[Uu]uid)$")

#: Fields that identify something this mock does not model, so their values
#: name nothing here on purpose. Each is listed with what it identifies in
#: the real product; a value of one that happens to equal a record's key
#: elsewhere is a coincidence, not a link.
_OPAQUE = {
    # The prevention-policy template instance a Falcon behaviour came from.
    # mockdr serves policies as the summary a host carries, not as templates.
    "cs_detections.behaviors[].template_instance_id",
    # SentinelOne numbers the indicators of a threat against its own
    # catalogue, which this mock does not serve; the numbers are small
    # enough to collide with a record key elsewhere on some draws.
    "threats.indicators[].ids[]",
    # Defender's RBAC device group. It names a group in the tenant's own
    # machine-group configuration, which mockdr does not serve as a
    # collection, so the number can only ever resolve by collision — and on
    # one draw in CI it did, against three unrelated collections at once.
    "mde_machines.rbacGroupId",
    "splunk_events.fields.rbacGroupId",
    "graph_security_alerts.evidence[].rbacGroupId",
}

#: Keys a record is addressed by, beside the key it is stored under.
_PRIMARY_KEYS = (
    "id", "machineId", "device_id", "endpoint_id", "agent_id", "sid",
    "rule_id", "user_email", "incident_id", "alert_id", "uuid",
    "composite_id", "detection_id", "event_id", "investigationId",
)


def as_dict(record):
    """A stored record as a plain dict, whatever it is stored as."""
    if isinstance(record, dict):
        return record
    if dataclasses.is_dataclass(record) and not isinstance(record, type):
        return dataclasses.asdict(record)
    return dict(getattr(record, "__dict__", {}) or {})


def addressable(store):
    """Every value any record in this install can be found by."""
    known: set[str] = set()
    for collection in store._collections:  # noqa: SLF001 - a release tool
        for key, record in store.get_all_with_keys(collection).items():
            known.add(str(key))
            fields = as_dict(record)
            for name in _PRIMARY_KEYS:
                value = fields.get(name)
                if isinstance(value, (str, int)):
                    known.add(str(value))
    return known


def references(store):
    """Every id-shaped field, with the values it carries."""
    found: dict[tuple[str, str], list[str]] = collections.defaultdict(list)

    def walk(node, path, collection):
        if not isinstance(node, dict):
            return
        for key, value in node.items():
            where = f"{path}.{key}"
            if isinstance(value, (str, int)) and _NAMES_SOMETHING.search(key):
                found[(collection, where)].append(str(value))
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, (str, int)) and _NAMES_SOMETHING.search(key):
                        found[(collection, where + "[]")].append(str(item))
                    else:
                        walk(item, where + "[]", collection)
            else:
                walk(value, where, collection)

    for collection in store._collections:  # noqa: SLF001 - a release tool
        for record in store.get_all(collection):
            walk(as_dict(record), "", collection)
    return found


def main():
    """Report every id-shaped field that resolves for some values, not others."""
    logging.disable(logging.CRITICAL)
    warnings.filterwarnings("ignore")
    sys.path.insert(0, str(ROOT / "backend"))
    from fastapi.testclient import TestClient  # noqa: PLC0415
    from main import app  # noqa: PLC0415
    from repository.store import store  # noqa: PLC0415

    with TestClient(app):  # the lifespan seeds the install
        known = addressable(store)
        fields = references(store)
        records = sum(len(store.get_all(c)) for c in store._collections)  # noqa: SLF001

        flags = []
        for (collection, path), values in sorted(fields.items()):
            carried = {v for v in values if v not in ("", "0", "None")}
            resolved = carried & known
            dangling = sorted(carried - known)
            # Nothing resolved: an identifier of something this mock does not
            # model, left opaque on purpose. Everything resolved: a link.
            if f"{collection}{path}" in _OPAQUE:
                continue
            if resolved and dangling:
                flags.append((collection, path, len(dangling), len(carried), dangling[:2]))

    print(f"=== DANGLING REFERENCES === {records} record(s), {len(fields)} id-shaped field(s)")
    for collection, path, missing, carried, examples in flags:
        print(f"  {collection}{path}: {missing} of {carried} name nothing, e.g. {examples}")
    print(f"\n  {len(flags)} field(s) that name records this install does not have")
    return 1 if flags else 0


if __name__ == "__main__":
    sys.exit(main())
