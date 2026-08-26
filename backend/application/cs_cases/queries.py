"""CrowdStrike Falcon Cases (Messaging Center) query handlers (read-only)."""
from __future__ import annotations

from repository.cs_case_repo import cs_case_repo
from utils.cs_fql import apply_fql
from utils.cs_pagination import paginate_cs
from utils.cs_response import build_cs_entity_response, build_cs_id_response
from utils.serde import record_dict


def query_case_ids(
    filter_fql: str | None,
    offset: int,
    limit: int,
    sort: str | None,
) -> dict:
    """Query case IDs matching FQL filter.

    Args:
        filter_fql: FQL filter string, or None for all cases.
        offset:     Zero-based pagination offset.
        limit:      Maximum number of IDs to return.
        sort:       Sort string (``field.asc`` or ``field.desc``).

    Returns:
        CS ID response envelope with case IDs.
    """
    records = [record_dict(c) for c in cs_case_repo.list_all()]
    if filter_fql:
        records = apply_fql(records, filter_fql)
    if sort:
        parts = sort.rsplit(".", 1)
        field_name = parts[0]
        desc = len(parts) > 1 and parts[1].lower() == "desc"
    else:
        field_name, desc = "created_time", True
    records.sort(key=lambda r: r.get(field_name, ""), reverse=desc)
    page, total = paginate_cs(records, offset, limit)
    ids = [r["id"] for r in page]
    return build_cs_id_response(ids, total, offset, limit)


#: What gofalcon's `APIMessageCenterCasesResponse` carries on a case. The
#: stored record has more — `assignee`, `tags`, `fine_score` — and the
#: vendor's document does not, so the answer does not either.
_CASE_FIELDS = (
    "id", "cid", "title", "body", "status", "type", "case_type", "key",
    "created_time", "last_modified_time", "detections", "incidents",
    "hosts", "aids", "ip_addresses", "assigner",
)


def get_case_entities(ids: list[str]) -> dict:
    """Return the cases named by ``ids``.

    `/cases/queries/cases/v1` answered case ids and nothing served the cases
    themselves, so a client could list them and never read one — including
    who a case is assigned by.

    Args:
        ids: Case ids to fetch.

    Returns:
        CS entity response with the case documents.
    """
    resources = []
    for case_id in ids:
        case = cs_case_repo.get(case_id)
        if case is None:
            continue
        record = record_dict(case)
        # gofalcon's case names its kind `case_type`; the stored record
        # keeps the same value under `type`.
        record.setdefault("case_type", record.get("type", ""))
        record.setdefault("key", record.get("id", ""))
        record.setdefault("aids", [])
        resources.append({k: record[k] for k in _CASE_FIELDS if k in record})
    return build_cs_entity_response(resources)
