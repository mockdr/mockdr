"""Elastic Security API response envelope builders.

Elastic Security uses two distinct response formats:

* **Elasticsearch _search** — ``hits`` envelope with ``took``, ``_shards``, etc.
* **Kibana list** — simple ``page``/``per_page``/``total``/``data`` envelope.
"""
from __future__ import annotations


def build_es_search_response(
    hits: list[dict],
    total: int,
    took: int = 5,
    *,
    sorted_search: bool = False,
) -> dict:
    """Build an Elasticsearch ``_search`` response envelope.

    Args:
        hits:          List of hit documents to include.
        total:         Total number of matching documents.
        took:          Simulated query time in milliseconds.
        sorted_search: Whether the request carried a ``sort``. Elasticsearch
                       does not score a sorted search, so ``max_score`` is
                       null there — as is each hit's ``_score``.

    Returns:
        Complete Elasticsearch search response envelope.
    """
    return {
        "took": took,
        "timed_out": False,
        "_shards": {"total": 1, "successful": 1, "skipped": 0, "failed": 0},
        "hits": {
            "total": {"value": total, "relation": "eq"},
            "max_score": None if (sorted_search or not hits) else 1.0,
            "hits": hits,
        },
    }


def build_kibana_list_response(
    data: list,
    page: int,
    per_page: int,
    total: int,
) -> dict:
    """Build a Kibana paginated list response.

    Args:
        data:     Page of resource objects to include.
        page:     Current page number (1-based).
        per_page: Number of items per page.
        total:    Total number of matching resources.

    Returns:
        Kibana list response envelope.
    """
    return {"page": page, "per_page": per_page, "total": total, "data": data}


def build_kibana_rules_response(
    data: list,
    page: int,
    per_page: int,
    total: int,
) -> dict:
    """Build the Security Solution ``rules/_find`` response.

    Note the asymmetry, which is real: the *request* parameter is ``per_page``
    but the *response* key is ``perPage``. Kibana's generated schema
    (``find_rules_route.gen.ts``) declares ``{page, perPage, total, data}``,
    so a client reading ``perPage`` off this envelope found nothing.
    """
    return {"page": page, "perPage": per_page, "total": total, "data": data}


def build_kibana_cases_response(
    cases: list,
    page: int,
    per_page: int,
    total: int,
    status_counts: dict[str, int] | None = None,
) -> dict:
    """Build the Cases ``_find`` response.

    ``CasesFindResponseRt`` names the collection ``cases``, not ``data``, and
    carries the per-status counts alongside it.
    """
    counts = status_counts or {}
    return {
        "cases": cases,
        "page": page,
        "per_page": per_page,
        "total": total,
        "count_open_cases": counts.get("open", 0),
        "count_in_progress_cases": counts.get("in-progress", 0),
        "count_closed_cases": counts.get("closed", 0),
    }


def build_kibana_endpoint_response(
    data: list,
    page: int,
    page_size: int,
    total: int,
    sort_field: str = "enrolled_at",
    sort_direction: str = "desc",
) -> dict:
    """Build the endpoint metadata list response.

    The real endpoint returns ``pageSize``, not ``per_page``, and it echoes
    the sort it applied — ``enrolled_at`` descending unless the caller asked
    for another. mockdr left both members out, so a client reading back what
    it had asked for found nothing there.
    """
    return {
        "data": data,
        "total": total,
        "page": page,
        "pageSize": page_size,
        "sortField": sort_field,
        "sortDirection": sort_direction,
    }


def build_es_error_response(
    status_code: int,
    error: str,
    reason: str,
    detail: dict | None = None,
) -> dict:
    """Build an Elasticsearch error response.

    Args:
        status_code: HTTP status code.
        error:       Error type string (e.g. ``security_exception``).
        reason:      Human-readable error description.
        detail:      Members this error carries beside its reason — a parse
                     failure names the ``line`` and ``col`` it stopped at,
                     and carries them in the root cause as well.

    Returns:
        Elasticsearch error response envelope.
    """
    cause = {"type": error, "reason": reason, **(detail or {})}
    return {
        "error": {
            "root_cause": [dict(cause)],
            **cause,
        },
        "status": status_code,
    }


def build_es_document_missing(index: str, index_uuid: str, doc_id: str) -> dict:
    """The 404 an update names a missing document with.

    It reads like a shard failure — the shard is what looked for the
    document — and carries the index, its uuid and the shard number.
    """
    cause = {
        "type": "document_missing_exception",
        "reason": f"[{doc_id}]: document missing",
        "index_uuid": index_uuid,
        "shard": "0",
        "index": index,
    }
    return {"error": {"root_cause": [dict(cause)], **cause}, "status": 404}


def build_es_index_not_found(index: str) -> dict:
    """Build Elasticsearch's ``index_not_found_exception`` body.

    The exception carries the index name as exception metadata, which renders
    as extra ``index`` and ``index_uuid`` members beside ``reason`` — a client
    that reads them to name the missing index finds nothing without them.
    ``_na_`` is what Elasticsearch reports for an index that never existed.

    Args:
        index: The index name that could not be resolved.

    Returns:
        Elasticsearch 404 error envelope.
    """
    # `resource.type` and `resource.id` are literal dotted keys, not a nested
    # object: Elasticsearch renders exception metadata flat, and a client that
    # reads `error["resource.id"]` to name the missing index finds nothing if
    # they are nested or absent. Measured against Elasticsearch 8.15.0.
    detail = {
        "type": "index_not_found_exception",
        "reason": f"no such index [{index}]",
        "resource.type": "index_or_alias",
        "resource.id": index,
        "index_uuid": "_na_",
        "index": index,
    }
    return {
        "error": {"root_cause": [dict(detail)], **detail},
        "status": 404,
    }


def build_es_invalid_index_name(index: str) -> dict:
    """Build ``invalid_index_name_exception`` for a name Elasticsearch refuses.

    An index name may not start with an underscore, and Elasticsearch says so
    with a 400 rather than reporting the index as missing (measured on 8.15).
    """
    detail = {
        "type": "invalid_index_name_exception",
        "reason": f"Invalid index name [{index}], must not start with '_'.",
        "index_uuid": "_na_",
        "index": index,
    }
    return {"error": {"root_cause": [dict(detail)], **detail}, "status": 400}


def build_es_resource_exists(index: str, uuid: str) -> dict:
    """Build ``resource_already_exists_exception`` for a repeated create.

    The reason quotes the index and its uuid together, and both appear as
    members beside it — measured on 8.15.
    """
    detail = {
        "type": "resource_already_exists_exception",
        "reason": f"index [{index}/{uuid}] already exists",
        "index_uuid": uuid,
        "index": index,
    }
    return {"error": {"root_cause": [dict(detail)], **detail}, "status": 400}


#: Challenges Elasticsearch offers on a 401, ordered by its own scheme priority.
#: Measured against Elasticsearch 8.15.0 with default security: Basic first,
#: then ApiKey, and no Bearer — the token service only advertises itself when
#: it is enabled, which on a stock install without TLS it is not.
ES_WWW_AUTHENTICATE: tuple[str, ...] = (
    'Basic realm="security", charset="UTF-8"',
    "ApiKey",
)


def build_es_auth_error(status_code: int, reason: str) -> dict:
    """Build an Elasticsearch ``security_exception`` body.

    Authentication failures carry the ``WWW-Authenticate`` challenges in the
    body under ``header`` as well as in the real HTTP headers, and they appear
    in both the top-level error and each ``root_cause`` entry.

    Args:
        status_code: 401 or 403.
        reason:      Human-readable error description.

    Returns:
        Elasticsearch error envelope with the challenge headers attached.
    """
    detail: dict = {"type": "security_exception", "reason": reason}
    if status_code == 401:
        detail["header"] = {"WWW-Authenticate": list(ES_WWW_AUTHENTICATE)}
    return {
        "error": {"root_cause": [dict(detail)], **detail},
        "status": status_code,
    }



#: Boom's status-title table, which is what lands in Kibana's ``error`` field.
_KBN_TITLES: dict[int, str] = {
    400: "Bad Request",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not Found",
    405: "Method Not Allowed",
    409: "Conflict",
    # Hapi's answer to a media type it has no parser for, title and message
    # both (measured on 8.15).
    415: "Unsupported Media Type",
    429: "Too Many Requests",
    500: "Internal Server Error",
}


def build_kbn_error_response(status_code: int, message: str) -> dict:
    """Build a Kibana error response.

    Kibana does not share Elasticsearch's envelope, even though the two ship
    together: it serves errors through Hapi/Boom, so ``error`` is a status
    *title string* and the status travels as ``statusCode`` inside the body.
    Elasticsearch's ``error`` is an object and its status is a top-level
    ``status``. A client switching between the two cannot use one parser.

    Args:
        status_code: HTTP status code.
        message:     Human-readable error description.

    Returns:
        Kibana (Boom) error response envelope.
    """
    return {
        "statusCode": status_code,
        "error": _KBN_TITLES.get(status_code, "Internal Server Error"),
        "message": message,
    }


# Security Solution routes — detection_engine, exception_lists, endpoint — do
# not use the platform's Boom envelope.
_SECURITY_SOLUTION_PREFIXES = (
    "/kibana/api/detection_engine",
    "/kibana/api/exception_lists",
    "/kibana/api/exceptions",
    "/kibana/api/endpoint",
)


def build_security_solution_error(status_code: int, message: str) -> dict:
    """Build a Security Solution error response.

    Kibana has *two* error envelopes, not one. Platform routes answer through
    Hapi/Boom with ``{statusCode, error, message}``; the Security Solution's
    own routes answer with ``{message, status_code}``. Serving Boom everywhere
    meant a detection-engine client read ``undefined`` for the status it was
    told to branch on.
    """
    return {"message": message, "status_code": status_code}


def is_security_solution_path(path: str) -> bool:
    """Whether *path* belongs to a Security Solution route."""
    return path.startswith(_SECURITY_SOLUTION_PREFIXES)


def build_kibana_error(path: str, status_code: int, message: str) -> dict:
    """Build the error envelope the route at *path* actually uses."""
    if is_security_solution_path(path):
        return build_security_solution_error(status_code, message)
    return build_kbn_error_response(status_code, message)
