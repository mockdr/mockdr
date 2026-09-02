"""Cortex XDR Endpoint command handlers (mutations)."""
from __future__ import annotations

import uuid
from datetime import UTC, datetime

from application import bridge
from domain.xdr_action import XdrAction
from repository.xdr_action_repo import xdr_action_repo
from repository.xdr_endpoint_repo import xdr_endpoint_repo
from utils.xdr_response import build_xdr_reply


def _epoch_ms() -> int:
    """Return current time as epoch milliseconds."""
    return int(datetime.now(UTC).timestamp() * 1000)


def _count(covered: list[str]) -> str:
    """How many endpoints an action covers, in the type the recording has.

    `scripts/gen_xdr_fixtures.py` writes a type-correct blank per field, and
    the recorded `endpoints_count` is `""` — a string, not a number. The
    field was answered blank on every call; it says how many now, without
    changing what a client parses.
    """
    return str(len(covered))


def _create_action(
    endpoint_id: str, action_type: str, endpoint_ids: list[str] | None = None,
) -> XdrAction:
    """Create and persist an XDR action record.

    Args:
        endpoint_id:  Target endpoint identifier.
        action_type:  Action type string.
        endpoint_ids: Every endpoint the action covers, when a `filters`
                      block selected more than one.

    Returns:
        The newly created action.
    """
    action = XdrAction(
        action_id=str(uuid.uuid4()),
        action_type=action_type,
        status="pending",
        endpoint_id=endpoint_id,
        endpoint_ids=list(endpoint_ids or [endpoint_id]),
        creation_time=_epoch_ms(),
    )
    xdr_action_repo.save(action)
    return action


def _names_a_target(request_data: dict) -> bool:
    """Whether a request names anything at all to act on.

    `select_endpoints` answers with every endpoint when it is handed no
    filters, which is right for a listing and catastrophic for a write:
    `update_agent_name` with a body carrying only an alias renamed all sixty
    endpoints and answered `{"reply": true}`. `endpoints_named_by` has this
    guard; the two write paths below did not.
    """
    return bool(
        request_data.get("filters")
        or request_data.get("endpoint_id_list")
        or request_data.get("endpoint_id")
        or request_data.get("agent_id"),
    )


def endpoints_named_by(request_data: dict) -> list[str]:
    """Every endpoint a request names, by id or by filter.

    Cortex names the target of `file_retrieval`, `quarantine` and `scan` with
    a `filters` block and nothing else; `isolate` and `unisolate` take either,
    and the XSOAR integration spells it `agent_id` on `terminate_process`.
    These handlers read `endpoint_id` alone, so the body Cortex documents was
    answered `500 Endpoint  not found` — for the three that have no
    `endpoint_id` at all, every well-formed call failed.

    Args:
        request_data: The `request_data` dict from the POST body.

    Returns:
        The endpoint ids the request names, in listing order.
    """
    from application.xdr_endpoints.queries import select_endpoints  # noqa: PLC0415

    single = str(request_data.get("endpoint_id") or request_data.get("agent_id") or "")
    if single:
        return [single]
    if not (request_data.get("filters") or request_data.get("endpoint_id_list")):
        return []
    return [str(e.endpoint_id) for e in select_endpoints(request_data)]


def isolate_endpoint(endpoint_ids: list[str]) -> dict | None:
    """Isolate every endpoint the request named.

    Args:
        endpoint_ids: The endpoints to isolate.

    Returns:
        XDR reply with the action id and how many endpoints it covers, or
        None when the request named no endpoint this tenant has.
    """
    endpoints = [e for e in (xdr_endpoint_repo.get(i) for i in endpoint_ids) if e]
    if not endpoints:
        return None

    for endpoint in endpoints:
        endpoint.is_isolated = "isolated"
        endpoint.isolated_date = _epoch_ms()
        xdr_endpoint_repo.save(endpoint)
        bridge.xdr_endpoint_changed(endpoint)

    covered = [str(e.endpoint_id) for e in endpoints]
    action = _create_action(covered[0], "isolate", covered)
    return build_xdr_reply({"action_id": action.action_id, "endpoints_count": _count(covered)})


def unisolate_endpoint(endpoint_ids: list[str]) -> dict | None:
    """Release every endpoint the request named from isolation.

    Args:
        endpoint_ids: The endpoints to release.

    Returns:
        XDR reply with the action id and how many endpoints it covers, or
        None when the request named no endpoint this tenant has.
    """
    endpoints = [e for e in (xdr_endpoint_repo.get(i) for i in endpoint_ids) if e]
    if not endpoints:
        return None

    for endpoint in endpoints:
        endpoint.is_isolated = "unisolated"
        endpoint.isolated_date = None
        xdr_endpoint_repo.save(endpoint)
        bridge.xdr_endpoint_changed(endpoint)

    covered = [str(e.endpoint_id) for e in endpoints]
    action = _create_action(covered[0], "unisolate", covered)
    return build_xdr_reply({"action_id": action.action_id, "endpoints_count": _count(covered)})


def scan_endpoint(endpoint_ids: list[str]) -> dict | None:
    """Start a scan on every endpoint the request named.

    Args:
        endpoint_ids: The endpoints to scan.

    Returns:
        XDR reply with the action id and how many endpoints it covers, or
        None when the request named no endpoint this tenant has.
    """
    endpoints = [e for e in (xdr_endpoint_repo.get(i) for i in endpoint_ids) if e]
    if not endpoints:
        return None

    for endpoint in endpoints:
        endpoint.scan_status = "in_progress"
        xdr_endpoint_repo.save(endpoint)
        bridge.xdr_endpoint_changed(endpoint)

    covered = [str(e.endpoint_id) for e in endpoints]
    action = _create_action(covered[0], "scan", covered)
    return build_xdr_reply({"action_id": action.action_id, "endpoints_count": _count(covered)})


def delete_endpoints(endpoint_ids: list[str]) -> dict:
    """Delete one or more endpoints.

    Args:
        endpoint_ids: List of endpoint identifiers to delete.

    Returns:
        XDR reply confirming success.
    """
    for eid in endpoint_ids:
        xdr_endpoint_repo.delete(eid)
    return build_xdr_reply(True)


def update_agent_name(request_data: dict, alias: str) -> dict | None:
    """Set the alias of every endpoint the request's ``filters`` select.

    Cortex names the target of this call with a ``filters`` block, the same
    one the read routes take — not with an ``endpoint_id``. Reading an id
    that the documented body never carries meant the call answered 500
    ``Endpoint  not found`` to every well-formed request.

    Args:
        request_data: The ``request_data`` dict from the POST body.
        alias: New alias string.

    Returns:
        XDR reply confirming success, or None if the filters select nothing.
    """
    from application.xdr_endpoints.queries import select_endpoints

    if not _names_a_target(request_data):
        return None
    matched = select_endpoints(request_data)
    if not matched:
        return None

    for endpoint in matched:
        endpoint.alias = alias
        xdr_endpoint_repo.save(endpoint)
    return build_xdr_reply(True)


def terminate_process(endpoint_ids: list[str], params: dict) -> dict | None:
    """Terminate a process on every endpoint the request named.

    The connector's recorded reply carries `group_action_id`, and the request
    names its target the way its siblings do — which this read as
    `endpoint_id` alone.

    Args:
        endpoint_ids: The endpoints to act on.
        params: Dict with process details (``pid``, ``process_name``).

    Returns:
        XDR reply with the action id and how many endpoints it covers, or
        None when the request named no endpoint this tenant has.
    """
    covered = [str(e.endpoint_id) for e in
               (xdr_endpoint_repo.get(i) for i in endpoint_ids) if e]
    if not covered:
        return None

    action = _create_action(covered[0], "terminate_process", covered)
    action.result = {"pid": params.get("pid"), "process_name": params.get("process_name")}
    xdr_action_repo.save(action)
    return build_xdr_reply({
        "action_id": action.action_id,
        "group_action_id": action.action_id,
        "endpoints_count": _count(covered),
    })


def quarantine_file(endpoint_ids: list[str], params: dict) -> dict | None:
    """Quarantine a file on every endpoint the request named.

    Args:
        endpoint_ids: The endpoints to act on.
        params: Dict with file details (``file_path``, ``file_hash``).

    Returns:
        XDR reply with the action id and how many endpoints it covers, or
        None when the request named no endpoint this tenant has.
    """
    covered = [str(e.endpoint_id) for e in
               (xdr_endpoint_repo.get(i) for i in endpoint_ids) if e]
    if not covered:
        return None

    action = _create_action(covered[0], "quarantine", covered)
    action.result = {"file_path": params.get("file_path"), "file_hash": params.get("file_hash")}
    xdr_action_repo.save(action)
    return build_xdr_reply({"action_id": action.action_id, "endpoints_count": _count(covered)})


def restore_file(endpoint_ids: list[str], params: dict) -> dict | None:
    """Restore a quarantined file on every endpoint the request named.

    Args:
        endpoint_ids: The endpoints to act on.
        params: Dict with file details (``file_hash``).

    Returns:
        XDR reply with the action id and how many endpoints it covers, or
        None when the request named no endpoint this tenant has.
    """
    covered = [str(e.endpoint_id) for e in
               (xdr_endpoint_repo.get(i) for i in endpoint_ids) if e]
    if not covered:
        return None

    action = _create_action(covered[0], "restore", covered)
    action.result = {"file_hash": params.get("file_hash")}
    xdr_action_repo.save(action)
    return build_xdr_reply({"action_id": action.action_id, "endpoints_count": _count(covered)})


def file_retrieval(endpoint_ids: list[str], params: dict) -> dict | None:
    """Retrieve files from every endpoint the request named.

    Cortex names the files per platform — `files.windows`, `files.linux`,
    `files.macos` — and names the endpoints with a `filters` block.

    Args:
        endpoint_ids: The endpoints to act on.
        params: The request data, carrying `files`.

    Returns:
        XDR reply with the action id and how many endpoints it covers, or
        None when the request named no endpoint this tenant has.
    """
    covered = [str(e.endpoint_id) for e in
               (xdr_endpoint_repo.get(i) for i in endpoint_ids) if e]
    if not covered:
        return None

    action = _create_action(covered[0], "file_retrieval", covered)
    action.result = {"files": params.get("files") or {}}
    xdr_action_repo.save(action)
    return build_xdr_reply({"action_id": action.action_id, "endpoints_count": _count(covered)})


def tag_endpoints(body: dict, *, assign: bool) -> dict:
    """Add or remove one tag on every endpoint the body names.

    Cortex's client sends the endpoints in ``context.lcaas_id`` and narrows
    them with ``request_data.filters``; either may be absent, and what both
    name is intersected. The reply is empty, as the vendor's own sample is.

    Args:
        body: The whole POST body, ``context`` included.
        assign: ``True`` to add the tag, ``False`` to remove it.

    Returns:
        XDR reply with an empty body.
    """
    from application.xdr_endpoints.queries import select_endpoints

    request_data = body.get("request_data") or {}
    lcaas = (body.get("context") or {}).get("lcaas_id")
    if not _names_a_target(request_data) and not lcaas:
        return build_xdr_reply({})
    matched = select_endpoints(request_data)
    if lcaas:
        matched = [e for e in matched if e.endpoint_id in lcaas]

    tag = str(request_data.get("tag") or "")
    for endpoint in matched:
        tags = list(endpoint.endpoint_tags)
        if assign and tag and tag not in tags:
            tags.append(tag)
        elif not assign and tag in tags:
            tags.remove(tag)
        endpoint.endpoint_tags = tags
        xdr_endpoint_repo.save(endpoint)
    return build_xdr_reply({})
