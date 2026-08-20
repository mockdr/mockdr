"""Render Elastic Defend endpoints the way the endpoint metadata API does.

The stored dataclass is flat (``agent_id``, ``host_os_name``,
``agent_status``). The real ``/api/endpoint/metadata`` response wraps each
entry in ``metadata`` / ``host_status`` / ``policy_info`` and nests the host
fields as ECS. The two shared no field names at all, so a client written
against the real API read ``undefined`` for every one of them.
"""
from __future__ import annotations

from typing import Any

__all__ = ["to_endpoint_entry"]


def to_endpoint_entry(record: dict[str, Any]) -> dict[str, Any]:
    """Wrap one stored endpoint as a metadata list entry."""
    metadata: dict[str, Any] = {
        "@timestamp": record.get("last_checkin") or record.get("enrolled_at", ""),
        "agent": {
            "id": record.get("agent_id", ""),
            "version": record.get("agent_version", ""),
            "type": "endpoint",
        },
        "elastic": {"agent": {"id": record.get("agent_id", "")}},
        "host": {
            "hostname": record.get("hostname", ""),
            "name": record.get("hostname", ""),
            "id": record.get("agent_id", ""),
            "ip": record.get("host_ip", []),
            "mac": record.get("host_mac", []),
            "architecture": record.get("host_architecture", ""),
            "os": {
                "name": record.get("host_os_name", ""),
                "version": record.get("host_os_version", ""),
                "full": _os_full(record),
                "platform": str(record.get("host_os_name", "")).lower(),
                "family": str(record.get("host_os_name", "")).lower(),
            },
        },
        "Endpoint": {
            "status": "enrolled",
            "policy": {
                "applied": {
                    "id": record.get("policy_id", ""),
                    "status": record.get("policy_status", "success"),
                    "name": record.get("policy_name", ""),
                },
            },
            "state": {"isolation": record.get("isolation_status") == "isolated"},
            "capabilities": ["isolation", "kill_process", "suspend_process",
                             "running_processes", "get_file", "execute"],
        },
        "data_stream": {
            "dataset": "endpoint.metadata",
            "namespace": "default",
            "type": "metrics",
        },
    }

    return {
        "metadata": metadata,
        # host_status is a sibling of metadata, not a field inside it.
        "host_status": _host_status(record),
        "policy_info": {
            "agent": {
                "applied": {"id": record.get("policy_id", ""), "revision": 1},
                "configured": {"id": record.get("policy_id", ""), "revision": 1},
            },
            "endpoint": {"id": record.get("policy_id", ""), "revision": 1},
        },
    }


def _os_full(record: dict[str, Any]) -> str:
    name = record.get("host_os_name", "")
    version = record.get("host_os_version", "")
    return f"{name} {version}".strip()


def _host_status(record: dict[str, Any]) -> str:
    """Map the stored agent status onto the endpoint API's vocabulary."""
    status = str(record.get("agent_status", "")).lower()
    if status in ("online", "healthy"):
        return "healthy"
    if status in ("offline", "unhealthy"):
        return "offline"
    if status == "updating":
        return "updating"
    return "unenrolled" if status == "unenrolled" else "healthy"
