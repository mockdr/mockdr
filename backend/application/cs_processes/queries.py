"""CrowdStrike Falcon Process Analysis query handlers (read-only).

Generates mock process entities from host data.  Real CS returns process
details from the sensor; we deterministically generate them from the host's
device_id so outputs are reproducible.
"""
from __future__ import annotations

import hashlib

from utils.cs_response import build_cs_entity_response

_PROCESS_NAMES: list[str] = [
    "svchost.exe", "lsass.exe", "csrss.exe", "explorer.exe",
    "chrome.exe", "powershell.exe", "cmd.exe", "python3",
    "bash", "conhost.exe", "taskhostw.exe", "RuntimeBroker.exe",
]


def _mock_process(pid: str) -> dict:
    """Generate a deterministic mock process entity from a process ID.

    Args:
        pid: CrowdStrike process ID (``pid:<hex>:<decimal>``).

    Returns:
        Process entity dict matching the real CS API shape.
    """
    h = int(hashlib.sha256(pid.encode()).hexdigest(), 16)
    name = _PROCESS_NAMES[h % len(_PROCESS_NAMES)]
    # Extract device_id from pid format pid:<device_id>:<process_num>
    parts = pid.split(":")
    device_id = parts[1] if len(parts) > 1 else ""
    return {
        "process_id": pid,
        "device_id": device_id,
        "command_line": (
            f"C:\\Windows\\System32\\{name}"
            if not name.endswith("3")
            else f"/usr/bin/{name}"
        ),
        "file_name": name,
        "start_timestamp": "2025-01-15T10:30:00Z",
        "stop_timestamp": "",
        "parent_process_id": f"pid:{device_id}:1" if device_id else "",
        "process_id_local": str(h % 65535),
        "user_name": "ACMECORP\\admin" if h % 2 == 0 else "SYSTEM",
        "user_sid": f"S-1-5-21-{h % 999999999}-{(h >> 32) % 999999}-500",
        "sha256": hashlib.sha256(name.encode()).hexdigest(),
        "md5": hashlib.md5(name.encode()).hexdigest(),  # noqa: S324
    }


def get_process_entities(ids: list[str]) -> dict:
    """Get process entities by process ID list.

    Generates deterministic mock process records for each requested ID.

    Args:
        ids: List of process IDs to look up.

    Returns:
        CS entity response envelope containing process entity dicts.
    """
    entities = [_mock_process(pid) for pid in ids]
    return build_cs_entity_response(entities)
