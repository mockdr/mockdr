"""CrowdStrike Falcon Process Analysis query handlers (read-only).

Generates mock process entities from host data.  Real CS returns process
details from the sensor; we deterministically generate them from the host's
device_id so outputs are reproducible.
"""
from __future__ import annotations

import hashlib
import time

from utils.cs_response import build_cs_entity_response

#: Processes are dated within the last thirty days of this install's clock,
#: so a time-bounded query sees them.
_EPOCH_START = int(time.time()) - 30 * 86400

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
    # `ProcessesapiProcessDetail` declares these members and no others.
    # Five more were answered beside them — `sha256`, `md5`, `user_name`,
    # `user_sid` and `parent_process_id` — none of which Falcon's model
    # carries here, so anything built against them breaks against the real
    # product. The two `*_raw` members are Falcon's sensor-native form of
    # the timestamps, whose format nothing vendored here records; a member
    # a generated SDK declares and a response omits is not drift, an
    # invented one is.
    started = _EPOCH_START + h % (30 * 86400)
    return {
        "process_id": pid,
        "device_id": device_id,
        "command_line": (
            f"C:\\Windows\\System32\\{name}"
            if not name.endswith("3")
            else f"/usr/bin/{name}"
        ),
        "file_name": name,
        # Every process started at the same instant of 2025 before this.
        "start_timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(started)),
        "stop_timestamp": "",
        "process_id_local": str(h % 65535),
    }


def get_process_entities(ids: list[str]) -> dict:
    """Get process entities by process ID list.

    A Falcon process id carries the device it ran on — `pid:<device>:<n>` —
    and this answered a generated process for any id at all, including one
    naming a device this tenant does not have. A client that mistyped an id,
    or carried one over from another install, was handed a process that
    never existed rather than the empty answer Falcon gives for an id it
    cannot resolve.

    Args:
        ids: List of process IDs to look up.

    Returns:
        CS entity response envelope containing process entity dicts.
    """
    from repository.cs_host_repo import cs_host_repo  # noqa: PLC0415

    entities = [
        _mock_process(pid)
        for pid in ids
        if cs_host_repo.get(pid.split(":")[1] if ":" in pid else "")
    ]
    return build_cs_entity_response(entities)
