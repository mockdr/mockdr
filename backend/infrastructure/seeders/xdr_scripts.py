"""XDR scripts seeder -- pre-seeds predefined response scripts."""
from __future__ import annotations

from domain.xdr_script import XdrScript
from infrastructure.seeders.xdr_shared import rand_epoch_ms, xdr_id
from repository.xdr_script_repo import xdr_script_repo

_SCRIPTS: list[dict[str, object]] = [
    {
        "name": "Network Scan",
        "description": "Scan for open ports on target endpoint",
        "script_type": "python",
        "is_high_risk": False,
    },
    {
        "name": "Process List",
        "description": "Retrieve running processes with full command line",
        "script_type": "powershell",
        "is_high_risk": False,
    },
    {
        "name": "File Search",
        "description": "Search for files matching pattern on endpoint",
        "script_type": "python",
        "is_high_risk": False,
    },
    {
        "name": "Registry Dump",
        "description": "Export registry hive for forensic analysis",
        "script_type": "powershell",
        "is_high_risk": True,
    },
    {
        "name": "Memory Dump",
        "description": "Capture process memory for analysis",
        "script_type": "python",
        "is_high_risk": True,
    },
    {
        "name": "DNS Cache Dump",
        "description": "Export DNS resolver cache entries",
        "script_type": "shell",
        "is_high_risk": False,
    },
    {
        "name": "Scheduled Tasks List",
        "description": "Enumerate all scheduled tasks",
        "script_type": "powershell",
        "is_high_risk": False,
    },
    {
        "name": "Active Connections",
        "description": "List active network connections and listening ports",
        "script_type": "shell",
        "is_high_risk": False,
    },
    {
        "name": "User Session Info",
        "description": "Get active user sessions and login history",
        "script_type": "python",
        "is_high_risk": False,
    },
    {
        "name": "Kill Process",
        "description": "Terminate a process by PID or name",
        "script_type": "powershell",
        "is_high_risk": True,
    },
]


def seed_xdr_scripts() -> None:
    """Pre-seed ~10 XDR response scripts."""
    for script_def in _SCRIPTS:
        xdr_script_repo.save(XdrScript(
            script_id=xdr_id("SCR"),
            name=script_def["name"],  # type: ignore[arg-type]
            description=script_def["description"],  # type: ignore[arg-type]
            script_type=script_def["script_type"],  # type: ignore[arg-type]
            is_high_risk=script_def["is_high_risk"],  # type: ignore[arg-type]
            modification_date=rand_epoch_ms(180),
            created_by="admin@acmecorp.internal",
        ))
