"""Microsoft Defender for Endpoint Advanced Hunting query handler."""
from __future__ import annotations

from utils.dt import utc_now


def run_query(body: dict) -> dict:
    """Execute an advanced hunting KQL query and return canned results.

    The real MDE Advanced Hunting API accepts a KQL query and returns a
    ``Schema`` + ``Results`` structure.  This mock returns synthetic data
    regardless of the query content.

    Args:
        body: Request body containing ``Query`` (KQL string).

    Returns:
        Advanced hunting response with ``Schema`` and ``Results`` arrays.
    """
    _query = body.get("Query", "")  # accepted but not evaluated
    now = utc_now()

    schema = [
        {"Name": "Timestamp", "Type": "DateTime"},
        {"Name": "DeviceId", "Type": "String"},
        {"Name": "DeviceName", "Type": "String"},
        {"Name": "ActionType", "Type": "String"},
        {"Name": "FileName", "Type": "String"},
        {"Name": "FolderPath", "Type": "String"},
        {"Name": "SHA256", "Type": "String"},
        {"Name": "InitiatingProcessFileName", "Type": "String"},
        {"Name": "InitiatingProcessCommandLine", "Type": "String"},
        {"Name": "AccountName", "Type": "String"},
    ]

    results = [
        {
            "Timestamp": now,
            "DeviceId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            "DeviceName": "ws-fin-001.acmecorp.internal",
            "ActionType": "ProcessCreated",
            "FileName": "powershell.exe",
            "FolderPath": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0",
            "SHA256": "de96a6e69944335375dc1ac238336066889d9ffc7d73628ef4fe1b1b160ab32c",
            "InitiatingProcessFileName": "cmd.exe",
            "InitiatingProcessCommandLine": "cmd.exe /c powershell.exe -ep bypass",
            "AccountName": "jsmith",
        },
        {
            "Timestamp": now,
            "DeviceId": "b2c3d4e5-f6a7-8901-bcde-f12345678901",
            "DeviceName": "srv-dc-01.acmecorp.internal",
            "ActionType": "ConnectionSuccess",
            "FileName": "",
            "FolderPath": "",
            "SHA256": "",
            "InitiatingProcessFileName": "svchost.exe",
            "InitiatingProcessCommandLine": "svchost.exe -k netsvcs",
            "AccountName": "SYSTEM",
        },
        {
            "Timestamp": now,
            "DeviceId": "c3d4e5f6-a7b8-9012-cdef-123456789012",
            "DeviceName": "ws-hr-042.acmecorp.internal",
            "ActionType": "FileCreated",
            "FileName": "report.docx",
            "FolderPath": "C:\\Users\\ajones\\Documents",
            "SHA256": "abc123def456789012345678901234567890123456789012345678901234abcd",
            "InitiatingProcessFileName": "WINWORD.EXE",
            "InitiatingProcessCommandLine": (  # noqa: E501
                "\"C:\\Program Files\\Microsoft Office\\WINWORD.EXE\" /n"
            ),
            "AccountName": "ajones",
        },
    ]

    return {
        "Schema": schema,
        "Results": results,
        "Stats": {
            "ExecutionTime": 0.023,
            "resource_usage": {
                "cache": {"memory": {"hits": 0, "misses": 1, "total": 1}},
                "cpu": {
                    "user": "00:00:00.0156250",
                    "kernel": "00:00:00",
                    "total cpu": "00:00:00.0156250",
                },
                "memory": {"peak_per_node": 1048576},
            },
            "dataset_statistics": [{"table_row_count": len(results), "table_size": 1024}],
        },
    }
