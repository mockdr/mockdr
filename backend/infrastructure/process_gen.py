"""Runtime process-list generator for mock agent endpoints.

Extracted from ``seed.py`` so that ``application.agents.queries`` can import
it at module level without creating a circular dependency on the full seeder.
"""
import random

from faker import Faker

from infrastructure.seeders._shared import rand_ago

_fake = Faker()

PROCESS_CATALOG: list[tuple[str, str]] = [
    ("cmd.exe",        "C:\\Windows\\System32\\cmd.exe"),
    ("powershell.exe", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"),
    ("python.exe",     "C:\\Python312\\python.exe"),
    ("chrome.exe",     "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"),
    ("svchost.exe",    "C:\\Windows\\System32\\svchost.exe"),
    ("explorer.exe",   "C:\\Windows\\explorer.exe"),
    ("bash",           "/bin/bash"),
    ("python3",        "/usr/bin/python3"),
    ("nginx",          "/usr/sbin/nginx"),
    ("sshd",           "/usr/sbin/sshd"),
]


def generate_processes_for_agent(agent_id: str) -> list[dict]:
    """Return a randomised list of running processes for the given agent.

    Args:
        agent_id: The agent to associate each process entry with.

    Returns:
        List of process dicts matching the real S1 ``/agents/{id}/processes``
        response shape.
    """
    return [
        {
            "pid":         random.randint(100, 65535),
            "parentPid":   random.randint(1, 1000),
            "name":        proc_name,
            "path":        proc_path,
            "user":        _fake.user_name(),
            "startTime":   rand_ago(1),
            "cpuUsage":    random.randint(0, 15),
            "memoryUsage": random.randint(10, 512),
            "agentId":     agent_id,
        }
        for proc_name, proc_path in random.sample(
            PROCESS_CATALOG, random.randint(4, len(PROCESS_CATALOG))
        )
    ]
