"""MDE network events seeder -- the connections behind ``DeviceNetworkEvents``.

Each onboarded machine reports a few days of outbound connections, made by
processes that fit its platform and run as the users logged on to it, so the
table joins ``DeviceInfo`` on ``DeviceId`` the way Defender's does. Machines
that are not onboarded report no telemetry, as in Defender.

The seeder draws from its own RNG rather than the shared one: inserting it into
``generate_all`` would otherwise shift the random stream of every seeder that
runs after it.
"""
from __future__ import annotations

import ipaddress
import random
from datetime import UTC, datetime, timedelta

from domain.mde_machine import MdeMachine
from domain.mde_network_event import MdeNetworkEvent
from infrastructure.safe_net import doc_ipv4
from infrastructure.seeders.mde_shared import MDE_TENANT_DOMAIN
from repository.mde_machine_repo import mde_machine_repo
from repository.mde_network_event_repo import mde_network_event_repo

_TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%S.000Z"

#: How far back from a machine's last check-in its events reach.
_WINDOW_DAYS = 7

# (file name, folder path, company, command line, runs as system, destinations)
# A destination is (remote url, remote port); an empty url is a connection to
# a private address, which Defender records without a host name.
_Process = tuple[str, str, str, str, bool, list[tuple[str, int]]]

_WINDOWS_PROCESSES: list[_Process] = [
    ("chrome.exe", r"c:\program files\google\chrome\application\chrome.exe",
     "Google LLC", '"chrome.exe" --type=utility --utility-sub-type=network.mojom.NetworkService',
     False, [("www.google.com", 443), ("accounts.google.com", 443), ("chatgpt.com", 443),
             ("claude.ai", 443), ("github.com", 443)]),
    ("msedge.exe", r"c:\program files (x86)\microsoft\edge\application\msedge.exe",
     "Microsoft Corporation", '"msedge.exe" --type=utility --utility-sub-type=network.mojom.NetworkService',
     False, [("login.microsoftonline.com", 443), ("outlook.office365.com", 443),
             ("www.bing.com", 443), ("copilot.microsoft.com", 443)]),
    ("ms-teams.exe", r"c:\program files\windowsapps\msteams_8wekyb3d8bbwe\ms-teams.exe",
     "Microsoft Corporation", '"ms-teams.exe"',
     False, [("teams.microsoft.com", 443), ("presence.teams.microsoft.com", 443)]),
    ("onedrive.exe", r"c:\program files\microsoft onedrive\onedrive.exe",
     "Microsoft Corporation", '"OneDrive.exe" /background',
     False, [("acmecorp-my.sharepoint.com", 443), ("g.live.com", 443)]),
    ("code.exe", r"c:\program files\microsoft vs code\code.exe",
     "Microsoft Corporation", '"Code.exe" --type=utility',
     False, [("marketplace.visualstudio.com", 443), ("api.github.com", 443),
             ("api.githubcopilot.com", 443)]),
    ("python.exe", r"c:\program files\python312\python.exe",
     "Python Software Foundation", "python.exe app.py",
     False, [("pypi.org", 443), ("files.pythonhosted.org", 443), ("api.openai.com", 443),
             ("api.anthropic.com", 443)]),
    ("node.exe", r"c:\program files\nodejs\node.exe",
     "Node.js", "node.exe index.js",
     False, [("registry.npmjs.org", 443), ("api.openai.com", 443),
             ("generativelanguage.googleapis.com", 443)]),
    ("slack.exe", r"c:\program files\slack\slack.exe",
     "Slack Technologies, LLC", '"slack.exe"',
     False, [("slack.com", 443), ("wss-primary.slack.com", 443)]),
    ("zoom.exe", r"c:\program files\zoom\bin\zoom.exe",
     "Zoom Video Communications, Inc.", '"Zoom.exe"',
     False, [("zoom.us", 443)]),
    ("powershell.exe", r"c:\windows\system32\windowspowershell\v1.0\powershell.exe",
     "Microsoft Corporation", "powershell.exe -NoProfile -ExecutionPolicy Bypass",
     False, [("raw.githubusercontent.com", 443), ("www.powershellgallery.com", 443)]),
    ("svchost.exe", r"c:\windows\system32\svchost.exe",
     "Microsoft Corporation", "svchost.exe -k NetworkService -p",
     True, [("settings-win.data.microsoft.com", 443), ("ctldl.windowsupdate.com", 80),
            ("", 445), ("", 135)]),
    ("mssense.exe", r"c:\program files\windows defender advanced threat protection\mssense.exe",
     "Microsoft Corporation", '"MsSense.exe"',
     True, [("winatp-gw-eus.microsoft.com", 443), ("us-v20.events.data.microsoft.com", 443)]),
]

_MACOS_PROCESSES: list[_Process] = [
    ("Google Chrome", "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
     "", "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
     False, [("www.google.com", 443), ("chatgpt.com", 443), ("claude.ai", 443)]),
    ("Slack", "/Applications/Slack.app/Contents/MacOS/Slack",
     "", "/Applications/Slack.app/Contents/MacOS/Slack",
     False, [("slack.com", 443)]),
    ("python3", "/opt/homebrew/bin/python3",
     "", "python3 agent.py",
     False, [("api.openai.com", 443), ("api.anthropic.com", 443), ("pypi.org", 443)]),
    ("curl", "/usr/bin/curl",
     "", "curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh",
     False, [("raw.githubusercontent.com", 443)]),
    ("wdavdaemon", "/Library/Application Support/Microsoft/Defender/wdavdaemon",
     "", "wdavdaemon",
     True, [("winatp-gw-eus.microsoft.com", 443)]),
]

_LINUX_PROCESSES: list[_Process] = [
    ("python3", "/usr/bin/python3",
     "", "python3 /opt/app/worker.py",
     False, [("api.openai.com", 443), ("api.anthropic.com", 443), ("pypi.org", 443)]),
    ("curl", "/usr/bin/curl",
     "", "curl -s https://api.github.com/repos",
     False, [("api.github.com", 443)]),
    ("http", "/usr/lib/apt/methods/http",
     "", "/usr/lib/apt/methods/http",
     True, [("archive.ubuntu.com", 80), ("security.ubuntu.com", 80)]),
    ("wdavdaemon", "/opt/microsoft/mdatp/sbin/wdavdaemon",
     "", "/opt/microsoft/mdatp/sbin/wdavdaemon",
     True, [("winatp-gw-eus.microsoft.com", 443)]),
    ("ssh", "/usr/bin/ssh",
     "", "ssh -o BatchMode=yes deploy@build-runner",
     False, [("", 22)]),
]

#: Weighted: most connections Defender records succeed.
_ACTION_TYPES: list[str] = ["ConnectionSuccess"] * 8 + ["ConnectionFailed", "ConnectionAttempt"]


def _processes_for(machine: MdeMachine) -> list[_Process]:
    if machine.osPlatform == "macOS":
        return _MACOS_PROCESSES
    if machine.osPlatform == "Linux":
        return _LINUX_PROCESSES
    return _WINDOWS_PROCESSES


def _last_seen(machine: MdeMachine) -> datetime:
    try:
        return datetime.strptime(machine.lastSeen, _TIMESTAMP_FORMAT).replace(tzinfo=UTC)
    except ValueError:
        return datetime.now(UTC)


def _guid(rng: random.Random) -> str:
    h = f"{rng.getrandbits(128):032x}"
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:]}"


def _private_peer(local_ip: str, rng: random.Random) -> str:
    """A neighbour on the machine's own /24, or a 10/8 host if it has none."""
    try:
        network = ipaddress.ip_network(f"{local_ip}/24", strict=False)
    except ValueError:
        return f"10.0.{rng.randint(0, 255)}.{rng.randint(2, 254)}"
    return str(network.network_address + rng.randint(2, 254))


def seed_mde_network_events() -> None:
    """Generate ``DeviceNetworkEvents`` rows for every onboarded MDE machine.

    Must run after ``seed_mde_machines``: each event names a machine, a user
    logged on to it, and an address on its network.
    """
    rng = random.Random("mde_network_events")
    # One address per host and one directory object per user, so the same
    # name resolves the same way on every device and in every event. The
    # addresses are documentation ranges: a seeded row must not say that a
    # real service lives at somebody else's real address.
    host_ips: dict[str, str] = {}
    object_ids: dict[str, str] = {}

    for machine in mde_machine_repo.list_all():
        if machine.onboardingStatus != "Onboarded":
            continue

        processes = _processes_for(machine)
        is_windows = processes is _WINDOWS_PROCESSES
        users = [u["accountName"] for u in machine.loggedOnUsers if u.get("accountName")]
        last_seen = _last_seen(machine)

        for _ in range(rng.randint(8, 16)):
            file_name, folder_path, company, command_line, as_system, destinations = (
                rng.choice(processes)
            )
            remote_url, remote_port = rng.choice(destinations)

            if remote_url:
                remote_ip = host_ips.setdefault(remote_url, doc_ipv4(rng))
                remote_ip_type = "Public"
            else:
                remote_ip = _private_peer(machine.lastIpAddress, rng)
                remote_ip_type = "Private"

            if as_system or not users:
                account_domain = "nt authority" if is_windows else ""
                account_name = "system" if is_windows else "root"
                upn = object_id = ""
            else:
                account_name = rng.choice(users)
                account_domain = "acmecorp" if is_windows else ""
                upn = f"{account_name}@{MDE_TENANT_DOMAIN}"
                object_id = object_ids.setdefault(account_name, _guid(rng))

            when = last_seen - timedelta(seconds=rng.randint(0, _WINDOW_DAYS * 86400))
            mde_network_event_repo.save(MdeNetworkEvent(
                eventId=_guid(rng),
                reportId=rng.randint(1_000, 99_999_999),
                timestamp=when.strftime(_TIMESTAMP_FORMAT),
                machineId=machine.machineId,
                computerDnsName=machine.computerDnsName,
                actionType=rng.choice(_ACTION_TYPES),
                remoteIp=remote_ip,
                remotePort=remote_port,
                remoteUrl=remote_url,
                remoteIpType=remote_ip_type,
                localIp=machine.lastIpAddress,
                localPort=rng.randint(49152, 65535) if is_windows else rng.randint(32768, 60999),
                protocol="Tcp",
                processFileName=file_name,
                processFolderPath=folder_path,
                processCommandLine=command_line,
                processId=rng.randint(400, 65000),
                processCompanyName=company,
                accountDomain=account_domain,
                accountName=account_name,
                accountUpn=upn,
                accountObjectId=object_id,
            ))
