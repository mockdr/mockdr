"""Seed Intune detected applications from installed_apps data."""
from __future__ import annotations

import random

from faker import Faker

from domain.graph.detected_app import GraphDetectedApp
from infrastructure.seeders.graph.graph_shared import graph_uuid
from repository.graph.detected_app_repo import graph_detected_app_repo
from repository.store import store

_COMMON_APPS: list[dict] = [
    {"name": "Microsoft Teams", "publisher": "Microsoft Corporation", "platform": "windows"},
    {"name": "Microsoft Outlook", "publisher": "Microsoft Corporation", "platform": "windows"},
    {"name": "Microsoft Edge", "publisher": "Microsoft Corporation", "platform": "windows"},
    {"name": "Google Chrome", "publisher": "Google LLC", "platform": "windows"},
    {"name": "Slack", "publisher": "Slack Technologies", "platform": "windows"},
    {"name": "Zoom", "publisher": "Zoom Video Communications", "platform": "windows"},
    {"name": "Visual Studio Code", "publisher": "Microsoft Corporation", "platform": "windows"},
    {"name": "Adobe Acrobat Reader", "publisher": "Adobe Inc.", "platform": "windows"},
    {"name": "7-Zip", "publisher": "Igor Pavlov", "platform": "windows"},
    {"name": "VLC media player", "publisher": "VideoLAN", "platform": "windows"},
    {"name": "Python 3.11", "publisher": "Python Software Foundation", "platform": "windows"},
    {"name": "Git", "publisher": "The Git Development Community", "platform": "windows"},
    {"name": "Node.js", "publisher": "OpenJS Foundation", "platform": "windows"},
    {"name": "Firefox", "publisher": "Mozilla", "platform": "windows"},
    {"name": "Notepad++", "publisher": "Don Ho", "platform": "windows"},
    {"name": "WinRAR", "publisher": "win.rar GmbH", "platform": "windows"},
    {"name": "Wireshark", "publisher": "The Wireshark Team", "platform": "windows"},
    {"name": "PuTTY", "publisher": "Simon Tatham", "platform": "windows"},
    {"name": "Xcode", "publisher": "Apple Inc.", "platform": "macOS"},
    {"name": "Homebrew", "publisher": "Homebrew Contributors", "platform": "macOS"},
    {"name": "Docker Desktop", "publisher": "Docker Inc.", "platform": "windows"},
    {"name": "Postman", "publisher": "Postman Inc.", "platform": "windows"},
    {"name": "FileZilla", "publisher": "Tim Kosse", "platform": "windows"},
    {"name": "KeePass", "publisher": "Dominik Reichl", "platform": "windows"},
    {"name": "LibreOffice", "publisher": "The Document Foundation", "platform": "linux"},
    {"name": "Thunderbird", "publisher": "Mozilla", "platform": "linux"},
    {"name": "OpenSSH", "publisher": "OpenBSD Project", "platform": "linux"},
    {"name": "Java Runtime 8", "publisher": "Oracle Corporation", "platform": "windows"},
    {"name": "Flash Player", "publisher": "Adobe Inc.", "platform": "windows"},
    {"name": "Internet Explorer 11", "publisher": "Microsoft Corporation", "platform": "windows"},
]


def seed_graph_detected_apps(fake: Faker) -> None:
    """Populate the detected apps store from common application pool.

    Creates ~30 detected apps with realistic device counts and stores
    the device-to-app mapping in ``graph_detected_app_devices``.
    """
    managed_devices = store.get_all("graph_managed_devices")
    device_ids = [d.id for d in managed_devices]

    versions = ["1.0.0", "2.0.1", "3.5.2", "4.1.0", "10.0.19045", "22.11.3",
                 "116.0.5845.188", "23.0.1", "5.4.3", "8.0.362"]

    for _i, app_spec in enumerate(_COMMON_APPS[:30]):
        app_id = graph_uuid()
        device_count = random.randint(5, len(device_ids))
        assigned_devices = random.sample(device_ids, min(device_count, len(device_ids)))

        app = GraphDetectedApp(
            id=app_id,
            displayName=app_spec["name"],
            version=random.choice(versions),
            deviceCount=len(assigned_devices),
            sizeInByte=random.randint(1_000_000, 500_000_000),
            platform=app_spec["platform"],
            publisher=app_spec["publisher"],
        )
        graph_detected_app_repo.save(app)
        store.save("graph_detected_app_devices", app_id, assigned_devices)
