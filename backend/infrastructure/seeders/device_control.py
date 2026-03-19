"""Device control rules seeder — seeds six device control rule records."""
import random

from faker import Faker

from domain.device_control_rule import DeviceControlRule
from infrastructure.seeders._shared import rand_ago
from repository.device_control_repo import device_control_repo
from repository.site_repo import site_repo
from repository.user_repo import user_repo
from utils.id_gen import new_id

_DC_CLASSES: list[tuple[str, str, str, str]] = [
    ("USB_STORAGE", "USB Storage Device", "USB",       "class"),
    ("BLUETOOTH",   "Bluetooth Device",   "Bluetooth", "bluetoothVersion"),
    ("PRINTER",     "Printer",            "USB",       "class"),
    ("CAMERA",      "Camera",             "USB",       "productId"),
    ("AUDIO",       "Audio Device",       "USB",       "vendorId"),
]


def seed_device_control_rules(
    fake: Faker,
    site_ids: list[str],
    user_ids: list[str],
) -> None:
    """Create six device control rule records and persist them.

    Args:
        fake: Shared :class:`~faker.Faker` instance (seeded externally).
        site_ids: Pool of site IDs for scope assignment.
        user_ids: Pool of user IDs for creator attribution.
    """
    for i in range(6):
        dcid = new_id()
        dc_cls, dc_cls_name, dc_iface, dc_rtype = random.choice(_DC_CLASSES)
        dc_site_id = random.choice(site_ids)
        dc_site = site_repo.get(dc_site_id)
        dc_uid = random.choice(user_ids)
        dc_user = user_repo.get(dc_uid)
        device_control_repo.save(DeviceControlRule(
            id=dcid,
            ruleName=f"DC-Rule-{i + 1:02d}-{fake.word().upper()}",
            action=random.choice(["Allow", "Block"]),
            status=random.choice(["Enabled", "Enabled", "Disabled"]),
            deviceClass=dc_cls,
            deviceClassName=dc_cls_name,
            interface=dc_iface,
            ruleType=dc_rtype,
            order=i + 1,
            editable=True,
            creator=dc_user.fullName if dc_user else "Admin",
            creatorId=dc_uid,
            scope="site",
            scopeName=dc_site.name if dc_site else "",
            scopeId=dc_site_id,
            createdAt=rand_ago(90),
            updatedAt=rand_ago(30),
            siteId=dc_site_id,
        ))
