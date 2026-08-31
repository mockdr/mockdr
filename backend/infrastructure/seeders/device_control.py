"""Device control rules seeder — seeds six device control rule records."""
import random

from faker import Faker

from domain.device_control_rule import DeviceControlRule
from infrastructure.seeders._shared import rand_after, rand_ago
from repository.device_control_repo import device_control_repo
from repository.site_repo import site_repo
from repository.user_repo import user_repo
from utils.id_gen import new_id

#: Vendors a device-control rule names, and the Bluetooth services it can
#: match on. Free-form in the swagger, so these are the ones a console shows.
_MANUFACTURERS: list[str] = [
    "Kingston Technology", "SanDisk", "Logitech", "Hewlett-Packard",
    "Apple Inc.", "Samsung Electronics",
]
_GATT_SERVICES: list[str] = [
    "Device Information", "Battery Service", "Human Interface Device",
    "Generic Access", "Audio Sink",
]

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
            action=(action := random.choice(["Allow", "Block"])),
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
            createdAt=(created := rand_ago(90)),
            updatedAt=rand_after(created),
            siteId=dc_site_id,
            # The device a rule matches, which this record described by class
            # alone: eleven members the swagger declares were unset, so the
            # eleven documented filters over them matched nothing and the
            # console showed a rule with no device behind it. Which members
            # carry a value follows the interface — a USB rule is written
            # against a vendor and product id, a Bluetooth one against its
            # minor classes and services.
            accessPermission=("Read-Only" if action == "Allow" else "Not-Applicable"),
            manufacturerName=random.choice(_MANUFACTURERS),
            deviceName=f"{dc_cls_name} {fake.word().capitalize()}",
            uid=f"{dc_iface}\\{new_id()[:16]}",
            version=f"{random.randint(1, 5)}.{random.randint(0, 9)}",
            **(
                {
                    "vendorId": f"{random.randint(0x0400, 0x0FFF):04x}",
                    "productId": f"{random.randint(0x0100, 0x0FFF):04x}",
                    "deviceId": f"{random.randint(0x0100, 0x0FFF):04x}",
                }
                if dc_iface == "USB"
                else {
                    "minorClasses": [f"{random.randint(1, 63):02d}"],
                    "gattService": random.sample(_GATT_SERVICES, k=2),
                    "deviceInformationServiceInfoKey": "Firmware Revision",
                    "deviceInformationServiceInfoValue": f"{random.randint(1, 9)}.0.{random.randint(0, 20)}",
                }
            ),
        ))
