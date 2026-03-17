"""Domain dataclass for CrowdStrike Falcon Host (device) entities."""
from dataclasses import dataclass, field


@dataclass
class CsHost:
    """A CrowdStrike Falcon managed host/device.

    Field names match the real CrowdStrike Falcon API exactly (snake_case).
    The ``id`` property aliases ``device_id`` so the generic Repository[T]
    pattern works unchanged.
    """

    # ── Identity ──────────────────────────────────────────────────────────────
    device_id: str
    cid: str
    hostname: str

    # ── Network ───────────────────────────────────────────────────────────────
    local_ip: str
    external_ip: str
    mac_address: str
    connection_ip: str = ""

    # ── OS ────────────────────────────────────────────────────────────────────
    os_version: str = ""
    os_build: str = ""
    platform_name: str = "Windows"
    platform_id: str = "0"
    kernel_version: str = ""
    major_version: str = ""
    minor_version: str = ""
    build_number: str = ""

    # ── Hardware ──────────────────────────────────────────────────────────────
    system_manufacturer: str = ""
    system_product_name: str = ""
    bios_manufacturer: str = ""
    bios_version: str = ""
    serial_number: str = ""
    chassis_type: str = ""
    chassis_type_desc: str = ""
    pointer_size: str = "8"
    cpu_signature: str = ""

    # ── Agent ─────────────────────────────────────────────────────────────────
    agent_version: str = ""
    agent_load_flags: str = "0"
    config_id_base: str = ""
    config_id_build: str = ""
    config_id_platform: str = ""
    reduced_functionality_mode: str = "no"
    provision_status: str = "Provisioned"

    # ── Status / Timestamps ───────────────────────────────────────────────────
    status: str = "normal"
    first_seen: str = ""
    last_seen: str = ""
    modified_timestamp: str = ""
    slow_changing_modified_timestamp: str = ""

    # ── Domain / OU ───────────────────────────────────────────────────────────
    site_name: str = ""
    machine_domain: str = ""
    ou: list[str] = field(default_factory=list)
    email: str = ""

    # ── Product ───────────────────────────────────────────────────────────────
    product_type_desc: str = "Workstation"
    service_provider: str = ""
    service_provider_account_id: str = ""
    detection_suppression_status: str = "active"

    # ── Groups / Tags / Policies ──────────────────────────────────────────────
    tags: list[str] = field(default_factory=list)
    groups: list[str] = field(default_factory=list)
    policies: list[dict] = field(default_factory=list)
    device_policies: dict = field(default_factory=dict)

    # ── Meta ──────────────────────────────────────────────────────────────────
    meta: dict = field(default_factory=lambda: {"version": "1"})

    @property
    def id(self) -> str:
        """Return the primary identifier expected by ``Repository[T]``."""
        return self.device_id
