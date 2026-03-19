from dataclasses import dataclass, field


@dataclass
class DeviceControlRule:
    """Represents a SentinelOne device control rule.

    Field names match the real S1 GET /device-control API response exactly.
    """

    id: str
    ruleName: str
    action: str         # Allow | Block | Readonly
    status: str         # Enabled | Disabled
    deviceClass: str    # USB_STORAGE | BLUETOOTH | PRINTER | CAMERA | AUDIO
    deviceClassName: str
    interface: str      # USB | Bluetooth
    ruleType: str       # usb_device | bluetooth | ...
    createdAt: str
    updatedAt: str

    # Scope
    scope: str | None = None
    scopeName: str | None = None
    scopeId: str | None = None

    # Ordering / audit
    order: int = 0
    editable: bool = True
    creator: str | None = None
    creatorId: str | None = None
    version: str | None = None

    # Device identifiers (USB)
    deviceId: str | None = None
    vendorId: str | None = None
    productId: str | None = None
    uid: str | None = None

    # Bluetooth-specific
    minorClasses: list = field(default_factory=list)
    accessPermission: str | None = None
    bluetoothAddress: str | None = None
    gattService: list = field(default_factory=list)
    manufacturerName: str | None = None
    deviceName: str | None = None
    deviceInformationServiceInfoKey: str | None = None
    deviceInformationServiceInfoValue: str | None = None

    # Internal — used for site-scoped filtering, not returned in responses
    siteId: str = ""
