from domain.device_control_rule import DeviceControlRule
from repository.base import Repository


class DeviceControlRepository(Repository[DeviceControlRule]):
    """Repository for DeviceControlRule entities."""

    def __init__(self) -> None:
        """Initialise the repository bound to the device_control_rules collection."""
        super().__init__("device_control_rules")


device_control_repo = DeviceControlRepository()
