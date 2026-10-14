
from application.scopes import filter_scope
from domain.device_control_rule import DeviceControlRule
from repository.activity_repo import activity_repo
from repository.device_control_repo import device_control_repo
from utils.dt import utc_now
from utils.id_gen import new_id
from utils.internal_fields import DEVICE_CONTROL_INTERNAL_FIELDS
from utils.serde import record_dict
from utils.strip import strip_fields


def create_rule(data: dict, scope_filter: dict | None = None) -> dict:
    """Create a new device control rule and persist it.

    The swagger requires a ``filter`` beside ``data`` -- the account, site or
    group the rule is created at. It was not read, so every rule was created
    ``global`` whatever scope was asked for; ``data``'s own ``scope`` still
    wins where a client sends one.
    """
    data = _with_filter_scope(data, scope_filter)
    now = utc_now()
    rule = DeviceControlRule(
        id=new_id(),
        ruleName=data.get("ruleName", ""),
        action=data.get("action", "Allow"),
        status=data.get("status", "Enabled"),
        deviceClass=data.get("deviceClass", ""),
        deviceClassName=data.get("deviceClass", ""),
        interface=data.get("interface", "USB"),
        ruleType=data.get("ruleType", "class"),
        scope=data.get("scope", "global"),
        scopeName=data.get("scopeName"),
        scopeId=data.get("scopeId"),
        order=data.get("order", 0),
        editable=True,
        vendorId=data.get("vendorId"),
        productId=data.get("productId"),
        deviceId=data.get("deviceId"),
        uid=data.get("uid"),
        accessPermission=data.get("accessPermission"),
        bluetoothAddress=data.get("bluetoothAddress"),
        manufacturerName=data.get("manufacturerName"),
        deviceName=data.get("deviceName"),
        version=data.get("version"),
        minorClasses=data.get("minorClasses", []),
        gattService=data.get("gattService") or [],
        deviceInformationServiceInfoKey=data.get("deviceInformationServiceInfoKey"),
        deviceInformationServiceInfoValue=data.get("deviceInformationServiceInfoValue"),
        siteId=data.get("siteId", ""),
        createdAt=now,
        updatedAt=now,
    )
    device_control_repo.save(rule)
    activity_repo.create(
        activity_type=400,
        description=f"Device control rule created: {rule.ruleName}",
        site_id=rule.siteId,
    )
    return {"data": strip_fields(record_dict(rule), DEVICE_CONTROL_INTERNAL_FIELDS)}


def update_rule(rule_id: str, data: dict) -> dict | None:
    """Update an existing device control rule. Returns None if not found."""
    rule = device_control_repo.get(rule_id)
    if rule is None:
        return None
    record = record_dict(rule)
    updatable = {
        "ruleName", "action", "status", "deviceClass", "interface", "ruleType",
        "scope", "scopeName", "scopeId", "vendorId", "productId", "deviceId", "uid",
        "accessPermission", "bluetoothAddress", "manufacturerName", "deviceName",
        "version", "minorClasses", "gattService",
        "deviceInformationServiceInfoKey", "deviceInformationServiceInfoValue",
    }
    for key, value in data.items():
        if key in updatable:
            record[key] = value
    if "deviceClass" in data:
        record["deviceClassName"] = data["deviceClass"]
    record["updatedAt"] = utc_now()
    updated = DeviceControlRule(**record)
    device_control_repo.save(updated)
    activity_repo.create(
        activity_type=401,
        description=f"Device control rule updated: {updated.ruleName}",
        site_id=updated.siteId,
    )
    return {"data": strip_fields(record_dict(updated), DEVICE_CONTROL_INTERNAL_FIELDS)}


def delete_rules(ids: list[str]) -> int:
    """Delete rules by IDs. Returns count of successfully deleted rules."""
    affected = 0
    for rule_id in ids:
        rule = device_control_repo.get(rule_id)
        if rule:
            device_control_repo.delete(rule_id)
            activity_repo.create(
                activity_type=402,
                description=f"Device control rule deleted: {rule.ruleName}",
                site_id=rule.siteId,
            )
            affected += 1
    return affected


def _with_filter_scope(data: dict, scope_filter: dict | None) -> dict:
    """*data* with the scope the filter names, where *data* does not name one."""
    scope = filter_scope(scope_filter)
    if scope is None or data.get("scope"):
        return data
    return {
        "scope": scope.level, "scopeId": scope.scope_id or None,
        "scopeName": scope.name, "siteId": scope.site_id, **data,
    }
