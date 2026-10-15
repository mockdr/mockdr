"""The data models ``tstats`` reads, as ``datamodel/model`` lists them.

Each entry carries the model's JSON definition in ``description`` — the
form a data model's ``.json`` file takes, objects and their fields and
constraints — and its acceleration settings in ``acceleration``, both as
JSON text the way splunkd serves them (REST reference, datamodel/model).
"""
from __future__ import annotations

import json

from utils.splunk.response import build_splunk_entry, build_splunk_envelope
from utils.splunk.spl_datamodels import DATA_MODELS, INHERITED_FIELDS, DataModel

_COLLECTION = "datamodel/model"

#: Where the CIM data models live.
CIM_APP = "Splunk_SA_CIM"

#: Every model here is accelerated, with a summary that covers every event.
_ACCELERATION = {"enabled": True, "earliest_time": "-1y", "cron_schedule": "*/5 * * * *"}


def _definition(model: DataModel) -> dict:
    """The model as its ``.json`` definition describes it."""
    objects = []
    for dataset in model.datasets:
        inherited = [
            {"fieldName": name, "owner": "BaseEvent", "type": "string", "required": False,
             "multivalue": False, "hidden": False, "editable": True, "displayName": name}
            for name in INHERITED_FIELDS
        ]
        own = [
            {"fieldName": name, "owner": dataset.name, "type": "string", "required": False,
             "multivalue": False, "hidden": False, "editable": True, "displayName": name}
            for name in dataset.fields
        ]
        objects.append({
            "objectName": dataset.name,
            "displayName": dataset.name.replace("_", " "),
            "parentName": "BaseEvent",
            "fields": inherited + own,
            "calculations": [],
            "constraints": [{"search": dataset.constraint, "owner": dataset.name}],
            "lineage": dataset.name,
        })
    return {
        "modelName": model.name,
        "displayName": model.display_name,
        "description": f"{model.display_name} (CIM)",
        "objectSummary": {"Event-Based": len(objects), "Transaction-Based": 0,
                          "Search-Based": 0},
        "objects": objects,
        "objectNameList": [o["objectName"] for o in objects],
    }


def _entry(model: DataModel) -> dict:
    return build_splunk_entry(
        model.name,
        {
            "acceleration": json.dumps(_ACCELERATION),
            "description": json.dumps(_definition(model)),
            "displayName": model.display_name,
            "disabled": False,
            "eai:acl": None,
            "eai:appName": CIM_APP,
            "eai:type": "models",
            "eai:userName": "nobody",
        },
        collection=_COLLECTION,
        links=("alternate", "list", "edit", "remove", "move", "_reload", "desc"),
        fields=False,
        acl_extra={"app": CIM_APP, "owner": "nobody", "sharing": "global",
                   "perms": {"read": ["*"], "write": ["admin", "power"]}},
    )


def _envelope(entries: list[dict]) -> dict:
    path = f"/services/{_COLLECTION}"
    return build_splunk_envelope(
        entries, origin=path,
        links={"_reload": f"{path}/_reload", "create": f"{path}/_new"},
    )


def list_models() -> dict:
    """Every data model, by name."""
    return _envelope([_entry(DATA_MODELS[name]) for name in sorted(DATA_MODELS)])


def get_model(name: str) -> dict | None:
    """One data model, or None."""
    model = DATA_MODELS.get(name)
    return _envelope([_entry(model)]) if model else None
