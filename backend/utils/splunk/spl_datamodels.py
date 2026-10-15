"""The CIM data models ``tstats`` reads, and how mockdr's events fill them.

Splunk Enterprise Security's correlation searches are written against the
Common Information Model rather than against any one product: `| tstats
count from datamodel=Endpoint.Processes where Processes.process_name=cmd.exe
by Processes.dest`. A data model is a set of datasets; each dataset admits
the events its constraint selects — in the CIM add-on, a pair of tags such
as ``tag=process tag=report`` that the vendor add-ons' event types attach —
and exposes them under CIM field names, which a search writes prefixed with
the dataset's name (CIM 6.x reference, "Endpoint", "Malware", …).

mockdr has no event types or tags of its own to run that machinery on, so
the registry below states its outcome directly: which index and sourcetype
feed which dataset, and how each CIM field is read off the event the EDR
bridge indexed. Two ways in:

* A **feed** maps one of the bridge's sourcetypes into a dataset, field by
  field, the way the vendor's add-on maps it (the SentinelOne App, the
  CrowdStrike Event Streams add-on, the Microsoft Security add-on, the Palo
  Alto Networks add-on, Elastic's integration).
* An event that carries the dataset's CIM **tags** itself — a ``tag`` field
  holding, say, ``network`` and ``communicate`` — joins the dataset with its
  fields read as they are named. That is the door for events a test sends
  through HEC already shaped as CIM.

Every dataset also carries the fields every CIM event inherits, unprefixed:
``_time``, ``host``, ``source``, ``sourcetype`` (and ``index``).
"""
from __future__ import annotations

import ntpath
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from utils.splunk.spl_functions import values_of

Row = dict[str, Any]
#: A CIM field is read either from a field of the event, by name, or
#: computed from the whole event.
FieldSource = str | Callable[[Row], Any]

#: The fields every dataset inherits from the event, written unprefixed.
INHERITED_FIELDS = ("_time", "host", "source", "sourcetype", "index")


@dataclass(frozen=True)
class Feed:
    """One sourcetype's way into a dataset."""

    index: str
    sourcetype: str
    fields: Mapping[str, FieldSource]
    #: A further condition on the event, where only some of a sourcetype's
    #: events belong (an alert whose category is malware, say).
    where: Callable[[Row], bool] | None = None

    def admits(self, event: Row) -> bool:
        """Whether *event* is one this feed maps."""
        if str(event.get("index", "")).lower() != self.index.lower():
            return False
        if str(event.get("sourcetype", "")).lower() != self.sourcetype.lower():
            return False
        return self.where is None or bool(self.where(event))


@dataclass(frozen=True)
class Dataset:
    """A root event dataset of a data model."""

    name: str
    #: The CIM constraint's tags; an event carrying all of them is admitted.
    tags: tuple[str, ...]
    #: The dataset's CIM fields, without the prefix.
    fields: tuple[str, ...]
    feeds: tuple[Feed, ...] = ()

    @property
    def constraint(self) -> str:
        """The constraint as the CIM add-on writes it."""
        return " ".join(f"tag={tag}" for tag in self.tags)

    def rows(self, events: list[Row]) -> list[Row]:
        """The events this dataset admits, as CIM rows."""
        out: list[Row] = []
        for event in events:
            mapped = self._map(event)
            if mapped is not None:
                out.append(mapped)
        return out

    def _map(self, event: Row) -> Row | None:
        feed = next((f for f in self.feeds if f.admits(event)), None)
        if feed is None and not self._tagged(event):
            return None
        row: Row = {name: event[name] for name in INHERITED_FIELDS if name in event}
        for name in self.fields:
            source: FieldSource | None = feed.fields.get(name) if feed else name
            if source is None:
                continue
            value = source(event) if callable(source) else event.get(source)
            if value is None or value == "" or value == []:
                continue
            row[f"{self.name}.{name}"] = value
        return row

    def _tagged(self, event: Row) -> bool:
        held = {str(v).lower() for v in values_of(event.get("tag"))}
        return bool(self.tags) and all(tag in held for tag in self.tags)


@dataclass(frozen=True)
class DataModel:
    """A data model: a name and its root datasets."""

    name: str
    display_name: str
    datasets: tuple[Dataset, ...] = field(default_factory=tuple)

    def dataset(self, name: str) -> Dataset | None:
        """A root dataset by name, as a search writes it (case matters)."""
        return next((d for d in self.datasets if d.name == name), None)


# ── How the bridge's events read as CIM ─────────────────────────────────────


def _lower(name: str) -> Callable[[Row], Any]:
    def read(event: Row) -> Any:
        value = event.get(name)
        return str(value).lower() if value not in (None, "") else None
    return read


def _basename(name: str) -> Callable[[Row], Any]:
    def read(event: Row) -> Any:
        value = event.get(name)
        return ntpath.basename(str(value)) if value not in (None, "") else None
    return read


def _constant(value: str) -> Callable[[Row], Any]:
    return lambda _event: value


def _s1_action(event: Row) -> str:
    """``blocked`` for a threat the agent mitigated, ``allowed`` otherwise."""
    status = str(event.get("threatInfo.mitigationStatus", "")).lower()
    return "blocked" if status in ("mitigated", "marked_as_benign") else "allowed"


def _s1_severity(event: Row) -> str:
    confidence = str(event.get("threatInfo.confidenceLevel", "")).lower()
    return {"malicious": "critical", "suspicious": "high"}.get(confidence, "medium")


_CS_BLOCKING_FLAGS = (
    "KillProcess", "KillSubProcess", "QuarantineFile", "OperationBlocked",
    "ProcessBlocked", "KillParent",
)


def _cs_action(event: Row) -> str:
    flags = event.get("event.PatternDispositionFlags") or {}
    blocked = isinstance(flags, dict) and any(flags.get(f) for f in _CS_BLOCKING_FLAGS)
    return "blocked" if blocked else "allowed"


def _cs_detection(event: Row) -> bool:
    return str(event.get("metadata.eventType", "")).endswith("DetectionSummaryEvent")


def _xdr_action(event: Row) -> str:
    return "blocked" if str(event.get("action", "")).lower() == "prevented" else "allowed"


def _xdr_malware(event: Row) -> bool:
    return str(event.get("category", "")).lower() == "malware"


_S1 = ("sentinelone", "sentinelone:channel:threats")
_CS = ("crowdstrike", "CrowdStrike:Event:Streams:JSON")
_MDE = ("msdefender", "ms:defender:atp:alerts")
_ELASTIC = ("elastic_security", "elastic:security:alerts")
_XDR = ("cortex_xdr", "pan:xdr:alert")

_S1_VENDOR = _constant("SentinelOne Singularity")
_CS_VENDOR = _constant("CrowdStrike Falcon")
_MDE_VENDOR = _constant("Microsoft Defender for Endpoint")
_ELASTIC_VENDOR = _constant("Elastic Security")
_XDR_VENDOR = _constant("Palo Alto Networks Cortex XDR")

PROCESSES = Dataset(
    name="Processes",
    tags=("process", "report"),
    fields=(
        "action", "dest", "user", "process", "process_name", "process_path",
        "process_id", "process_hash", "parent_process", "parent_process_name",
        "parent_process_id", "vendor_product",
    ),
    feeds=(
        Feed(*_CS, where=_cs_detection, fields={
            "action": _cs_action,
            "dest": "event.Hostname",
            "user": "event.UserName",
            "process": "event.CommandLine",
            "process_name": "event.FileName",
            "process_path": "event.FilePath",
            "process_id": "event.ProcessId",
            "process_hash": "event.SHA256String",
            "parent_process": "event.ParentCommandLine",
            "parent_process_name": "event.ParentImageFileName",
            "parent_process_id": "event.ParentProcessId",
            "vendor_product": _CS_VENDOR,
        }),
        Feed(*_S1, fields={
            "action": _s1_action,
            "dest": "agentRealtimeInfo.agentComputerName",
            "user": "threatInfo.processUser",
            "process": "threatInfo.maliciousProcessArguments",
            "process_name": "threatInfo.originatorProcess",
            "vendor_product": _S1_VENDOR,
        }),
        Feed(*_ELASTIC, fields={
            "dest": "hostname",
            "user": "user_name",
            "process_name": "process_name",
            "process_path": "process_executable",
            "process_id": "process_pid",
            "vendor_product": _ELASTIC_VENDOR,
        }),
    ),
)

FILESYSTEM = Dataset(
    name="Filesystem",
    tags=("endpoint", "filesystem"),
    fields=(
        "action", "dest", "user", "file_name", "file_path", "file_hash",
        "file_size", "vendor_product",
    ),
    feeds=(
        Feed(*_S1, fields={
            "action": _s1_action,
            "dest": "agentRealtimeInfo.agentComputerName",
            "user": "threatInfo.processUser",
            "file_name": _basename("threatInfo.filePath"),
            "file_path": "threatInfo.filePath",
            "file_hash": "threatInfo.sha256",
            "file_size": "threatInfo.fileSize",
            "vendor_product": _S1_VENDOR,
        }),
        Feed(*_CS, where=_cs_detection, fields={
            "action": _cs_action,
            "dest": "event.Hostname",
            "user": "event.UserName",
            "file_name": "event.FileName",
            "file_path": "event.FilePath",
            "file_hash": "event.SHA256String",
            "vendor_product": _CS_VENDOR,
        }),
        Feed(*_ELASTIC, fields={
            "dest": "hostname",
            "user": "user_name",
            "file_name": "file_name",
            "file_path": "file_path",
            "file_hash": "file_hash_sha256",
            "vendor_product": _ELASTIC_VENDOR,
        }),
    ),
)

MALWARE_ATTACKS = Dataset(
    name="Malware_Attacks",
    tags=("malware", "attack"),
    fields=(
        "action", "category", "dest", "file_hash", "file_name", "file_path",
        "severity", "signature", "user", "vendor_product",
    ),
    feeds=(
        Feed(*_S1, fields={
            "action": _s1_action,
            "category": "threatInfo.classification",
            "dest": "agentRealtimeInfo.agentComputerName",
            "file_hash": "threatInfo.sha256",
            "file_name": _basename("threatInfo.filePath"),
            "file_path": "threatInfo.filePath",
            "severity": _s1_severity,
            "signature": "threatInfo.threatName",
            "user": "threatInfo.processUser",
            "vendor_product": _S1_VENDOR,
        }),
        Feed(*_CS, where=_cs_detection, fields={
            "action": _cs_action,
            "category": "event.Tactic",
            "dest": "event.Hostname",
            "file_hash": "event.SHA256String",
            "file_name": "event.FileName",
            "file_path": "event.FilePath",
            "severity": _lower("event.SeverityName"),
            "signature": "event.Name",
            "user": "event.UserName",
            "vendor_product": _CS_VENDOR,
        }),
        Feed(*_MDE, fields={
            "category": "category",
            "dest": "computerDnsName",
            "severity": _lower("severity"),
            "signature": "title",
            "user": "relatedUser.userName",
            "vendor_product": _MDE_VENDOR,
        }),
        Feed(*_XDR, where=_xdr_malware, fields={
            "action": _xdr_action,
            "category": "category",
            "dest": "host_name",
            "severity": _lower("severity"),
            "signature": "name",
            "vendor_product": _XDR_VENDOR,
        }),
    ),
)

IDS_ATTACKS = Dataset(
    name="IDS_Attacks",
    tags=("ids", "attack"),
    fields=(
        "action", "category", "dest", "ids_type", "severity", "signature",
        "src", "user", "vendor_product",
    ),
    feeds=(
        Feed(*_XDR, fields={
            "action": _xdr_action,
            "category": "category",
            "dest": "host_name",
            "ids_type": _constant("host"),
            "severity": _lower("severity"),
            "signature": "name",
            "vendor_product": _XDR_VENDOR,
        }),
        Feed(*_ELASTIC, fields={
            "category": "threat_tactic_name",
            "dest": "hostname",
            "ids_type": _constant("host"),
            "severity": _lower("signal_rule_severity"),
            "signature": "signal_rule_name",
            "user": "user_name",
            "vendor_product": _ELASTIC_VENDOR,
        }),
    ),
)

ALL_TRAFFIC = Dataset(
    name="All_Traffic",
    tags=("network", "communicate"),
    fields=(
        "action", "app", "bytes", "bytes_in", "bytes_out", "dest", "dest_ip",
        "dest_port", "direction", "protocol", "src", "src_ip", "src_port",
        "transport", "user", "vendor_product",
    ),
)

AUTHENTICATION = Dataset(
    name="Authentication",
    tags=("authentication",),
    fields=(
        "action", "app", "authentication_method", "dest", "signature",
        "signature_id", "src", "src_user", "user", "vendor_product",
    ),
)

#: The data models, by the name a search gives them.
DATA_MODELS: dict[str, DataModel] = {
    model.name: model
    for model in (
        DataModel("Endpoint", "Endpoint", (PROCESSES, FILESYSTEM)),
        DataModel("Malware", "Malware", (MALWARE_ATTACKS,)),
        DataModel("Intrusion_Detection", "Intrusion Detection", (IDS_ATTACKS,)),
        DataModel("Network_Traffic", "Network Traffic", (ALL_TRAFFIC,)),
        DataModel("Authentication", "Authentication", (AUTHENTICATION,)),
    )
}
