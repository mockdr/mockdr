"""Domain dataclass for a Splunk KV Store collection."""
from dataclasses import dataclass, field


@dataclass
class KVCollection:
    """A KV Store collection with its schema and records."""

    name: str
    app: str = "search"
    owner: str = "nobody"

    # Field definitions: name → type (string, number, bool, time, cidr)
    field_types: dict[str, str] = field(default_factory=dict)

    # Accelerated fields (field → True)
    accelerated_fields: dict[str, bool] = field(default_factory=dict)

    # Records: list of dicts, each with _key + arbitrary fields
    records: list[dict[str, object]] = field(default_factory=list)

    @property
    def id(self) -> str:
        """Primary identifier expected by ``Repository[T]``."""
        return f"{self.app}/{self.name}"
