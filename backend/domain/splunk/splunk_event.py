"""Domain dataclass for a Splunk event stored in an index."""
from dataclasses import dataclass, field


@dataclass
class SplunkEvent:
    """An indexed Splunk event.

    Maps to the JSON representation returned by Splunk search results.
    ``raw`` holds the original event payload as a JSON string.
    Serialization to Splunk's ``_raw`` key name happens in the response layer.
    """

    id: str
    index: str = "main"
    sourcetype: str = ""
    source: str = ""
    host: str = "mockdr"
    time: float = 0.0  # epoch seconds (float for sub-second precision)
    raw: str = ""

    # Extracted top-level fields (denormalised for fast filtering)
    fields: dict[str, object] = field(default_factory=dict)
