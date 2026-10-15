"""Domain dataclasses for Splunk lookups: the definitions and the CSV files.

splunkd resolves the name a search gives ``lookup`` or ``inputlookup``
through a lookup *definition* — a ``transforms.conf`` stanza — which says
where the table lives: ``collection =`` (with ``external_type = kvstore``)
for a KV Store collection, ``filename =`` for a CSV file in the app's
``lookups/`` directory (Knowledge Manager Manual, "About lookups";
transforms.conf.spec). A CSV file can also be named directly by its file
name, without a definition.
"""
from dataclasses import dataclass, field


@dataclass
class LookupDefinition:
    """A ``transforms.conf`` lookup stanza."""

    name: str
    app: str = "search"
    owner: str = "nobody"

    #: ``collection =`` — the KV Store collection a kvstore lookup reads.
    collection: str = ""
    #: ``filename =`` — the CSV file a file-based lookup reads.
    filename: str = ""
    #: ``fields_list =`` — the fields a kvstore lookup exposes, ``_key``
    #: included only when it is named. A CSV lookup's fields are its header.
    fields_list: list[str] = field(default_factory=list)

    #: transforms.conf defaults: up to 1000 matches per input value when no
    #: ``time_field`` is set, none required, nothing filled in on a miss, and
    #: values compared case-sensitively.
    max_matches: int = 1000
    min_matches: int = 0
    default_match: str = ""
    case_sensitive_match: bool = True

    #: The optional settings the stanza spells out, as splunkd reports them
    #: back: only what was given, never the defaults above.
    explicit: dict[str, object] = field(default_factory=dict)

    #: The user who created the definition over REST; empty for one a .conf
    #: file ships, which is ``nobody``'s.
    creator: str = ""

    @property
    def id(self) -> str:
        """Primary identifier expected by ``Repository[T]``."""
        return f"{self.app}/{self.name}"

    @property
    def type(self) -> str:
        """``kvstore`` or ``file``, as Settings > Lookups lists it."""
        return "kvstore" if self.collection else "file"


@dataclass
class LookupFile:
    """A CSV lookup table file, held in memory rather than on disk."""

    name: str
    app: str = "search"
    owner: str = "nobody"
    header: list[str] = field(default_factory=list)
    #: One dict per CSV row; an empty cell is a field the row does not have.
    rows: list[dict[str, str]] = field(default_factory=list)

    @property
    def id(self) -> str:
        """Primary identifier expected by ``Repository[T]``."""
        return f"{self.app}/{self.name}"
