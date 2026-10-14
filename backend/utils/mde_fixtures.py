"""Complete Defender for Endpoint resources to the shape the docs declare.

``scripts/gen_mde_fixtures.py`` derives one default object per entity from
Microsoft's docs tree (property tables and response examples); the
serialisers deep-merge the stored record over it, so every documented field
is present.
"""

from __future__ import annotations

import json
import re
from functools import cache
from pathlib import Path

_FIXTURES = Path(__file__).resolve().parents[1] / "infrastructure" / "fixtures" / "mde"


@cache
def _fixture(entity: str) -> dict:
    path = _FIXTURES / f"{entity}.json"
    if not path.exists():
        return {}
    with path.open(encoding="utf-8") as fh:
        data = json.load(fh)
    return data if isinstance(data, dict) else {}


def _blank(default: object) -> object:
    """A fresh value for a key the record lacks: [] for a list, a rebuilt object, or the scalar."""
    if isinstance(default, list):
        return []
    if isinstance(default, dict):
        return {k: _blank(v) for k, v in default.items()}
    return default


def deep_complete(defaults: dict, actual: dict) -> dict:
    """``actual`` over ``defaults``; list items are completed against the template item."""
    # A list in the defaults is a template for items the record provides;
    # a record without the list gets [] — never a one-item list of blanks.
    # Scalars are immutable and shared; a nested object is rebuilt from its
    # template so the caller can mutate the result freely.
    out: dict = {}
    # Microsoft's property tables are camelCase almost everywhere and not
    # quite: `machine` lists `onboardingstatus`, `investigation` `State`,
    # `software` `Vendor` and `Weaknesses`. Matching keys exactly meant the
    # record's spelling and the table's both reached the answer, so a machine
    # carried `onboardingStatus: "Onboarded"` *and* `onboardingstatus: ""` —
    # and a client whose JSON mapper ignores case could bind the empty one and
    # read the machine as not onboarded. No API answers a property twice.
    by_lower = {key.lower(): key for key in actual}
    for key, template in defaults.items():
        spelling = key if key in actual else by_lower.get(key.lower())
        if spelling is None:
            # Only a key the record lacks needs a default built for it.
            out[key] = _blank(template)
            continue
        value = actual[spelling]
        key = spelling
        if isinstance(value, dict) and isinstance(template, dict):
            out[key] = deep_complete(template, value)
        elif (
            isinstance(value, list)
            and isinstance(template, list)
            and template
            and isinstance(template[0], dict)
        ):
            out[key] = [deep_complete(template[0], i) if isinstance(i, dict) else i for i in value]
        else:
            out[key] = value
    for key, value in actual.items():
        if key not in defaults:
            out[key] = value
    return out


#: Leaf names Defender's property tables type DateTimeOffset / Nullable
#: DateTime: every date in them is spelled this way (`creationDateTimeUtc`,
#: `resolvedTime`, `lastSeen`, `firstDetected`, `publishedOn`,
#: `globalFirstObserved`). scripts/gen_mde_fixtures.py reads it too.
DATE_FIELD = re.compile(r"(?:Time|DateTimeUtc|Seen|Observed|On|Detected)$")


def null_unset_dates(value: object) -> object:
    """*value* with every date field that holds "" set to null, at any depth.

    Defender answers an unset date as null -- the docs' examples carry
    `"resolvedTime": null`, `"endTime": null`, `"cancellationDateTimeUtc":
    null` -- and "" is a value no date parser reads. The records keep ""
    for "not yet" (a running investigation's `endTime`, an unresolved
    alert's `resolvedTime`), so the answer is where it becomes null.
    """
    if isinstance(value, dict):
        return {
            k: None if v == "" and DATE_FIELD.search(k) else null_unset_dates(v)
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [null_unset_dates(v) for v in value]
    return value


def complete_mde(record: dict, entity: str) -> dict:
    """``record`` with every documented property of ``entity`` present, unset dates null."""
    defaults = _fixture(entity)
    completed = deep_complete(defaults, record) if defaults else record
    return null_unset_dates(completed)  # type: ignore[return-value]
