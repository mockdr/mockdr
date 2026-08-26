r"""Render JSON the way splunkd renders it.

Measured on 10.4.2: splunkd writes its JSON compact — `{"name":"x"}`, no
space after the colon — and writes non-ASCII as the UTF-8 bytes themselves,
not as `\uXXXX` escapes. mockdr's Splunk mount did neither consistently:
the paging, search, sort and field-filter middlewares each re-serialised
with Python's defaults, so a saved search called `Grüße` came back as
`Gr\u00fce` — the same value to a parser, and a different one to anything
that reads the bytes, which is what a SIEM ingesting a raw response does.

Worse, it was not even self-consistent: two of the output-mode paths already
wrote compact JSON and the four middlewares wrote spaced JSON, so one server
rendered the same collection two ways depending on which parameter the
client happened to send.
"""

from __future__ import annotations

import json
from typing import Any


def splunk_json(payload: Any) -> bytes:  # noqa: ANN401 - any JSON document
    """Serialise a document the way splunkd puts it on the wire."""
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode()
