"""The GitHub Action's base-URL outputs have to point at the mounts.

`action.yml` hands a workflow one base URL per vendor. `cs-base-url` and
`mde-base-url` were the bare root, while Falcon lives under `/cs` and
Defender under `/mde`: a workflow that joined `/oauth2/token` to the output
it was given got a 404 from the first request it made. Graph had no output at
all. Each output is joined here to a path its vendor documents and must reach
the mount, whatever that mount then says about the credentials.
"""
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from main import app

_ACTION = Path(__file__).resolve().parents[3] / "action.yml"

#: For each output: a request a client of that product makes first.
_FIRST_CALL = {
    "s1-base-url": ("GET", "/system/status"),
    "cs-base-url": ("POST", "/oauth2/token"),
    "mde-base-url": ("POST", "/oauth2/v2.0/token"),
    "es-base-url": ("GET", "/"),
    "kibana-base-url": ("GET", "/api/status"),
    "xdr-base-url": ("POST", "/healthcheck"),
    "splunk-base-url": ("GET", "/services/collector/health"),
    "sentinel-base-url": ("POST", "/oauth2/v2.0/token"),
    "graph-base-url": ("POST", "/oauth2/v2.0/token"),
}


def _outputs() -> dict[str, str]:
    """The `name=url` lines the start step writes, with the port as 5001."""
    text = _ACTION.read_text().replace("${{ inputs.port }}", "5001")
    return dict(re.findall(r'echo "([a-z0-9-]+)=(http://[^"]+)" >> "\$GITHUB_OUTPUT"', text))


def test_every_vendor_has_an_output() -> None:
    assert set(_FIRST_CALL) <= set(_outputs())


def test_every_output_is_declared() -> None:
    declared = set(re.findall(r"^  ([a-z0-9-]+):\n    description", _ACTION.read_text(), re.M))
    assert set(_outputs()) <= declared


@pytest.mark.parametrize("name", sorted(_FIRST_CALL))
def test_the_output_reaches_its_mount(name: str) -> None:
    base = _outputs()[name].removeprefix("http://localhost:5001")
    method, path = _FIRST_CALL[name]
    with TestClient(app) as client:
        response = client.request(method, base + path)
    # 400/401/405 are the mount speaking (no credentials sent); a 404 is
    # nobody there.
    assert response.status_code != 404, f"{name} -> {base + path}: {response.text[:200]}"
