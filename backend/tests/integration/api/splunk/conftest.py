"""Splunk test fixtures.

splunkd answers in Atom XML unless ``output_mode=json`` is requested, and the
Splunk SDKs request it on every call. These tests assert on the JSON bodies, so
the client fixture asks the same way — leaving the XML default itself to be
tested explicitly in ``test_splunk_output_mode.py``.
"""
import pytest
from fastapi.testclient import TestClient

import main

# HEC always answers JSON and ignores output_mode, like the real service.
_HEC_PREFIX = "/splunk/services/collector"


class _SplunkSdkTestClient(TestClient):
    """TestClient that requests JSON output, as the Splunk SDKs do."""

    def request(self, method: str, url: str, **kwargs: object):  # type: ignore[no-untyped-def, override]
        """Append ``output_mode=json`` unless the caller chose a mode."""
        target = str(url)
        params = kwargs.get("params")
        already_set = "output_mode=" in target or (
            isinstance(params, dict) and "output_mode" in params
        )
        if not target.startswith("/splunk") or target.startswith(_HEC_PREFIX) or already_set:
            return super().request(method, target, **kwargs)  # type: ignore[arg-type]

        if isinstance(params, dict):
            kwargs["params"] = {**params, "output_mode": "json"}
        else:
            separator = "&" if "?" in target else "?"
            target = f"{target}{separator}output_mode=json"
        return super().request(method, target, **kwargs)  # type: ignore[arg-type]


@pytest.fixture()
def client(fresh_seed: None) -> TestClient:
    """Test client that behaves like a Splunk SDK caller."""
    return _SplunkSdkTestClient(main.app)
