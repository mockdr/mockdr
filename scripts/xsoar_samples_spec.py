# ruff: noqa: ANN001, ANN201, ANN202, D103, E402
"""Reduce the XSOAR packs' recorded vendor responses into route → shape maps.

Palo Alto publishes no machine-readable spec for the Cortex XDR API, and
Microsoft none for Defender for Endpoint. The XSOAR content packs
(``github.com/demisto/content``, MIT) ship responses recorded from the real
products for their unit tests, vendored under
``data/vendor-specs/xsoar-samples/``. This maps each sample to the mock's
route and flattens its key paths:

    data/vendor-specs/xdr_samples_reduced.json
    data/vendor-specs/mde_samples_reduced.json

Only key sets are compared; the values are the recording's.
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "data" / "vendor-specs" / "xsoar-samples"

#: Cortex XDR: sample file -> public_api route (all POST, ``{"request_data": …}``).
XDR = {
    "get_incidents_list.json": "POST /public_api/v1/incidents/get_incidents/",
    "get_incident_extra_data.json": "POST /public_api/v1/incidents/get_incident_extra_data/",
    "update_incident.json": "POST /public_api/v1/incidents/update_incident/",
    "get_endpoints.json": "POST /public_api/v1/endpoints/get_endpoint/",
    "get_all_endpoints.json": "POST /public_api/v1/endpoints/get_endpoints/",
    "isolate_endpoint.json": "POST /public_api/v1/endpoints/isolate",
    "unisolate_endpoint.json": "POST /public_api/v1/endpoints/unisolate",
    "scan_endpoints.json": "POST /public_api/v1/endpoints/scan/",
    "quarantine_files.json": "POST /public_api/v1/endpoints/quarantine/",
    "get_alerts_by_filter_results.json": "POST /public_api/v1/alerts/get_alerts_by_filter_data/",
    "get_original_alerts_results.json": "POST /public_api/v1/alerts/get_original_alerts/",
    "insert_cef_alerts.json": "POST /public_api/v1/alerts/insert_cef_alerts/",
    "get_audit_agent_report.json": "POST /public_api/v1/audits/agents_reports/",
    "get_audit_management_logs.json": "POST /public_api/v1/audits/management_logs/",
    "get_endpoint_violations.json": "POST /public_api/v1/device_control/get_violations/",
    "create_distribution.json": "POST /public_api/v1/distributions/create/",
    "get_distribution_url.json": "POST /public_api/v1/distributions/get_dist_url/",
    "get_distribution_status.json": "POST /public_api/v1/distributions/get_status/",
    "get_distribution_versions.json": "POST /public_api/v1/distributions/get_versions/",
    "get_quarantine_status.json": "POST /public_api/v1/quarantine/status/",
    "get_scripts.json": "POST /public_api/v1/scripts/get_scripts/",
    "get_script_metadata.json": "POST /public_api/v1/scripts/get_script_metadata/",
    "get_script_execution_status.json": "POST /public_api/v1/scripts/get_script_execution_status/",
    "get_script_execution_results.json": "POST /public_api/v1/scripts/get_script_execution_results",
    "run_script.json": "POST /public_api/v1/scripts/run_script/",
    "get_tenant_info.json": "POST /public_api/v1/system/get_tenant_info/",
    "retrieve_file_details.json": "POST /public_api/v1/actions/file_retrieval_details/",
    "action_status_get.json": "POST /public_api/v1/actions/get_action_status/",
    "blacklist_whitelist_files_success.json": "POST /public_api/v1/hash_exceptions/blocklist/",
}

#: Defender for Endpoint: the recorded alert pages.
MDE = {
    "first_response_alerts.json": "GET /api/alerts",
    "second_response_alerts.json": "GET /api/alerts",
    "third_response_alerts.json": "GET /api/alerts",
}


def observed(value, prefix: str = "", depth: int = 0) -> set[str]:
    out: set[str] = set()
    if depth > 8:
        return out
    if isinstance(value, dict):
        for k, v in value.items():
            out.add(f"{prefix}{k}")
            out |= observed(v, f"{prefix}{k}.", depth + 1)
    elif isinstance(value, list):
        for item in value[:5]:
            out |= observed(item, f"{prefix[:-1]}[*]." if prefix else "[*].", depth + 1)
    return out


def unwrap(sample):
    """Some test files wrap the recording: the response is under ``api_response``."""
    if isinstance(sample, dict) and isinstance(sample.get("api_response"), dict):
        return sample["api_response"]
    return sample


def reduce(pack: str, mapping: dict[str, str], out_name: str) -> None:
    reduced: dict[str, dict] = {}
    for name, route in mapping.items():
        path = SAMPLES / pack / name
        if not path.exists():
            print(f"  ? {pack}/{name} missing")
            continue
        paths = observed(unwrap(json.load(open(path))))
        entry = reduced.setdefault(route, {"samples": [], "paths": set()})
        entry["samples"].append(name)
        entry["paths"] |= paths
    out = ROOT / "data" / "vendor-specs" / out_name
    out.write_text(
        json.dumps(
            {
                k: {"samples": v["samples"], "paths": sorted(v["paths"])}
                for k, v in sorted(reduced.items())
            },
            indent=1,
        )
        + "\n"
    )
    print(
        f"{pack}: {len(reduced)} routes from {sum(len(v['samples']) for v in reduced.values())} samples → {out.relative_to(ROOT)}"
    )


def main() -> int:
    reduce("CortexXDR", XDR, "xdr_samples_reduced.json")
    reduce("MicrosoftDefenderAdvancedThreatProtection", MDE, "mde_samples_reduced.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
