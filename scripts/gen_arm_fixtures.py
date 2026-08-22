# ruff: noqa: ANN001, ANN201, ANN202, D103, E402, PLR0912, PLR2004
# A fixture generator, run by hand when the vendored spec changes.
"""Generate type-correct default objects for Sentinel resources from the ARM spec.

Sentinel cannot be run locally, so the published 2024-03-01 specification is
the only reference. For each resource definition this resolves every
declared property — through $ref, allOf, the common types and the `kind`
discriminator — and writes an object with a type-correct default at every
path: "" for strings, 0 for numbers, false for booleans, [] for arrays,
nested objects recursed. The builders deep-merge their real values over it,
so a client reading any declared property finds it.

    backend/.venv/bin/python scripts/gen_arm_fixtures.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from schema_drift import SPECS, deref, props  # noqa: E402

OUT = ROOT / "backend" / "infrastructure" / "fixtures" / "sentinel"
TARGETS = {
    "incident": ("Incidents", "Incident"),
    "incident_comment": ("Incidents", "IncidentComment"),
    "incident_relation": ("Incidents", "Relation"),
    "bookmark": ("Bookmarks", "Bookmark"),
    "scheduled_alert_rule": ("AlertRules", "ScheduledAlertRule"),
    "fusion_alert_rule": ("AlertRules", "FusionAlertRule"),
    "ms_security_incident_creation_alert_rule": (
        "AlertRules",
        "MicrosoftSecurityIncidentCreationAlertRule",
    ),
    "scheduled_alert_rule_template": ("AlertRules", "ScheduledAlertRuleTemplate"),
    "watchlist": ("Watchlists", "Watchlist"),
    "watchlist_item": ("Watchlists", "WatchlistItem"),
    "threat_intelligence_indicator": (
        "ThreatIntelligence",
        "ThreatIntelligenceIndicatorModel",
    ),
    "security_alert": ("common:EntityTypes", "SecurityAlert"),
    "aad_data_connector": ("DataConnectors", "AADDataConnector"),
    "aatp_data_connector": ("DataConnectors", "AATPDataConnector"),
    "asc_data_connector": ("DataConnectors", "ASCDataConnector"),
    "aws_cloud_trail_data_connector": ("DataConnectors", "AwsCloudTrailDataConnector"),
    "mcas_data_connector": ("DataConnectors", "MCASDataConnector"),
    "mdatp_data_connector": ("DataConnectors", "MDATPDataConnector"),
    "ti_data_connector": ("DataConnectors", "TIDataConnector"),
    "office_data_connector": ("DataConnectors", "OfficeDataConnector"),
    "generic_ui_data_connector": (
        "preview:2025-10-01-preview",
        "CodelessUiDataConnector",
    ),
}


def spec_path(file: str) -> Path:
    """``common:X`` names a file in the shared sentinel-common directory."""
    if file.startswith("common:"):
        return SPECS / "sentinel-common" / f"{file[7:]}.json"
    if file.startswith("preview:"):
        return SPECS / f"sentinel_{file[8:]}_openapi.json"
    return SPECS / f"sentinel_2024-03-01_{file}.json"


def default_for(doc: dict, schema, depth: int = 0):
    schema = deref(doc, schema)
    if depth > 7 or not isinstance(schema, dict):
        return None
    kind = schema.get("type")
    if "properties" in schema or "allOf" in schema or kind == "object":
        return {
            name: default_for(doc, sub, depth + 1)
            for name, sub in props(doc, schema, depth).items()
        }
    if kind == "array":
        return []
    if kind == "boolean":
        return False
    if kind in ("integer", "number"):
        return 0
    if kind == "string":
        return "" if "enum" not in schema else schema["enum"][0]
    return None


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    for name, (file, definition) in TARGETS.items():
        doc = json.load(open(spec_path(file)))
        schema = doc["definitions"].get(definition)
        if schema is None:
            print(f"  ? {definition} not in {file}")
            continue
        fixture = default_for(doc, schema)
        (OUT / f"{name}.json").write_text(json.dumps(fixture, indent=2, ensure_ascii=False) + "\n")
        flat = json.dumps(fixture)
        print(
            f"  {name:42} {len(fixture):3} top-level keys, {len(flat):5} bytes  ({file}:{definition})"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
