#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────
# fetch_swagger.sh — download the SentinelOne Management Console API 2.1 spec
#
# `data/` is gitignored: the spec is ~14 MB of vendor-published content and does
# not belong in this tree. Without it scripts/field_drift.py has nothing to
# compare against, so fetch it before running the drift check.
#
# Source: SentinelOne's own GitHub organisation, which publishes the spec
# alongside their AI-SIEM skills.
# ──────────────────────────────────────────────────────────────────────────────
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEST="$ROOT/data/swagger_2_1.json"
URL="https://raw.githubusercontent.com/Sentinel-One/ai-siem/master/plugins/s1-secops-skills/skills/mgmt-console-api/spec/swagger_2_1.json"

mkdir -p "$(dirname "$DEST")"

echo "Fetching S1 MGMT API 2.1 spec …"
curl --fail --location --silent --show-error --max-time 300 --output "$DEST.tmp" "$URL"

# A truncated or redirected download would otherwise be reported as drift on
# every endpoint, which reads as a mock bug rather than a bad download.
if ! python3 -c "import json,sys; d=json.load(open(sys.argv[1])); sys.exit(0 if d.get('info',{}).get('version')=='2.1' else 1)" "$DEST.tmp"; then
    rm -f "$DEST.tmp"
    echo "ERROR: downloaded file is not the S1 2.1 spec." >&2
    exit 1
fi

mv "$DEST.tmp" "$DEST"
echo "Saved $DEST ($(du -h "$DEST" | cut -f1))"
