#!/usr/bin/env bash
# field_coverage.sh — Call all GET endpoints on the mockdr server and print a
# summary table showing field count per endpoint.
#
# Usage:
#   ./field_coverage.sh                       # defaults: localhost:8001, admin token
#   ./field_coverage.sh http://myhost:9000    # custom base URL
#   BASE_URL=http://myhost:9000 ./field_coverage.sh
set -euo pipefail

BASE_URL="${1:-${BASE_URL:-http://localhost:8001}}"
API="${BASE_URL}/web/api/v2.1"
TOKEN="${API_TOKEN:-admin-token-0000-0000-000000000001}"
AUTH="Authorization: ApiToken ${TOKEN}"

# ── Helpers ──────────────────────────────────────────────────────────────────

# Recursively extract all leaf-key paths from a JSON value.
# Requires Python 3 (available in the project venv or system).
count_fields() {
  python3 -c "
import json, sys

def keys_flat(obj, prefix=''):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from keys_flat(v, f'{prefix}{k}.')
    elif isinstance(obj, list):
        if obj:
            yield from keys_flat(obj[0], prefix)
    else:
        yield prefix.rstrip('.')

data = json.load(sys.stdin)
fields = sorted(set(keys_flat(data)))
print(len(fields))
"
}

# Fetch JSON, extract the first data item (handles both list and dict data envelopes),
# then count unique leaf keys.
fetch_and_count() {
  local endpoint="$1"
  local json
  json=$(curl -sf -H "${AUTH}" "${API}${endpoint}" 2>/dev/null) || { echo "ERR"; return; }

  # Extract the payload to count against.  Strategies:
  #   1. data.sites[0]  (sites endpoint)
  #   2. data[0]        (standard list)
  #   3. data           (single-object or nested)
  echo "${json}" | python3 -c "
import json, sys

def keys_flat(obj, prefix=''):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from keys_flat(v, f'{prefix}{k}.')
    elif isinstance(obj, list):
        if obj:
            yield from keys_flat(obj[0], prefix)
    else:
        yield prefix.rstrip('.')

raw = json.load(sys.stdin)
data = raw.get('data', raw)

# sites endpoint wraps in allSites/sites
if isinstance(data, dict) and 'sites' in data and isinstance(data['sites'], list):
    target = data['sites'][0] if data['sites'] else data
elif isinstance(data, list):
    target = data[0] if data else {}
elif isinstance(data, dict):
    target = data
else:
    target = {}

fields = sorted(set(keys_flat(target)))
print(len(fields))
" 2>/dev/null || echo "ERR"
}

# ── Endpoints ────────────────────────────────────────────────────────────────

declare -a ENDPOINTS=(
  "/agents?limit=1"
  "/agents/count"
  "/agents/tags?limit=1"
  "/threats?limit=1"
  "/cloud-detection/alerts?limit=1"
  "/sites?limit=1"
  "/groups?limit=1"
  "/users?limit=1"
  "/exclusions?limit=1"
  "/restrictions?limit=1"
  "/firewall-control?limit=1"
  "/device-control?limit=1"
  "/threat-intelligence/iocs?limit=1"
  "/activities?limit=1"
  "/activities/types"
  "/accounts"
  "/policies"
  "/webhooks"
  "/hashes/0000000000000000000000000000000000000000000000000000000000000000/verdict"
  "/system/info"
  "/system/configuration"
)

declare -a LABELS=(
  "agents"
  "agents/count"
  "agents/tags"
  "threats"
  "cloud-detection/alerts"
  "sites"
  "groups"
  "users"
  "exclusions"
  "restrictions (blocklist)"
  "firewall-control"
  "device-control"
  "threat-intelligence/iocs"
  "activities"
  "activities/types"
  "accounts"
  "policies"
  "webhooks"
  "hashes/verdict"
  "system/info"
  "system/configuration"
)

# ── Run ──────────────────────────────────────────────────────────────────────

echo ""
echo "mockdr Field Coverage Report"
echo "Server: ${API}"
echo "======================================"
printf "%-30s %s\n" "Endpoint" "Fields"
printf "%-30s %s\n" "------------------------------" "------"

total=0
ok=0
for i in "${!ENDPOINTS[@]}"; do
  count=$(fetch_and_count "${ENDPOINTS[$i]}")
  printf "%-30s %s\n" "${LABELS[$i]}" "${count}"
  if [[ "${count}" != "ERR" ]]; then
    total=$((total + count))
    ok=$((ok + 1))
  fi
done

echo "======================================"
echo "Endpoints queried: ${ok}/${#ENDPOINTS[@]}"
echo "Total unique fields: ${total}"
echo ""
