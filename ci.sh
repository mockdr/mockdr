#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────
# ci.sh — Run all CI/CD checks locally (mirrors .github/workflows/ci.yml)
#
# Parallelism:
#   • Backend and frontend quality gates run concurrently
#   • pytest uses -n auto (pytest-xdist) to spread tests across all cores
#   • Sequential stages (e2e, field-drift, docker) run after both gates pass
# ──────────────────────────────────────────────────────────────────────────────
set -uo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
BACKEND="$ROOT/backend"
FRONTEND="$ROOT/frontend"

# Prefer docker, fall back to podman
if command -v docker &>/dev/null; then
    DOCKER=docker
elif command -v podman &>/dev/null; then
    DOCKER=podman
else
    DOCKER=""
fi

# Temp files for collecting results from parallel jobs
BACKEND_LOG=$(mktemp)
FRONTEND_LOG=$(mktemp)
BACKEND_RESULT="$BACKEND_LOG.result"
FRONTEND_RESULT="$FRONTEND_LOG.result"
trap 'rm -f "$BACKEND_LOG" "$FRONTEND_LOG" "$BACKEND_RESULT" "$FRONTEND_RESULT"' EXIT

# ── Colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# ── Result tracking ──────────────────────────────────────────────────────────
PASSED=0
FAILED=0
SKIPPED=0
FAIL_NAMES=()

step()  { echo -e "\n${CYAN}${BOLD}── $1 ──${NC}"; }
pass()  { echo -e "${GREEN}✓ $1${NC}";  ((PASSED++)); }
fail()  { echo -e "${RED}✗ $1${NC}";    ((FAILED++)); FAIL_NAMES+=("$1"); }
skip()  { echo -e "${YELLOW}⊘ $1 (skipped — $2)${NC}"; ((SKIPPED++)); }

run() {
    local name="$1"; shift
    if "$@"; then pass "$name"; else fail "$name"; fi
}

# ── Parse result files from parallel jobs ────────────────────────────────────
parse_results() {
    local file="$1"
    while IFS='|' read -r status name; do
        case "$status" in
            PASS) pass "$name" ;;
            FAIL) fail "$name" ;;
            SKIP) skip "$name" "see log above" ;;
        esac
    done < "$file"
}

# ══════════════════════════════════════════════════════════════════════════════
# BACKEND (runs in subshell)
# ══════════════════════════════════════════════════════════════════════════════
run_backend() {
    local results="$1"
    cd "$BACKEND"

    _run() {
        local name="$1"; shift
        if "$@"; then echo "PASS|$name" >> "$results"
        else           echo "FAIL|$name" >> "$results"; fi
    }

    _run "BE: Lint (ruff)" \
        .venv/bin/ruff check .

    _run "BE: Type-check (mypy)" \
        .venv/bin/mypy --strict --allow-any-generics . --ignore-missing-imports --exclude tests/

    _run "BE: Test + coverage (85% gate)" \
        .venv/bin/pytest --cov --cov-fail-under=85

    _run "BE: Critical-path tests" \
        .venv/bin/pytest -m critical --no-cov -n auto

    _run "BE: Security audit (pip-audit)" \
        .venv/bin/pip-audit

    _run "BE: SAST (bandit)" \
        bandit -r . -x ./tests,./.venv -ll

    # Exclude own package — BSL 1.1, not in deny-list scope
    _run "BE: License compliance (pip-licenses)" \
        .venv/bin/pip-licenses --format=plain --with-license-file --no-license-path --ignore-packages mockdr

    _run "BE: License deny-list" \
        .venv/bin/pip-licenses --fail-on="GPL-3.0-only;GPL-3.0-or-later;AGPL-3.0-only;AGPL-3.0-or-later" --ignore-packages mockdr
}

# ══════════════════════════════════════════════════════════════════════════════
# FRONTEND (runs in subshell)
# ══════════════════════════════════════════════════════════════════════════════
run_frontend() {
    local results="$1"
    cd "$FRONTEND"

    _run() {
        local name="$1"; shift
        if "$@"; then echo "PASS|$name" >> "$results"
        else           echo "FAIL|$name" >> "$results"; fi
    }

    if [ ! -d node_modules ]; then
        echo "Installing Node dependencies …"
        npm ci
    fi

    _run "FE: Lint (eslint — zero warnings)" \
        npx eslint src/ --max-warnings=0

    _run "FE: Type-check (vue-tsc)" \
        npx vue-tsc --noEmit

    _run "FE: Unit tests + coverage" \
        npx vitest run --coverage

    _run "FE: Security audit (npm audit)" \
        npm audit --omit=dev --audit-level=high

    _run "FE: License compliance (license-checker)" \
        npx license-checker --production --failOn "GPL-3.0;AGPL-3.0;GPL-2.0"
}

# ══════════════════════════════════════════════════════════════════════════════
# PHASE 1: Backend + Frontend in parallel
# ══════════════════════════════════════════════════════════════════════════════
echo -e "${BOLD}Phase 1: Backend + Frontend quality gates (parallel)${NC}"
echo -e "${DIM}Running backend and frontend checks concurrently …${NC}"

> "$BACKEND_RESULT"
> "$FRONTEND_RESULT"

run_backend  "$BACKEND_RESULT" > "$BACKEND_LOG"  2>&1 &
BE_PID=$!
run_frontend "$FRONTEND_RESULT" > "$FRONTEND_LOG" 2>&1 &
FE_PID=$!

# Wait and capture exit codes (don't fail the script)
wait "$BE_PID" 2>/dev/null || true
wait "$FE_PID" 2>/dev/null || true

step "Backend results"
cat "$BACKEND_LOG"
parse_results "$BACKEND_RESULT"

step "Frontend results"
cat "$FRONTEND_LOG"
parse_results "$FRONTEND_RESULT"

# ══════════════════════════════════════════════════════════════════════════════
# PHASE 2: Sequential stages (need running server or special tools)
# ══════════════════════════════════════════════════════════════════════════════
echo -e "\n${BOLD}Phase 2: Integration checks (sequential)${NC}"

# ── Shared server helper ──────────────────────────────────────────────────────
SERVER_PID=""
cleanup_server() { [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null || true; SERVER_PID=""; }

start_server() {
    local port="$1"
    cleanup_server
    cd "$BACKEND"
    .venv/bin/python -m uvicorn main:app --host 127.0.0.1 --port "$port" &>/dev/null &
    SERVER_PID=$!
    for _ in $(seq 1 30); do
        curl -s "http://localhost:${port}/web/api/v2.1/system/status" >/dev/null 2>&1 && return 0
        sleep 1
    done
    echo "Server failed to start on port $port" >&2
    return 1
}

# ── E2E (Playwright) ─────────────────────────────────────────────────────────
step "E2E — Playwright critical flows"

if compgen -G "$HOME/.cache/ms-playwright/chromium*/chrome-linux*/chrome" &>/dev/null \
   || compgen -G "$HOME/.cache/ms-playwright/chromium_headless_shell*/chrome-headless-shell-linux*/chrome-headless-shell" &>/dev/null; then
    if start_server 8001; then
        cd "$FRONTEND"
        run "E2E tests (Playwright)" npx playwright test
        cleanup_server
    else
        fail "E2E tests (Playwright) — server failed to start"
    fi
else
    skip "E2E tests (Playwright)" "browsers not installed — run: npx playwright install chromium"
fi

# ── Field Drift ───────────────────────────────────────────────────────────────
step "Field drift — swagger spec vs mock responses"

if start_server 8001; then
    run "Field drift check" \
        python "$ROOT/scripts/field_drift.py" --base-url http://localhost:8001/web/api/v2.1
    cleanup_server
else
    fail "Field drift — server failed to start"
fi

# ── Secret Scanning ───────────────────────────────────────────────────────────
step "Secret scanning — gitleaks"

if command -v gitleaks &>/dev/null; then
    cd "$ROOT"
    run "Gitleaks" gitleaks detect --source . --config .gitleaks.toml --redact
else
    skip "Gitleaks" "not installed — brew install gitleaks / go install github.com/gitleaks/gitleaks/v8@latest"
fi

# ── Docker / Podman ───────────────────────────────────────────────────────────
step "Docker — build + smoke test"

if [ -n "$DOCKER" ]; then
    cd "$ROOT"
    run "Docker build ($DOCKER)" $DOCKER build -t mockdr:ci .

    if $DOCKER image inspect mockdr:ci &>/dev/null; then
        $DOCKER rm -f mockdr-ci 2>/dev/null || true
        $DOCKER run -d --name mockdr-ci -p 5001:5001 mockdr:ci

        DOCKER_OK=true
        for endpoint in \
            "http://localhost:5001/web/api/v2.1/system/status" \
            "http://localhost:5001/splunk/services/server/info?output_mode=json" \
            "http://localhost:5001/sentinel/providers/Microsoft.SecurityInsights/operations"; do
            if ! curl --fail --retry 20 --retry-delay 3 --retry-all-errors -s "$endpoint" >/dev/null; then
                DOCKER_OK=false
                break
            fi
        done

        $DOCKER stop mockdr-ci >/dev/null 2>&1 || true
        $DOCKER rm mockdr-ci >/dev/null 2>&1 || true

        if $DOCKER_OK; then pass "Docker smoke test"; else fail "Docker smoke test"; fi
    fi

    if command -v trivy &>/dev/null; then
        # Trivy needs a socket to inspect local images; start podman's if needed
        if [ "$DOCKER" = "podman" ]; then
            PODMAN_SOCK=""
            for sock in "/run/podman/podman.sock" "/run/user/$(id -u)/podman/podman.sock"; do
                [ -S "$sock" ] && PODMAN_SOCK="$sock" && break
            done
            if [ -z "$PODMAN_SOCK" ]; then
                podman system service --time=60 &>/dev/null &
                sleep 1
                for sock in "/run/podman/podman.sock" "/run/user/$(id -u)/podman/podman.sock"; do
                    [ -S "$sock" ] && PODMAN_SOCK="$sock" && break
                done
            fi
            [ -n "$PODMAN_SOCK" ] && export DOCKER_HOST="unix://$PODMAN_SOCK"
        fi
        run "Trivy container scan" \
            trivy image --severity CRITICAL,HIGH --ignore-unfixed --exit-code 1 mockdr:ci
    else
        skip "Trivy container scan" "not installed — brew install trivy"
    fi
else
    skip "Docker build" "docker/podman not available"
    skip "Docker smoke test" "docker/podman not available"
    skip "Trivy container scan" "docker/podman not available"
fi

# ══════════════════════════════════════════════════════════════════════════════
# SUMMARY
# ══════════════════════════════════════════════════════════════════════════════
echo ""
echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo -e "${BOLD}  CI Summary${NC}"
echo -e "${BOLD}══════════════════════════════════════════${NC}"
[ "$PASSED"  -gt 0 ] && echo -e "${GREEN}  Passed:  $PASSED${NC}"
[ "$FAILED"  -gt 0 ] && echo -e "${RED}  Failed:  $FAILED${NC}"
[ "$SKIPPED" -gt 0 ] && echo -e "${YELLOW}  Skipped: $SKIPPED${NC}"
echo ""

if [ "$FAILED" -gt 0 ]; then
    echo -e "${RED}Failed checks:${NC}"
    for f in "${FAIL_NAMES[@]}"; do
        echo -e "  ${RED}✗ $f${NC}"
    done
    echo ""
    exit 1
fi

echo -e "${GREEN}All checks passed!${NC}"
