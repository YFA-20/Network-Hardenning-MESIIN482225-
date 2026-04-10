#!/usr/bin/env bash
# =============================================================================
# run_all.sh — Regression suite orchestrator
# Final Hardening Pack | Group OCC2 / Youssouf FARRAGE
# Usage: bash tests/regression/run_all.sh
# Exit: 0 if all tests pass, 1 if any critical test fails
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TIMESTAMP="$(date +%Y%m%dT%H%M%S)"
RESULTS_DIR="${SCRIPT_DIR}/results/${TIMESTAMP}"
SUMMARY="${RESULTS_DIR}/SUMMARY.txt"

mkdir -p "${RESULTS_DIR}"

echo "======================================================" | tee "${SUMMARY}"
echo "  Regression Suite — $(date)"                           | tee -a "${SUMMARY}"
echo "  Results: ${RESULTS_DIR}"                              | tee -a "${SUMMARY}"
echo "======================================================" | tee -a "${SUMMARY}"

FAILED=0
PASSED=0

run_test() {
    local name="$1"
    local script="${SCRIPT_DIR}/${name}"
    local outfile="${RESULTS_DIR}/${name%.sh}.txt"

    echo "" | tee -a "${SUMMARY}"
    echo "--- Running ${name} ---" | tee -a "${SUMMARY}"

    if bash "${script}" 2>&1 | tee "${outfile}"; then
        echo "[PASS] ${name}" | tee -a "${SUMMARY}"
        PASSED=$((PASSED + 1))
    else
        echo "[FAIL] ${name} *** CRITICAL ***" | tee -a "${SUMMARY}"
        FAILED=$((FAILED + 1))
    fi
}

run_test R1_firewall.sh
run_test R2_tls.sh
run_test R3_remote_access.sh
run_test R4_detection.sh

echo "" | tee -a "${SUMMARY}"
echo "======================================================" | tee -a "${SUMMARY}"
echo "  PASSED: ${PASSED} / $((PASSED + FAILED))" | tee -a "${SUMMARY}"
echo "  FAILED: ${FAILED} / $((PASSED + FAILED))" | tee -a "${SUMMARY}"
echo "  Results stored in: ${RESULTS_DIR}"         | tee -a "${SUMMARY}"
echo "======================================================" | tee -a "${SUMMARY}"

if [ "${FAILED}" -gt 0 ]; then
    echo "ERROR: ${FAILED} critical test(s) failed." >&2
    exit 1
fi

exit 0
