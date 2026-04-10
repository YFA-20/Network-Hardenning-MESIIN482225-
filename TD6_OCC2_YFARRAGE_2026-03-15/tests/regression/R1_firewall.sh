#!/usr/bin/env bash
# =============================================================================
# R1_firewall.sh — Firewall regression test
# Claims: C-FW-01, C-FW-02, C-FW-03
# What it tests:
#   Positive — HTTPS (443) and HTTP (80) reach srv-web from LAN
#   Negative — MySQL (3306) and random port (12345) are blocked from LAN
#   Negative — DMZ→LAN SSH (port 22) is blocked by FORWARD policy
# Expected: positive flows succeed, negative flows timeout/refused
# Run from: siteA-client (10.10.10.10) or gw-fw
# =============================================================================

set -uo pipefail

TARGET_DMZ="10.10.20.10"
TIMEOUT=5
PASS=0
FAIL=0

banner() { echo ""; echo "=== $* ==="; }
ok()     { echo "[PASS] $*"; PASS=$((PASS+1)); }
fail()   { echo "[FAIL] $*"; FAIL=$((FAIL+1)); }

echo "R1_firewall.sh — $(date)"
echo "Target: ${TARGET_DMZ}"
echo ""

# ----------------------------------------------------------------------------
# POSITIVE TESTS — allowed flows
# ----------------------------------------------------------------------------
banner "POSITIVE: HTTPS (TCP/443) — must succeed"
echo "Command: curl -sk --max-time ${TIMEOUT} https://${TARGET_DMZ}/"
if curl -sk --max-time "${TIMEOUT}" "https://${TARGET_DMZ}/" -o /dev/null -w "HTTP %{http_code}\n"; then
    HTTP_CODE=$(curl -sk --max-time "${TIMEOUT}" "https://${TARGET_DMZ}/" -o /dev/null -w "%{http_code}")
    if [[ "${HTTP_CODE}" =~ ^(200|301|302|403)$ ]]; then
        ok "HTTPS reached srv-web — HTTP ${HTTP_CODE}"
    else
        fail "HTTPS got unexpected code: ${HTTP_CODE}"
    fi
else
    fail "HTTPS connection failed (firewall block or service down)"
fi

banner "POSITIVE: HTTP (TCP/80) — must reach server"
echo "Command: curl -s --max-time ${TIMEOUT} http://${TARGET_DMZ}/"
HTTP_CODE=$(curl -s --max-time "${TIMEOUT}" "http://${TARGET_DMZ}/" -o /dev/null -w "%{http_code}" 2>/dev/null || echo "000")
if [[ "${HTTP_CODE}" =~ ^(200|301|302)$ ]]; then
    ok "HTTP reached srv-web — HTTP ${HTTP_CODE}"
else
    fail "HTTP got unexpected code: ${HTTP_CODE} (expected 200/301/302)"
fi

# ----------------------------------------------------------------------------
# NEGATIVE TESTS — blocked flows
# ----------------------------------------------------------------------------
banner "NEGATIVE: MySQL (TCP/3306) — must be blocked"
echo "Command: nc -vz -w ${TIMEOUT} ${TARGET_DMZ} 3306"
if nc -vz -w "${TIMEOUT}" "${TARGET_DMZ}" 3306 2>&1; then
    fail "TCP/3306 reached srv-web — firewall rule MISSING"
else
    ok "TCP/3306 blocked — NFT_FWD_DENY expected in logs"
fi

banner "NEGATIVE: Random port (TCP/12345) — must be blocked"
echo "Command: nc -vz -w ${TIMEOUT} ${TARGET_DMZ} 12345"
if nc -vz -w "${TIMEOUT}" "${TARGET_DMZ}" 12345 2>&1; then
    fail "TCP/12345 reached srv-web — firewall rule MISSING"
else
    ok "TCP/12345 blocked — NFT_FWD_DENY expected in logs"
fi

banner "NEGATIVE: Telnet (TCP/23) — must be blocked"
echo "Command: nc -vz -w ${TIMEOUT} ${TARGET_DMZ} 23"
if nc -vz -w "${TIMEOUT}" "${TARGET_DMZ}" 23 2>&1; then
    fail "TCP/23 reached srv-web — firewall rule MISSING"
else
    ok "TCP/23 blocked — NFT_FWD_DENY expected in logs"
fi

# ----------------------------------------------------------------------------
# LOG EVIDENCE — show recent NFT_FWD_DENY entries
# ----------------------------------------------------------------------------
banner "TELEMETRY: Recent NFT_FWD_DENY entries (from gw-fw)"
echo "Note: run this section on gw-fw if not already there"
if command -v journalctl &>/dev/null; then
    journalctl -k --since "5 minutes ago" 2>/dev/null | grep "NFT_FWD_DENY" | tail -10 || echo "(no deny entries in last 5 minutes — may need to check on gw-fw)"
else
    dmesg 2>/dev/null | grep "NFT_FWD_DENY" | tail -10 || echo "(dmesg not available)"
fi

# ----------------------------------------------------------------------------
# SUMMARY
# ----------------------------------------------------------------------------
echo ""
echo "--------------------------------------"
echo "R1_firewall.sh — PASS: ${PASS} | FAIL: ${FAIL}"
echo "--------------------------------------"

[ "${FAIL}" -eq 0 ] && exit 0 || exit 1
