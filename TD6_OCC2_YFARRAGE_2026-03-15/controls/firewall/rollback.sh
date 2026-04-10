#!/bin/bash
# =============================================================================
# TD2 — Emergency Firewall Rollback Script
# Author: Youssouf FARRAGE — Group OCC2
# Date:   2026-03-05
#
# PURPOSE: Instantly remove ALL nftables rules if locked out of gw-fw.
#
# USAGE:
#   Run from Azure Serial Console (portal.azure.com → gw-fw → Serial console)
#   OR via VirtualBox console window (not over SSH — SSH may be blocked).
#
#   sudo bash rollback.sh
#
# EFFECT:
#   Flushes the entire ruleset → policy becomes accept on all chains → full
#   connectivity restored immediately. No reboot required.
#
# RECOVERY AFTER ROLLBACK:
#   1. Reconnect via SSH
#   2. Review the ruleset in config/firewall_ruleset.txt
#   3. Fix the problematic rule
#   4. Re-apply with:  sudo nft -f /etc/nftables.conf
# =============================================================================

set -euo pipefail

echo "[$(date)] Starting emergency rollback..."

# Flush ALL nftables rules (drops policy too → implicit accept)
nft flush ruleset

echo "[$(date)] Ruleset flushed. All connections now open."
echo ""
echo "Verify connectivity: ping 10.10.10.10 from client VM"
echo "Then review and fix the firewall rules before re-applying."
echo ""
echo "To re-apply persistent rules:"
echo "  sudo nft -f /etc/nftables.conf"
