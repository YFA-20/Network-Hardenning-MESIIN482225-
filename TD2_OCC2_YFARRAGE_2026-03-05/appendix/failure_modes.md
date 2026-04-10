# Appendix — Failure Modes & Troubleshooting
**TD2: Firewall Policy (nftables) | Author: Youssouf FARRAGE — Group OCC2 | ESILV, 4th year, Major Cybersecurity & IOT Trust | 2026-03-05**

---

## FM-1 — Admin SSH locked out after setting input policy to drop

**Symptom:** SSH connection from admin-pc drops immediately when `nft chain inet filter input '{ policy drop; }'` is run.

**Root cause:** The input allow rule for the admin IP was not yet in place when the policy was changed.

**Prevention (applied in this TD):**
Always add ALL allow rules to the input chain before changing its policy to drop. Specifically:
1. Create the input chain **without** a policy (defaults to accept)
2. Add loopback, established/related, and all SSH allow rules
3. Only then change policy to drop

**Recovery if locked out:**
- Use Azure Serial Console (portal.azure.com → VM → Serial Console)
- Run: `sudo nft flush ruleset`
- This instantly restores full connectivity (no reboot needed)
- Reconnect via SSH, fix the missing rule, then re-apply

---

## FM-2 — UDR missing: traffic bypasses gw-fw entirely

**Symptom:** All flows work, but nft counters stay at 0. `tcpdump` on gw-fw shows no forwarded packets. TTL remains at 64 instead of 63.

**Root cause:** Azure routes LAN↔DMZ traffic internally (within its own fabric) by default. Without UDR route tables, packets never reach gw-fw.

**Detection:**
```bash
# On gw-fw, while client pings srv-web:
sudo tcpdump -i any icmp -n
# If you see nothing → UDR not configured
# If you see IN=eth0 OUT=eth1 → UDR working ✓
```

**Fix:**
Create UDR route tables and associate them with NH-LAN and NH-DMZ subnets.
Also enable Azure IP Forwarding on both gw-fw NICs.
Full commands: see `tests/commands.txt` Phase 1.

---

## FM-3 — Azure IP Forwarding not enabled: kernel drops forwarded packets

**Symptom:** UDR routes are configured, tcpdump shows packets arriving on eth0, but they never appear on eth1. `nft list ruleset` shows forward chain counters incrementing (packets hitting the chain) but they're dropped at the Azure NIC level.

**Root cause:** Azure enforces source/destination IP checks on NICs by default. Even if OS-level `ip_forward=1` is set, Azure's hypervisor drops packets where the source or destination IP doesn't match the NIC's IP.

**Fix:**
```bash
# Azure CLI — enable IP Forwarding on both gw-fw NICs
az network nic update --name nic-gw-fw-lan --resource-group NH-RG --ip-forwarding true
az network nic update --name nic-gw-fw-dmz --resource-group NH-RG --ip-forwarding true
```

**Note:** This is separate from OS-level `sysctl net.ipv4.ip_forward=1` — both are required.

---

## FM-4 — nc UDP false positive (N6 DNS test)

**Symptom:** `nc -vuz -w 3 10.10.20.10 53` reports "Connection to 10.10.20.10 53 port [udp/domain] succeeded!" even though the firewall policy should drop it.

**Root cause:** `nc` for UDP has no way to know if the packet was dropped. With DROP policy (as opposed to REJECT), no ICMP port-unreachable is sent back. `nc` sends the UDP datagram, waits briefly, receives nothing, and interprets "no error" as "succeeded."

**How to verify the packet was actually dropped:**
```bash
# On gw-fw, after the test:
sudo journalctl -k --grep="NFT_FWD_DENY" | grep "DPT=53"
# If you see the log entry → packet was dropped ✓
```

**Alternative test command for UDP (more reliable):**
```bash
# Use dig instead — it will timeout if DNS is blocked
dig @10.10.20.10 google.com +time=3 +tries=1
# Expected: ;; connection timed out; no servers could be reached
```

---

## FM-5 — SSH "Permission denied (publickey)" misread as firewall block

**Symptom:** SSH test returns "Permission denied (publickey)" and student marks the test as FAIL.

**Root cause:** Confusion between firewall behavior and SSH authentication. "Permission denied (publickey)" means the TCP connection **succeeded** and reached the target host — the SSH daemon responded. The firewall **passed** the packet. The error is at the application layer: the SSH client doesn't have the correct private key for that host.

**Correct interpretation:** If you can see the SSH banner or an authentication error → firewall PASS ✓

**Contrast with actual firewall block:**
- DROP policy: connection hangs, then times out after the specified timeout (`ConnectTimeout`)
- REJECT policy: "Connection refused" immediately (not used in this lab)

---

## FM-6 — nftables rules lost after VM reboot

**Symptom:** All nftables rules disappear after rebooting gw-fw. The firewall returns to default accept-all state.

**Root cause:** `nft add rule` commands are applied to the running kernel state only. They are not persistent by default.

**Fix — make rules persistent:**
```bash
# 1. Export current ruleset to the nftables config file
sudo nft list ruleset > /etc/nftables.conf

# 2. Enable the nftables systemd service
sudo systemctl enable nftables
sudo systemctl start nftables

# 3. Verify service status
sudo systemctl status nftables
# Should show: Active: active (running)

# 4. Test persistence: reboot and verify
sudo reboot
# After reboot:
sudo nft list ruleset
# All rules should be present
```

**Alternative (simpler but less elegant):**
Add the nft commands to `/etc/rc.local` or create a systemd service unit.

---

## FM-7 — Conflict with Azure waagent "table ip security"

**Symptom:** `nft list ruleset` shows a pre-existing `table ip security` with chains that touch IMDS (169.254.169.254). Attempting to modify or delete these chains causes Azure agent errors.

**Root cause:** Azure's Linux agent (waagent) and cloud-init install nftables rules to protect the Azure Instance Metadata Service endpoint.

**Correct approach:** Leave `table ip security` completely untouched. Create your own `table inet filter` in a separate namespace. The two tables coexist without conflict.

**DO NOT run:**
```bash
nft flush ruleset   # ← during normal operation, this also removes the waagent table
                    # (OK for emergency rollback, but re-apply your rules afterward)
```
