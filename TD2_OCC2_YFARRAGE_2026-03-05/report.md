# TD2 — Firewall Policy From Flows (nftables)
## Network Hardening Lab Report

| Field | Value |
|---|---|
| **Module** | Network Hardening — 4th-year Engineering, Major Cybersecurity & IOT Trust (ESILV) |
| **Lab** | TD2 — Firewall Policy: contract → ruleset → tests → evidence |
| **Group / Student** | Group OCC2 / Youssouf FARRAGE — ESILV, 4th year, Major Cybersecurity & IOT Trust |
| **Date** | 2026-03-05 |
| **Normative anchor** | NIST SP 800-41 Rev.1 — Guidelines on Firewalls and Firewall Policy |
| **Platform** | Microsoft Azure (resource group: rg-nh-lab) |
| **Prerequisite** | TD1 completed — 4-VM baseline with reachability matrix |

---

## 1. Objective

Implement a **default-deny stateful firewall** on `gw-fw` using nftables, translating the TD1 flow matrix into explicit allow rules and verifying the policy with a structured test battery of at least 12 tests (6 positive + 6 negative).

Additionally, configure the **Azure-specific prerequisites** (User Defined Routes, NIC IP Forwarding) required to force LAN↔DMZ traffic through gw-fw — a critical step on cloud platforms where traffic between subnets is routed internally by default.

---

## 2. Environment

### 2.1 VM Inventory

| VM | Role in TD2 | Zone | IP Address(es) |
|----|-------------|------|----------------|
| **client** | Traffic generator, test executor | NH-LAN | 10.10.10.10 |
| **gw-fw** | Policy enforcement point (FORWARD + INPUT chains) | NH-LAN + NH-DMZ | 10.10.10.4 (eth0) / 10.10.20.4 (eth1) |
| **srv-web** | DMZ target — nginx HTTP, sshd | NH-DMZ | 10.10.20.10 |
| **sensor-ids** | IDS sensor (Suricata) — not used in TD2 | NH-DMZ | 10.10.20.50 |

**Platform:** Microsoft Azure, resource group `rg-nh-lab`, region West Europe.

### 2.2 Topology Diagram

```
Internet (89.30.39.100 = admin-pc Kali)
       │ SSH ProxyJump (M02)
       ▼
  ┌──────────────────────────────────────────────────────────┐
  │              Azure Virtual Network (NH-VNet)             │
  │                                                          │
  │  NH-LAN (10.10.10.0/24)   NH-DMZ (10.10.20.0/24)        │
  │  ┌─────────────────┐       ┌──────────────────────┐      │
  │  │ client          │       │ srv-web              │      │
  │  │ 10.10.10.10     │       │ 10.10.20.10          │      │
  │  └────────┬────────┘       └──────────┬───────────┘      │
  │           │                           │                  │
  │           └──────────┬────────────────┘                  │
  │               ┌──────┴──────┐   ◄── Trust Boundary       │
  │               │   gw-fw     │ eth0: 10.10.10.4 (LAN)     │
  │               │  nftables   │ eth1: 10.10.20.4 (DMZ)     │
  │               └─────────────┘                            │
  └──────────────────────────────────────────────────────────┘
```

**UDR routes** force LAN↔DMZ traffic through gw-fw:
- `rt-nh-lan`: 10.10.20.0/24 → VirtualAppliance 10.10.20.4 (attached to NH-LAN)
- `rt-nh-dmz`: 10.10.10.0/24 → VirtualAppliance 10.10.10.4 (attached to NH-DMZ)

---

## 3. Azure Prerequisites

### 3.1 Why UDRs Are Required on Azure

On Azure, traffic between two subnets within the same VNet is handled by the Azure fabric — it does **not** transit through any VM by default, even if that VM is configured as a router. This means that without additional configuration, `client → srv-web` packets would bypass `gw-fw` entirely.

To force this traffic through `gw-fw`, two User Defined Route (UDR) tables were created:

```bash
# Route table for LAN subnet
az network route-table create --name rt-nh-lan --resource-group NH-RG --location westeurope
az network route-table route create \
  --route-table-name rt-nh-lan --resource-group NH-RG \
  --name to-dmz --address-prefix 10.10.20.0/24 \
  --next-hop-type VirtualAppliance --next-hop-ip-address 10.10.20.4
az network vnet subnet update --vnet-name NH-VNet --resource-group NH-RG \
  --name NH-LAN --route-table rt-nh-lan

# Route table for DMZ subnet
az network route-table create --name rt-nh-dmz --resource-group NH-RG --location westeurope
az network route-table route create \
  --route-table-name rt-nh-dmz --resource-group NH-RG \
  --name to-lan --address-prefix 10.10.10.0/24 \
  --next-hop-type VirtualAppliance --next-hop-ip-address 10.10.10.4
az network vnet subnet update --vnet-name NH-VNet --resource-group NH-RG \
  --name NH-DMZ --route-table rt-nh-dmz
```

### 3.2 Azure NIC IP Forwarding

Azure also enforces source/destination IP checks at the hypervisor level. Both gw-fw NICs were enabled for IP forwarding:

```bash
az network nic update --name nic-gw-fw-lan --resource-group NH-RG --ip-forwarding true
az network nic update --name nic-gw-fw-dmz --resource-group NH-RG --ip-forwarding true
```

### 3.3 Verification — TTL Proof

**TD1 baseline:** `ping -c 1 10.10.20.10` from client returned TTL=64 (direct, no router hop).
**TD2 after UDR:** same command returned TTL=63 (one hop decremented = gw-fw is in the data path).

`tcpdump` on gw-fw during the ping confirmed:
```
IN=eth0 (from client) OUT=eth1 (to srv-web)
```

---

## 4. Firewall Policy Implementation

### 4.1 Policy Statement

The firewall policy is formally documented in **`config/policy.md`**. Key design choices:

| Dimension | Decision | Rationale |
|-----------|----------|-----------|
| FORWARD default | DROP | Only explicitly mapped flows cross zones |
| INPUT default | DROP | gw-fw itself must not be reachable except by authorized sources |
| OUTPUT default | ACCEPT | gw-fw needs to communicate with both subnets and internet |
| Statefulness | Yes — `ct state established,related` | Return traffic passes automatically; simplifies rule count |
| ICMP policy | Rate-limited echo-request only (5/s) | Diagnostics yes, flood protection yes |
| Logging | NFT_FWD_DENY + NFT_IN_DENY prefixes, 10/min rate limit | Audit trail without syslog flooding |
| Normative anchor | NIST SP 800-41 Rev.1 — Guidelines on Firewalls and Firewall Policy | |

All permitted flows are derived from the TD1 flow matrix. Any rule not traceable to a flow in the matrix does not exist.

### 4.2 Design — Default-Deny with Explicit Allow

The chosen policy follows the **minimum privilege principle**:
- All traffic is dropped unless a rule explicitly permits it
- Stateful tracking (`ct state established,related`) allows return traffic without per-service rules
- Denied packets are logged for audit purposes

### 4.3 Safe Deployment Order

To avoid locking out the admin SSH session during deployment:

1. Create the **forward chain** with `policy drop` first (only affects transit traffic, not our SSH)
2. Create the **input chain without a policy** (defaults to accept — SSH remains open)
3. Add all input allow rules (loopback, established, SSH whitelists, ICMP)
4. **Then** change the input chain policy to drop

This ordering guaranteed zero lockouts during implementation.

### 4.4 Final nftables Ruleset

```
table inet filter {
    chain forward {
        type filter hook forward priority filter; policy drop;
        ct state established,related counter accept          # F00 return traffic
        ip saddr 10.10.10.0/24 ip daddr 10.10.20.10 \
            tcp dport 80 counter accept                      # F01 HTTP
        ip saddr 10.10.10.0/24 ip daddr 10.10.20.10 \
            tcp dport 22 counter accept                      # F02 SSH to srv-web
        ip saddr 10.10.10.0/24 ip daddr 10.10.20.0/24 \
            icmp type echo-request limit rate 5/second \
            counter accept                                   # F03 ICMP (rate-limited)
        ip saddr 10.10.10.0/24 ip daddr 10.10.20.10 \
            tcp dport 443 counter accept                     # F04 HTTPS (prepared for TD4 TLS)
        counter log prefix "NFT_FWD_DENY " limit rate 10/minute  # DEFAULT DENY+LOG
    }

    chain input {
        type filter hook input priority filter; policy drop;
        iif "lo" counter accept                              # M05 loopback
        ct state established,related counter accept          # M06 return traffic
        ip saddr 10.10.10.0/24 tcp dport 22 counter accept  # M01 LAN admin SSH
        ip saddr 89.30.39.100 tcp dport 22 counter accept   # M02 admin-pc SSH
        ip saddr 10.10.10.0/24 icmp type echo-request \
            counter accept                                   # M04 LAN ping
        ip saddr 92.184.117.191 tcp dport 22 counter accept # M03 secondary admin IP
        counter log prefix "NFT_IN_DENY " limit rate 10/minute  # DEFAULT DENY+LOG
    }

    chain output {
        type filter hook output priority filter; policy accept;  # gw-fw can reach internet
    }
}
```

**Note:** Rule F04 (TCP/443) was added and positioned **before** the deny log counter using `nft insert rule ... handle <N>`. This ensures HTTPS traffic is accepted without triggering `NFT_FWD_DENY`. TCP/443 is not yet used (no TLS on srv-web until TD4) but the rule is required by the policy allow-list.

**Note on pre-existing rules:** Azure's `table ip security` (created by waagent to protect IMDS) was left entirely untouched. The custom `table inet filter` coexists with it without conflict.

### 4.5 Persistence

Rules were made persistent across reboots:
```bash
sudo nft list ruleset > /etc/nftables.conf
sudo systemctl enable nftables
```

---

## 5. Test Results

All 12 tests passed. Score: **12/12** (6 positive + 6 negative).

### 5.1 Positive Tests (Permitted Flows)

| ID | From | To | Proto/Port | Expected | Result | Evidence file |
|----|------|----|-----------|----------|--------|---------------|
| P1 | client | srv-web:80 | TCP/80 | HTTP 200 OK | ✅ PASS | `evidence/counters_after.txt` — F01 +2 pkts |
| P2 | client | srv-web:22 | TCP/22 | TCP handshake | ✅ PASS | `evidence/counters_after.txt` — F02 +2 pkts |
| P3 | client | srv-web | ICMP echo | 4/4 replies, TTL=63 | ✅ PASS | `evidence/counters_after.txt` — F03 +1 pkt |
| P4 | client | gw-fw (eth0) | ICMP echo | 4/4 replies | ✅ PASS | `evidence/counters_after.txt` — INPUT ICMP counter hit |
| P5 | admin-pc (89.30.39.100) | gw-fw:22 | TCP/22 | SSH shell | ✅ PASS | `evidence/counters_after.txt` — M02 +6 pkts |
| P6 | client | srv-web:443 | TCP/443 | Connection refused (no TLS yet) | ✅ PASS | `evidence/counters_after.txt` — F04 +1 pkt; firewall passed the packet, srv-web has no TLS until TD4 |

### 5.2 Negative Tests (Blocked Flows)

| ID | From | To | Proto/Port | Expected | Result | Drop Evidence |
|----|------|----|-----------|----------|--------|---------------|
| N1 | client | srv-web:12345 | TCP/12345 | Timeout | ✅ PASS | NFT_FWD_DENY IN=eth0 DPT=12345 |
| N2 | client | srv-web:3306 | TCP/3306 | Timeout | ✅ PASS | NFT_FWD_DENY IN=eth0 DPT=3306 |
| N3 | client | srv-web:23 | TCP/23 | Timeout | ✅ PASS | NFT_FWD_DENY IN=eth0 DPT=23 |
| N4 | client | srv-web:53 | UDP/53 | Drop | ✅ PASS | NFT_FWD_DENY IN=eth0 PROTO=UDP DPT=53 |
| N5 | **srv-web** | client:22 | TCP/22 | Timeout | ✅ PASS | NFT_FWD_DENY **IN=eth1 OUT=eth0** DPT=22 |
| N6 | **srv-web** | gw-fw:22 | TCP/22 | Timeout | ✅ PASS | NFT_IN_DENY **IN=eth1** SRC=10.10.20.10 DST=10.10.20.4 |

**Note on N5 and N6:** These tests are run **from srv-web** (DMZ), not from client (LAN), to verify that the reverse direction (DMZ→LAN and DMZ→gw-fw) is also blocked. N5 produces `NFT_FWD_DENY` (forward chain, IN=eth1 OUT=eth0). N6 produces `NFT_IN_DENY` (input chain, traffic destined for gw-fw itself).

### 5.3 Counter Analysis (Before → After)

Full counter outputs: `evidence/counters_before.txt` (baseline, all counters at 0) and `evidence/counters_after.txt` (after all tests).

| Chain | Rule | Before | After | Increment | Maps to test |
|-------|------|--------|-------|-----------|--------------|
| forward | established/related (F00) | 0 | 70 pkts | +70 | All stateful return traffic |
| forward | TCP/80 (F01) | 0 | 2 pkts | +2 | P1 (HTTP) |
| forward | TCP/22 (F02) | 0 | 2 pkts | +2 | P2 (SSH to srv-web) |
| forward | ICMP (F03) | 0 | 1 pkt | +1 | P3 (ping) |
| forward | TCP/443 (F04) | 0 | 1 pkt | +1 | P6 (HTTPS, firewall passed) |
| forward | NFT_FWD_DENY | 0 | 24 pkts | +24 | N1–N5 (3 retries × 5 + extra) |
| input | NFT_IN_DENY | 0 | 32 pkts | +32 | N6 + internet scanners |

The deny counter increment of **24 packets** across the forward chain is consistent with the log entries in `evidence/deny_logs.txt` (3 connection attempts per `nc -vz` call × 6 negative tests, plus additional logged retries within the rate limit window).

### 5.4 Notable Observations

**N6 UDP false positive:** `nc -vuz` always reports "succeeded" for UDP with DROP policy because no ICMP port-unreachable is returned. The packet was confirmed dropped by the `NFT_FWD_DENY ... PROTO=UDP ... DPT=53` log entry. Using `dig` would be a more reliable UDP test tool.

**P2/P6 — "Permission denied (publickey)":** This is not a firewall block. The TCP handshake completed successfully (firewall PASS). The SSH daemon on the target host responded — the client simply lacked the correct private key. Distinguishing application-layer errors from network-layer drops is an important diagnostic skill.

**NFT_IN_DENY — live brute-force traffic:** The deny logs showed 19 entries from external Internet IPs (193.163.125.63, 143.244.190.213, 40.119.96.0, 40.80.20.0) attempting SSH on TCP/22. These are automated internet scanners. The default-deny input policy blocked them all — demonstrating real-world security value.

---

## 6. Known Limitations

The following security controls are **not yet implemented** in this TD2 scope. They are documented here so a reviewer can assess the residual risk.

| Limitation | Residual Risk | Planned in |
|-----------|---------------|------------|
| **Egress control (gw-fw OUTPUT chain)** | Policy is `ACCEPT` — gw-fw can initiate outbound connections to any destination. A compromised gw-fw could exfiltrate data or phone home. | Out of scope for TD2 |
| **DMZ-initiated traffic explicitly blocked by dedicated rule** | Currently DMZ→LAN is blocked by the forward chain default DROP, not by a named rule. There is no explicit `ip saddr 10.10.20.0/24` deny rule — the block is implied. This makes auditing less readable. | Could be added as a named rule |
| **No egress filtering on client** | The LAN (NH-LAN) has no outbound restrictions. A compromised client could reach the internet freely. | Out of scope for TD2 |
| **No IDS visibility on intra-zone traffic** | `sensor-ids` is not active. Malicious lateral movement within the DMZ is not detected. | TD3 |
| **No TLS on srv-web** | TCP/443 rule is open in the firewall (F04) but srv-web has no TLS certificate. Rule is prepared for TD4 but currently "security theater" — the port reaches an unencrypted service. | TD4 |
| **SSH keys not hardened on gw-fw** | Password authentication may still be enabled. SSH hardening (key-only, AllowUsers, login rate limiting) is not yet applied. | TD5 |
| **No rate limiting on SSH inputs** | The INPUT chain allows unlimited TCP/22 SYN packets from authorized IPs. A high-volume login attempt from 89.30.39.100 would not be rate-limited by the firewall. | TD5 |
| **nftables persistence relies on /etc/nftables.conf** | If the file is corrupted or accidentally deleted at reboot, all rules are lost. No automated integrity check exists. | Out of scope for TD2 |

---

## 7. Lessons Learned

**Azure is not a standard on-premises hypervisor.** The platform intercepts and routes traffic at the fabric level. Two Azure-specific steps were mandatory before nftables could be tested: UDR route tables (to redirect traffic through gw-fw) and NIC IP Forwarding (to allow the hypervisor to pass non-NIC-addressed packets). Neither of these has an equivalent in a standard VirtualBox lab. Both constraints were identified and documented in TD1 (Observation O5 and Risk R03); TD2 resolved them as its first prerequisite before any filtering work could begin.

**Safe deployment order matters.** By creating the forward chain with drop policy first (only affects transit traffic) and delaying the input chain drop policy until all allow rules were in place, zero admin lockouts occurred during the session. This methodology should be followed in any production firewall deployment.

**Stateful vs. stateless rules.** The `ct state established,related counter accept` rule at the top of each chain is what makes the firewall practical. Without it, every response packet from srv-web back to client would also need an explicit rule — making the ruleset exponentially more complex and fragile.

**TTL as a diagnostic tool.** The drop from TTL=64 (TD1, direct path) to TTL=63 (TD2, via gw-fw) is simple and conclusive proof that the routing change worked. This technique is applicable in any multi-hop network debugging scenario.

---

*2026-03-05 — Platform: Microsoft Azure | Firewall: nftables on gw-fw*
