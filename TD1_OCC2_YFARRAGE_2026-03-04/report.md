# TD1 — Network Baseline for Hardening
## Lab Report

| Field | Value |
|---|---|
| **Module** | Network Hardening — 4th-year Engineering, Major Cybersecurity & IOT Trust (ESILV) |
| **Lab** | TD1 — Network Baseline: map, flow matrix, capture, risk |
| **Group / Student** | Group OCC2 / Youssouf FARRAGE — ESILV, 4th year, Major Cybersecurity & IOT Trust |
| **Date** | 2026-03-04 |
| **Normative anchor** | NIST SP 800-53 CM-8 — Asset inventory, flow analysis, risk-driven observation |
| **Platform** | Microsoft Azure (francecentral, zone 2) — documented substitution for VirtualBox |

---

## Executive Summary

The objective of this TD was to establish a zero-state baseline of the network infrastructure before any hardening action. The deployed environment is a three-zone lab network: LAN (client), DMZ (web server), and a trust boundary enforced by a gateway/firewall (`gw-fw`). The initial attack surface is intentionally minimal — two open ports on the web server, no active filtering rules — which is precisely the baseline from which the subsequent TDs will build the security policy.

Two findings warrant immediate attention, independent of the TD schedule. First, the SSH port of `gw-fw` is exposed to the public internet with no source address restriction, and live SSH brute-force attempts from three distinct IP addresses were observed during the capture. This is not a theoretical assumption — it is real telemetry, visible in `evidence/baseline.pcap`. Second, in Azure, LAN↔DMZ traffic does not transit through `gw-fw` unless a User Defined Route (UDR) is configured, meaning the firewall is currently not in the data path. These two points are the priority risks to address in TD2.

---

## 1. Platform Context and Architectural Differences

The course prescribes a VirtualBox environment with four VMs. The deployment was carried out on **Microsoft Azure** due to hardware availability constraints. Several architectural differences follow from this choice and are documented here; they apply to all subsequent TDs in this module.

**Difference 1 — IP addressing.** Azure reserves addresses .0 through .3 of each subnet (network address, router, DNS×2). `gw-fw` therefore uses `10.10.10.4` and `10.10.20.4` instead of `.1`. All other VMs retain the IPs specified in the course sheet.

**Difference 2 — sensor-ids VM absent.** The Azure for Students quota is limited to 6 vCPUs per region. The three deployed VMs (gw-fw + client + srv-web: 2+2+2 = 6 vCPUs) exhaust this quota. `sensor-ids` could not be created. As a compensating measure, Suricata is installed on `gw-fw`, consistent with the alternative documented in `0_technical_support/00_environment/oci_cloud_alternative.md`. This configuration corresponds to a UTM (Unified Threat Management) architecture where the firewall and IDS sensor co-reside on the same machine.

**Difference 3 — Azure default routing.** In an Azure VNet, intra-VNet traffic between subnets is routed at the hypervisor level, outside any VM. Without a User Defined Route (UDR) forcing traffic through `gw-fw`, LAN↔DMZ traffic does not pass through the gateway. This is fundamentally different from VirtualBox, where `ip_forward=1` on `gw-fw` is sufficient to place the machine in the data path. The impact on the capture is described in section 4.

**Difference 4 — Administration access.** The absence of a local console requires SSH access from the physical workstation. A ProxyJump mechanism through `gw-fw` was configured, introducing an additional flow not anticipated in the course specification (F04/F05 in the flow matrix).

---

## 2. Asset Inventory (Part A)

### 2.1 Observed Topology

```
          [ INTERNET ]
               |
        (FW1 — not simulated)
               |
   ┌───────────────────────────┐
   │   NH-DMZ  10.10.20.0/24   │
   │                           │
   │  srv-web (10.10.20.10)    │  sensor-ids (10.10.20.50)
   │  nginx :80  sshd :22      │  NOT DEPLOYED — Azure quota
   └───────────────────────────┘
               |
   ┌─────────────────────────────────────────┐
   │   gw-fw — TRUST BOUNDARY                │
   │   NIC LAN : 10.10.10.4                  │
   │   NIC DMZ : 10.10.20.4                  │
   │   ip_forward = 1  |  Suricata (UTM)     │
   └─────────────────────────────────────────┘
               |
   ┌───────────────────────────┐
   │   NH-LAN  10.10.10.0/24   │
   │                           │
   │  client (10.10.10.10)     │
   │  nmap  tcpdump  curl      │
   └───────────────────────────┘

   [admin-pc Kali — 89.30.39.100]
   → SSH via internet → gw-fw (F04)
   → ProxyJump → client / srv-web (F05)
```

### 2.2 Per-Machine Inventory

**gw-fw (nh-gw)**

```
hostname      : nh-gw
OS            : Ubuntu 22.04 LTS
eth0 (LAN)    : 10.10.10.4/24
eth1 (DMZ)    : 10.10.20.4/24
gateway       : Azure router (.1 of each subnet)
ip_forward    : 1  ← verified via sysctl net.ipv4.ip_forward
open ports    : 0.0.0.0:22 (sshd)
IDS role      : Suricata installed (replaces sensor-ids)
```

**client (nh-client)**

```
hostname      : nh-client
OS            : Ubuntu 22.04 LTS
eth0 (LAN)    : 10.10.10.10/24
gateway       : 10.10.10.4 (gw-fw)
open ports    : 0.0.0.0:22 (sshd)
tools         : nmap, tcpdump, curl
```

**srv-web (nh-srvweb)**

```
hostname      : nh-srvweb
OS            : Ubuntu 22.04 LTS
eth0 (DMZ)    : 10.10.20.10/24
gateway       : 10.10.20.4 (gw-fw)
open ports    : 0.0.0.0:22 (sshd), 0.0.0.0:80 (nginx)
```

**sensor-ids**: not deployed (Azure quota exhausted — see section 1).

### 2.3 Security Zones

| Zone | Subnet | Assets | Trust Level |
|---|---|---|---|
| NH-LAN | 10.10.10.0/24 | client | High — internal zone |
| NH-DMZ | 10.10.20.0/24 | srv-web | Medium — published services |
| Trust Boundary | — | gw-fw | Critical — single control point |
| External | internet | admin-pc (Kali) | None — hostile zone |

---

## 3. Flow Matrix (Part B)

The full matrix is in `reachability_matrix.csv`. The reasoning behind each flow is detailed below.

| ID | Source | Destination | Proto | Port | Status | Justification |
|---|---|---|---|---|---|---|
| F01 | client (LAN) | srv-web (DMZ) | TCP | 80 | ALLOW | HTTP application test — primary lab objective |
| F02 | client (LAN) | srv-web (DMZ) | TCP | 22 | ALLOW — restrict by IP | Admin SSH during TDs only |
| F03 | client (LAN) | gw-fw (LAN) | TCP | 22 | ALLOW — restrict by IP | Gateway maintenance |
| F04 | admin-pc (internet) | gw-fw (LAN) | TCP | 22 | ALLOW — restrict by IP | Admin access from physical workstation (Azure-specific) |
| F05 | admin-pc (internet) | srv-web (DMZ) | TCP | 22 | ALLOW — via ProxyJump only | SSH relay through gw-fw, never direct |
| F06 | client (LAN) | srv-web (DMZ) | ICMP | — | REVIEW | Connectivity ping — acceptable in lab, to restrict in production |
| F07 | srv-web (DMZ) | client (LAN) | TCP | — | ALLOW stateful | Return traffic — handled by connection tracking |
| F08 | any | any | any | any | DENY — log | Implicit default-deny rule |

**Principle applied:** least privilege. Each ALLOW flow is justified by an explicit functional requirement. F06 is marked REVIEW because ICMP can serve as a covert channel in more exposed environments — acceptable in a lab context, but it must be re-evaluated before any production deployment.

F04 and F05 do not exist in the course's VirtualBox topology; they are specific to the Azure constraint (no local console). In a nominal environment, administration would be performed from the LAN via F03 only.

---

## 4. Connectivity Validation — nmap Scan (Part C)

Scan performed from `client` (10.10.10.10) against `srv-web` (10.10.20.10), ports 1–1000, SYN mode with version detection.

```
nmap -sS -sV -p 1-1000 10.10.20.10

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0
80/tcp open  http    nginx 1.18.0 (Ubuntu)

998 ports: filtered (no-response)
```

The two open ports correspond exactly to F01 (HTTP/80) and F02 (SSH/22) — no surprises, no unexpected ports in the scanned range. The 998 filtered ports are blocked by the Azure NSG, which mechanically reduces the exposed surface without any configuration effort. This is a notable difference from VirtualBox where this protection does not exist by default.

Note: the Azure NSG covers `srv-web` at the network interface level, but this protection is distinct from and independent of any nftables rules on `gw-fw`. It does not replace an application-layer filtering policy.

---

## 5. Network Capture and Observations (Part D)

**Capture conditions**

The capture was performed on `gw-fw`, interface `any`, for approximately 5 minutes. The tool used was `tcpdump` in interactive mode (two terminals) to work around the SSH background job suspension issue (see `appendix/failure_modes.md`, FM-07). Traffic generated from `client`: `curl http://10.10.20.10` and `ping -c 4 10.10.20.10`.

**Result:** 874 packets captured. File: `evidence/baseline.pcap`.

---

### Observation O1 — Administrator SSH access (expected flow)

**Time range:** 13:36:43 – end of capture
**Flow matrix reference:** F04
**Observed facts:** 159 packets between `89.30.39.100` (Kali admin) and `10.10.10.4:22`. TCP flags `[P.]` and `[.]` are consistent with an active, stable SSH session.

This is the expected administrative flow — the physical Kali workstation managing all VMs over SSH. It is visible and traceable, which is a desirable property. The problem is that the source IP `89.30.39.100` is a dynamic public address, and no source IP restriction is currently applied in the Azure NSG. In other words, any other IP can attempt the same connection.

**Proposed control:** restrict the inbound TCP/22 NSG rule on `gw-fw` to the administrator's fixed public IP. If the IP is dynamic, document a procedure for updating the rule on each change. Implement fail2ban as a secondary defense.
**Evidence pointer:** `baseline.pcap` — filter `tcp port 22 and host 89.30.39.100`

---

### Observation O2 — Internal ProxyJump SSH (expected flow)

**Time range:** 13:36:43 – intermittent
**Flow matrix reference:** F03, F05
**Observed facts:** 111 packets between `10.10.10.4` (gw-fw) and `10.10.10.10:22` (client). This traffic corresponds to the internal leg of the ProxyJump: when admin-pc establishes an SSH session to `client` or `srv-web` via gw-fw, the connection is relayed by gw-fw itself.

The ProxyJump architecture is correct — it avoids directly exposing the SSH of `client` and `srv-web` to the internet. However, if `gw-fw` is compromised, the attacker immediately gains a pivot to all other VMs without additional restriction. This is the inherent risk of a single bastion host.

**Proposed control:** restrict in gw-fw's `sshd_config` which destinations are permitted for relay (`AllowTCPForwarding` with `Match` blocks). Log relayed sessions separately.
**Evidence pointer:** `baseline.pcap` — filter `tcp port 22 and ip src 10.10.10.4 and ip dst 10.10.10.10`

---

### Observation O3 — Azure platform traffic (background noise)

**Time range:** 13:36:43 – continuous throughout the capture
**Flow matrix reference:** none (out-of-scope traffic)
**Observed facts:** 487 packets (56% of total volume) between `gw-fw` and `168.63.129.16`. URIs observed in HTTP headers include `/machine/?comp=goalstate` and `POST /machine?comp=telemetrydata`. This is the Azure guest agent (waagent) maintaining a heartbeat with the platform for VM health monitoring.

This traffic is permanent, non-configurable, and cannot be suppressed — any attempt to block `168.63.129.16` would break Azure provisioning. Its volume representing more than half of the capture, it visually masks application flows if not accounted for. This is a cloud-specific characteristic that must be integrated into IDS rules: without explicit suppression, this traffic would generate permanent noise in Suricata alerts.

**Proposed control:** exclude `168.63.129.16` from IDS rules (Suricata suppression, TD3). Document this traffic in the baseline so analysts know it is normal.
**Evidence pointer:** `baseline.pcap` — filter `host 168.63.129.16`

---

### Observation O4 — SSH brute-force from the internet (critical unsolicited finding)

**Time range:** present from the start of the capture
**Flow matrix reference:** violation of F08 (default deny)
**Observed facts:** Three distinct public IP addresses initiated TCP connections to `10.10.10.4:22` without being solicited:

| Source IP | Packets | Probable context |
|---|---|---|
| 146.190.237.210 | 30 | DigitalOcean server (NYC), known scanner |
| 104.248.85.160 | 30 | DigitalOcean server (NYC), known scanner |
| 64.227.160.12 | 9 | DigitalOcean server (FRA) |

These IPs belong to DigitalOcean, a hosting provider massively used for automated SSH brute-force campaigns. As soon as a public IP exposes TCP/22, it appears in continuous scans of the IPv4 address space (Shodan/Censys-style) and receives these attempts within minutes of exposure — which is exactly what is observed here.

This is not a targeted threat, but it is a real and measurable one. If authentication relied on weak passwords rather than SSH keys, a compromise would be statistically probable over the medium term.

**Proposed control (priority 1):** immediately restrict the inbound TCP/22 NSG rule on `gw-fw` to the administrator's IP. This single action fully neutralizes this attack surface in under 5 minutes.
**Evidence pointer:** `baseline.pcap` — filter `ip src 146.190.237.210 or ip src 104.248.85.160 or ip src 64.227.160.12`

---

### Observation O5 — LAN↔DMZ traffic invisible on gw-fw (architectural finding)

**Time range:** throughout the entire capture
**Flow matrix reference:** F01, F06
**Observed facts:** Despite executing `curl http://10.10.20.10` and `ping -c 4 10.10.20.10` from `client`, no packet involving both `10.10.10.10` and `10.10.20.10` simultaneously appears in the capture. The capture was performed on the `any` interface of gw-fw.

The explanation is architectural: in Azure, intra-VNet routing is operated at the hypervisor level by default. Two VMs in the same VNet but different subnets can communicate directly without traffic passing through a third VM — even if that VM has `ip_forward=1`. For a VM to act as a router in Azure, a UDR (User Defined Route) must be configured on each subnet, specifying `gw-fw` as the next-hop of type "Virtual Appliance". Without this UDR, `gw-fw` is in the logical topology but not in the actual data path.

The direct consequence: if an nftables policy were applied on `gw-fw` today, it would not filter traffic between `client` and `srv-web`. The firewall would be active but blind to the lab's primary communication flow.

**Proposed control (TD2):** create two Azure route tables — one on NH-LAN with route `10.10.20.0/24 → next-hop 10.10.10.4`, and one on NH-DMZ with `10.10.10.0/24 → next-hop 10.10.20.4`. Enable IP forwarding on gw-fw's NICs at the Azure level (distinct from the `sysctl` setting). Then verify that LAN↔DMZ traffic reappears in a capture on gw-fw.
**Evidence pointer:** `baseline.pcap` — complete absence of packets matching filter `host 10.10.10.10 and host 10.10.20.10`

---

## 6. Risk Analysis and Quick Wins (Part E)

### 6.1 Top 10 Risks

Risks are scored using an Impact × Exploitability matrix (1–5 each).

| ID | Risk | Impact | Exploitability | Score | Evidence |
|---|---|---|---|---|---|
| R01 | SSH on gw-fw exposed to 0.0.0.0/0 — active brute-force observed | 5 | 5 | 25 | O4, Azure NSG |
| R02 | No nftables rules on gw-fw — all forwarded traffic passes unfiltered | 5 | 4 | 20 | architecture, O5 |
| R03 | LAN↔DMZ traffic bypasses gw-fw due to missing Azure UDR | 5 | 4 | 20 | O5, pcap absence |
| R04 | Plaintext HTTP on srv-web — no TLS, credentials and content exposed | 4 | 3 | 12 | nmap port 80, no 443 |
| R05 | SSH on srv-web accessible from any LAN IP — F02 not restricted | 4 | 3 | 12 | flow matrix F02, nmap |
| R06 | No dedicated IDS sensor in DMZ — sensor-ids absent, Suricata on gw-fw only | 3 | 4 | 12 | architecture, Azure quota |
| R07 | No SSH key management policy — key lost and regenerated during lab | 3 | 3 | 9 | session history |
| R08 | No centralized log aggregation — no remote syslog, no correlation | 3 | 2 | 6 | observed configuration |
| R09 | Azure IMDS traffic undocumented — 56% of capture volume unexplained without baseline | 2 | 2 | 4 | O3 |
| R10 | ICMP LAN→DMZ unrestricted — potential exfiltration channel (F06 marked REVIEW) | 2 | 2 | 4 | flow matrix F06 |

### 6.2 Top 5 Quick Wins

**QW1 — Restrict SSH on gw-fw to admin IP (5 minutes)**
Modify the inbound TCP/22 NSG rule on gw-fw to accept only the administrator's source IP. This single action removes the visible surface targeted by the DigitalOcean scanners observed in O4. This has the best impact-to-effort ratio of all quick wins.

**QW2 — Create Azure UDRs to force traffic through gw-fw (10 minutes)**
Without this step, everything else (nftables, Suricata) is ineffective for LAN↔DMZ traffic. Two route tables, four lines of Azure CLI. This is the architectural prerequisite for TD2.

**QW3 — Apply nftables default-deny policy on gw-fw (30 minutes)**
Once the UDR is in place, implement an explicit filtering policy: ALLOW F01 (TCP/80), ALLOW F02 (TCP/22 with source restriction), DROP everything else with logging. TD2 objective.

**QW4 — Enable HTTPS on srv-web and redirect HTTP to HTTPS (20 minutes)**
Self-signed certificate or Let's Encrypt (depending on internet access), minimal nginx configuration. Eliminates plaintext exposure of application traffic.

**QW5 — Restrict SSH on srv-web to gw-fw source IP only (10 minutes)**
Add a `Match Address 10.10.20.4` block in `sshd_config`, or apply an NSG rule on srv-web's NIC. Reduces admin access surface on srv-web to the single authorized bastion.

---

## 7. Summary and Continuity to TD2

This TD produced the expected baseline: documented topology, justified flow matrix, annotated network capture, and a prioritized risk list. The Azure environment introduced real constraints (quota, routing) that are themselves relevant case studies — particularly the distinction between NSG protection (cloud perimeter) and application-layer filtering (nftables on gw-fw), and the necessity of UDRs for a virtual router to actually be in the data path.

The two critical actions to complete before starting TD2 are the SSH restriction on gw-fw (QW1, immediate security) and the UDR deployment (QW2, architectural prerequisite for filtering rules to have any real effect).

---

*2026-03-04 — Platform: Microsoft Azure | Tools: tcpdump, nmap*
